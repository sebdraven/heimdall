package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sebdraven/heimdall/internal/auth"
	"github.com/sebdraven/heimdall/internal/cdn"
	gjallarhorn "github.com/sebdraven/heimdall/internal/changes"
	"github.com/sebdraven/heimdall/internal/resolver"
	"github.com/sebdraven/heimdall/internal/store/ch"
	"github.com/sebdraven/heimdall/internal/store/pg"
)

type loginData struct {
	Error    string
	Username string
}

func (s *server) loginPage(w http.ResponseWriter, r *http.Request) {
	if auth.UserFrom(r.Context()) != nil {
		http.Redirect(w, r, "/campaigns", http.StatusSeeOther)
		return
	}
	s.render(w, r, "login", http.StatusOK, loginData{})
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")
	ip := clientIP(r)

	ipOK := s.ipLim.Allow(ip)
	userOK := s.usLim.Allow(strings.ToLower(username))
	if !ipOK || !userOK {
		s.log.Warn("login rate limited", "username", username, "remote", ip)
		s.render(w, r, "login", http.StatusTooManyRequests, loginData{Error: "Too many attempts. Try again later.", Username: username})
		return
	}

	u, err := s.pg.UserByUsername(r.Context(), username)
	ok := false
	switch {
	case err == nil:
		ok, err = auth.VerifyPassword(password, u.PasswordHash)
		if err != nil {
			s.log.Error("password hash", "username", username, "err", err)
		}
		ok = ok && !u.Disabled
	case errors.Is(err, pg.ErrNotFound):
		_, _ = auth.VerifyPassword(password, auth.DummyHash())
	default:
		s.fail(w, r, http.StatusInternalServerError, "login lookup", err)
		return
	}
	if !ok {
		s.log.Warn("login failed", "username", username, "remote", ip)
		s.render(w, r, "login", http.StatusUnauthorized, loginData{Error: "Invalid credentials.", Username: username})
		return
	}

	if err := s.auth.StartSession(r.Context(), w, u.ID); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "start session", err)
		return
	}
	if err := s.pg.TouchLogin(r.Context(), u.ID); err != nil {
		s.log.Warn("touch login", "err", err)
	}
	if err := s.pg.Audit(r.Context(), &u.ID, "login", u.Username); err != nil {
		s.log.Error("audit", "err", err)
	}
	http.Redirect(w, r, "/campaigns", http.StatusSeeOther)
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	s.auth.EndSession(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *server) campaignsPage(w http.ResponseWriter, r *http.Request) {
	cs, err := s.pg.Campaigns(r.Context())
	if err != nil {
		s.storeFail(w, r, err)
		return
	}
	s.render(w, r, "campaigns", http.StatusOK, map[string]any{"Campaigns": cs})
}

func (s *server) createCampaign(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" {
		s.fail(w, r, http.StatusBadRequest, "Name is required.", nil)
		return
	}
	c, err := s.pg.CreateCampaign(r.Context(), name,
		strings.TrimSpace(r.PostFormValue("family")), strings.TrimSpace(r.PostFormValue("description")))
	if err != nil {
		s.storeFail(w, r, err)
		return
	}
	s.audit(r, "campaign.create", c.Name)
	http.Redirect(w, r, fmt.Sprintf("/campaigns/%d", c.ID), http.StatusSeeOther)
}

func (s *server) campaignPage(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		s.fail(w, r, http.StatusNotFound, "Not found.", nil)
		return
	}
	c, err := s.pg.Campaign(r.Context(), id)
	if err != nil {
		s.storeFail(w, r, err)
		return
	}
	domains, err := s.pg.Domains(r.Context(), &id)
	if err != nil {
		s.storeFail(w, r, err)
		return
	}
	events, err := s.ch.Events(r.Context(), ch.EventFilter{Since: time.Now().AddDate(0, 0, -30), Campaign: c.Name, Limit: 50})
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "campaign events", err)
		return
	}
	s.render(w, r, "campaign", http.StatusOK, map[string]any{"Campaign": c, "Domains": domains, "Events": events})
}

func (s *server) addDomains(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		s.fail(w, r, http.StatusNotFound, "Not found.", nil)
		return
	}
	c, err := s.pg.Campaign(r.Context(), id)
	if err != nil {
		s.storeFail(w, r, err)
		return
	}
	interval, err := strconv.Atoi(r.PostFormValue("interval"))
	if err != nil || interval < 10 {
		s.fail(w, r, http.StatusBadRequest, "Interval must be at least 10 seconds.", nil)
		return
	}
	fqdns, bad := parseFQDNList(r.PostFormValue("fqdns"))
	if len(bad) > 0 {
		s.fail(w, r, http.StatusBadRequest, "Invalid FQDN: "+strings.Join(bad, ", "), nil)
		return
	}
	u := auth.UserFrom(r.Context())
	n, err := s.pg.ImportDomains(r.Context(), fqdns, &c.ID, interval, "web:"+u.Username, &u.ID)
	if err != nil {
		s.storeFail(w, r, err)
		return
	}
	s.audit(r, "domain.import", fmt.Sprintf("%s (%d new of %d)", c.Name, n, len(fqdns)))
	http.Redirect(w, r, fmt.Sprintf("/campaigns/%d", c.ID), http.StatusSeeOther)
}

// parseFQDNList accepts one FQDN per line; '#' starts a comment.
func parseFQDNList(text string) (fqdns, bad []string) {
	for line := range strings.Lines(text) {
		line, _, _ = strings.Cut(line, "#")
		if strings.TrimSpace(line) == "" {
			continue
		}
		f, err := resolver.NormalizeFQDN(line)
		if err != nil {
			bad = append(bad, strings.TrimSpace(line))
			continue
		}
		fqdns = append(fqdns, f)
	}
	slices.Sort(fqdns)
	return slices.Compact(fqdns), bad
}

const (
	domainChanges    = 200
	domainChangesMax = 1000
	domainPDNS       = 1000
)

// domainDetail is what /domains/{fqdn} shows. Domain is nil outside the
// watchlist. Changes include those of the zone "zone:"+fqdn.
type domainDetail struct {
	Domain  *pg.Domain
	Current []ch.Current
	Changes []gjallarhorn.Change
	PDNS    []ch.PDNSRecord
}

func (s *server) loadDomain(ctx context.Context, fqdn string, changes int) (domainDetail, error) {
	var dd domainDetail
	d, err := s.pg.Domain(ctx, fqdn)
	switch {
	case err == nil:
		dd.Domain = &d
	case !errors.Is(err, pg.ErrNotFound):
		return dd, err
	}
	if dd.Current, err = s.ch.CurrentState(ctx, fqdn); err != nil {
		return dd, fmt.Errorf("current state: %w", err)
	}
	if dd.Changes, err = s.ch.DomainChanges(ctx, fqdn, changes); err != nil {
		return dd, fmt.Errorf("changes: %w", err)
	}
	zoneChanges, err := s.ch.DomainChanges(ctx, gjallarhorn.ZonePrefix+fqdn, changes)
	if err != nil {
		return dd, fmt.Errorf("zone changes: %w", err)
	}
	dd.Changes = mergeChanges(dd.Changes, zoneChanges, changes)
	if dd.PDNS, err = s.ch.PDNSByName(ctx, fqdn, domainPDNS); err != nil {
		return dd, fmt.Errorf("pdns: %w", err)
	}
	return dd, nil
}

func (s *server) domainPage(w http.ResponseWriter, r *http.Request) {
	fqdn := resolver.Name(r.PathValue("fqdn"))
	dd, err := s.loadDomain(r.Context(), fqdn, domainChanges)
	if err != nil {
		s.storeFail(w, r, err)
		return
	}
	values, exclude := sharingQuery(fqdn, dd.Current, s.cdn)
	sharing, err := s.ch.RdataSharing(r.Context(), values, exclude)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "rdata sharing", err)
		return
	}
	zone, err := s.loadZone(r.Context(), fqdn, dd.PDNS)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "zone", err)
		return
	}
	pairs, err := s.loadNSPairs(r.Context(), fqdn, nsPairsPage)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "ns pairs", err)
		return
	}
	s.render(w, r, "domain", http.StatusOK, map[string]any{
		"FQDN": fqdn, "Domain": dd.Domain, "Current": dd.Current, "Changes": dd.Changes, "PDNS": dd.PDNS, "Sharing": sharing,
		"Zone": zone, "NSPairs": pairs,
	})
}

const nsPairsPage = 100

// nsPairsView is the zone of a name, its NS set and the other names holding
// exactly that set.
type nsPairsView struct {
	Zone    string
	NS      []string
	Matches []ch.NSPairPivot
}

// pairable reports whether z is a zone whose NS set is worth pivoting on.
func pairable(z *ch.NSSet) bool { return z != nil && len(z.NS) >= ch.MinNSSet }

// loadNSPairs returns nil when no zone is found or its NS set is too small.
func (s *server) loadNSPairs(ctx context.Context, fqdn string, limit int) (*nsPairsView, error) {
	z, err := s.ch.NSSet(ctx, fqdn)
	if err != nil {
		return nil, fmt.Errorf("ns set: %w", err)
	}
	if !pairable(z) {
		return nil, nil
	}
	matches, err := s.ch.NSPairPivots(ctx, z.Zone, z.NS, limit)
	if err != nil {
		return nil, fmt.Errorf("ns pair pivots: %w", err)
	}
	return &nsPairsView{Zone: z.Zone, NS: z.NS, Matches: matches}, nil
}

// mergeChanges interleaves two newest-first change lists, keeping the limit
// most recent.
func mergeChanges(a, b []gjallarhorn.Change, limit int) []gjallarhorn.Change {
	out := slices.Concat(a, b)
	slices.SortStableFunc(out, func(x, y gjallarhorn.Change) int { return y.TS.Compare(x.TS) })
	return out[:min(len(out), limit)]
}

// NS or SOA records last seen within zoneCurrent of the latest one of their
// type are considered current.
const zoneCurrent = time.Hour

type zoneView struct {
	Name    string
	Records []ch.PDNSRecord
}

// loadZone returns the enclosing zone of fqdn as seen in pdns: the nearest
// strict ancestor owning NS or SOA records. It returns nil if fqdn owns NS or
// SOA itself (an apex) or if no ancestor below the TLD does.
func (s *server) loadZone(ctx context.Context, fqdn string, own []ch.PDNSRecord) (*zoneView, error) {
	if len(currentZoneRecords(own)) > 0 {
		return nil, nil
	}
	for name := parentName(fqdn); strings.Contains(name, "."); name = parentName(name) {
		recs, err := s.ch.PDNSByName(ctx, name, domainPDNS)
		if err != nil {
			return nil, fmt.Errorf("zone pdns: %w", err)
		}
		if zr := currentZoneRecords(recs); len(zr) > 0 {
			return &zoneView{Name: name, Records: zr}, nil
		}
	}
	return nil, nil
}

func parentName(name string) string {
	_, parent, _ := strings.Cut(name, ".")
	return parent
}

// currentZoneRecords keeps the current NS and SOA records, sorted by type and
// value.
func currentZoneRecords(records []ch.PDNSRecord) []ch.PDNSRecord {
	newest := map[string]time.Time{}
	for _, r := range records {
		if (r.RRType == "NS" || r.RRType == "SOA") && r.LastSeen.After(newest[r.RRType]) {
			newest[r.RRType] = r.LastSeen
		}
	}
	var out []ch.PDNSRecord
	for _, r := range records {
		if last, ok := newest[r.RRType]; ok && !r.LastSeen.Before(last.Add(-zoneCurrent)) {
			out = append(out, r)
		}
	}
	slices.SortFunc(out, func(a, b ch.PDNSRecord) int {
		return cmp.Or(cmp.Compare(a.RRType, b.RRType), cmp.Compare(a.RData, b.RData))
	})
	return out
}

// sharingQuery returns the distinct values shown in Current state, CDN
// addresses aside, and the owner names not to count: the domain itself and
// its CNAME targets, which own the values reached through the chain.
func sharingQuery(fqdn string, current []ch.Current, cl *cdn.Classifier) (values, exclude []string) {
	exclude = []string{fqdn}
	for _, c := range current {
		for _, v := range c.Rdata {
			if _, isCDN := cl.Classify(v); !isCDN {
				values = append(values, v)
			}
		}
		if c.QType == "CNAME" {
			for _, v := range c.Rdata {
				exclude = append(exclude, resolver.Name(v))
			}
		}
	}
	slices.Sort(values)
	slices.Sort(exclude)
	return slices.Compact(values), slices.Compact(exclude)
}

type rdataRow struct {
	ch.PDNSRecord
	Domain *pg.Domain
}

const rdataLimit = 1000

type rdataView struct {
	Value     string
	Rows      []rdataRow
	Names     int
	Outside   int
	Limit     int
	Truncated bool
}

// buildRdataView sorts records by last seen, newest first, and attaches the
// watched domain of each owner name, if any. A result of exactly limit rows
// is flagged as truncated.
func buildRdataView(value string, records []ch.PDNSRecord, watched map[string]pg.Domain, limit int) rdataView {
	v := rdataView{Value: value, Rows: make([]rdataRow, 0, len(records)), Limit: limit, Truncated: len(records) == limit}
	names := map[string]struct{}{}
	for _, rec := range records {
		row := rdataRow{PDNSRecord: rec}
		if d, ok := watched[rec.RRName]; ok {
			row.Domain = &d
		}
		v.Rows = append(v.Rows, row)
		if _, seen := names[rec.RRName]; !seen {
			names[rec.RRName] = struct{}{}
			if row.Domain == nil {
				v.Outside++
			}
		}
	}
	v.Names = len(names)
	slices.SortStableFunc(v.Rows, func(a, b rdataRow) int { return b.LastSeen.Compare(a.LastSeen) })
	return v
}

func (s *server) rdataPage(w http.ResponseWriter, r *http.Request) {
	value := normalizeRdataQuery(r.PathValue("value"))
	if value == "" {
		s.fail(w, r, http.StatusNotFound, "Not found.", nil)
		return
	}
	records, err := s.ch.PDNSByRdata(r.Context(), value, rdataLimit)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "pdns by rdata", err)
		return
	}
	names := make([]string, 0, len(records))
	for _, rec := range records {
		names = append(names, rec.RRName)
	}
	slices.Sort(names)
	watched, err := s.pg.DomainsByFQDN(r.Context(), slices.Compact(names))
	if err != nil {
		s.storeFail(w, r, err)
		return
	}
	s.render(w, r, "rdata", http.StatusOK, buildRdataView(value, records, watched, rdataLimit))
}

const (
	searchLimit    = 200
	searchMinChars = 3
)

// likePattern turns a search query into an ILIKE pattern: * matches any
// characters, a query without * matches as a substring, and %, _ and \ are
// literal. ok is false below searchMinChars characters besides *.
func likePattern(q string) (pattern string, ok bool) {
	if utf8.RuneCountInString(strings.ReplaceAll(q, "*", "")) < searchMinChars {
		return "", false
	}
	p := escapeLike(q)
	if !strings.Contains(q, "*") {
		return "%" + p + "%", true
	}
	return strings.ReplaceAll(p, "*", "%"), true
}

var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

func escapeLike(s string) string { return likeEscaper.Replace(s) }

type nameRow struct {
	ch.NameMatch
	Domain *pg.Domain
}

type searchTruncated struct {
	Domains, Names, Values bool
}

// searchView is the result of a search. Kind is "ip", "exact" or "pattern",
// empty when nothing was searched.
type searchView struct {
	Query     string
	Kind      string
	TooShort  bool
	Limit     int
	Domains   []pg.Domain
	Names     []nameRow
	Values    []ch.ValueMatch
	Truncated searchTruncated
}

// knownName reports whether name is watched or owns pdns records.
func (s *server) knownName(ctx context.Context, name string) (bool, error) {
	_, err := s.pg.Domain(ctx, name)
	switch {
	case err == nil:
		return true, nil
	case !errors.Is(err, pg.ErrNotFound):
		return false, err
	}
	recs, err := s.ch.PDNSByName(ctx, name, 1)
	return len(recs) > 0, err
}

// searchPattern queries the watchlist, pdns names and pdns values. A source
// returning limit rows is flagged as truncated.
func (s *server) searchPattern(ctx context.Context, v *searchView, pattern string) error {
	var err error
	if v.Domains, err = s.pg.SearchDomains(ctx, pattern, v.Limit); err != nil {
		return err
	}
	names, err := s.ch.SearchNames(ctx, pattern, v.Limit)
	if err != nil {
		return fmt.Errorf("search names: %w", err)
	}
	if v.Values, err = s.ch.SearchValues(ctx, pattern, v.Limit); err != nil {
		return fmt.Errorf("search values: %w", err)
	}
	if v.Names, err = s.attachWatched(ctx, names); err != nil {
		return err
	}
	v.Truncated = searchTruncated{Domains: len(v.Domains) == v.Limit, Names: len(names) == v.Limit, Values: len(v.Values) == v.Limit}
	return nil
}

// searchIP lists the names that held addr, the watched ones among them and
// the value itself, from at most rdataLimit pdns records.
func (s *server) searchIP(ctx context.Context, v *searchView, addr string) error {
	records, err := s.ch.PDNSByRdata(ctx, addr, rdataLimit)
	if err != nil {
		return fmt.Errorf("pdns by rdata: %w", err)
	}
	names, values := groupRecords(records)
	partial := len(records) == rdataLimit
	v.Truncated = searchTruncated{Names: partial || len(names) > v.Limit, Values: partial}
	names = names[:min(len(names), v.Limit)]
	if v.Names, err = s.attachWatched(ctx, names); err != nil {
		return err
	}
	for _, n := range v.Names {
		if n.Domain != nil {
			v.Domains = append(v.Domains, *n.Domain)
		}
	}
	slices.SortFunc(v.Domains, func(a, b pg.Domain) int { return strings.Compare(a.FQDN, b.FQDN) })
	v.Values = values
	return nil
}

// attachWatched looks up, in one query, which names are in the watchlist.
func (s *server) attachWatched(ctx context.Context, names []ch.NameMatch) ([]nameRow, error) {
	fqdns := make([]string, 0, len(names))
	for _, n := range names {
		fqdns = append(fqdns, n.RRName)
	}
	watched, err := s.pg.DomainsByFQDN(ctx, fqdns)
	if err != nil {
		return nil, err
	}
	rows := make([]nameRow, 0, len(names))
	for _, n := range names {
		row := nameRow{NameMatch: n}
		if d, ok := watched[n.RRName]; ok {
			row.Domain = &d
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// groupRecords aggregates pdns records by owner name and by (rdata, rrtype),
// most recently seen first.
func groupRecords(records []ch.PDNSRecord) ([]ch.NameMatch, []ch.ValueMatch) {
	type vk struct{ rdata, rrtype string }
	byName := map[string]*ch.NameMatch{}
	byValue := map[vk]*ch.ValueMatch{}
	owners := map[vk]map[string]struct{}{}
	for _, r := range records {
		n, ok := byName[r.RRName]
		if !ok {
			n = &ch.NameMatch{RRName: r.RRName, FirstSeen: r.FirstSeen, LastSeen: r.LastSeen}
			byName[r.RRName] = n
		}
		if !slices.Contains(n.RRTypes, r.RRType) {
			n.RRTypes = append(n.RRTypes, r.RRType)
		}
		n.FirstSeen, n.LastSeen, n.Count = earliest(n.FirstSeen, r.FirstSeen), latest(n.LastSeen, r.LastSeen), n.Count+r.Count

		k := vk{r.RData, r.RRType}
		v, ok := byValue[k]
		if !ok {
			v = &ch.ValueMatch{RData: r.RData, RRType: r.RRType, FirstSeen: r.FirstSeen, LastSeen: r.LastSeen}
			byValue[k], owners[k] = v, map[string]struct{}{}
		}
		owners[k][r.RRName] = struct{}{}
		v.FirstSeen, v.LastSeen, v.Names = earliest(v.FirstSeen, r.FirstSeen), latest(v.LastSeen, r.LastSeen), uint64(len(owners[k]))
	}
	names := make([]ch.NameMatch, 0, len(byName))
	for _, n := range byName {
		slices.Sort(n.RRTypes)
		names = append(names, *n)
	}
	slices.SortFunc(names, func(a, b ch.NameMatch) int {
		return cmp.Or(b.LastSeen.Compare(a.LastSeen), cmp.Compare(a.RRName, b.RRName))
	})
	values := make([]ch.ValueMatch, 0, len(byValue))
	for _, v := range byValue {
		values = append(values, *v)
	}
	slices.SortFunc(values, func(a, b ch.ValueMatch) int {
		return cmp.Or(b.LastSeen.Compare(a.LastSeen), cmp.Compare(a.RData, b.RData), cmp.Compare(a.RRType, b.RRType))
	})
	return names, values
}

func earliest(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func latest(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func (s *server) searchPage(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	v := searchView{Query: q, Limit: searchLimit}
	if q == "" {
		s.render(w, r, "search", http.StatusOK, v)
		return
	}
	if a, err := netip.ParseAddr(q); err == nil {
		http.Redirect(w, r, "/rdata/"+url.PathEscape(a.String()), http.StatusSeeOther)
		return
	}
	name := resolver.Name(q)
	pattern, ok := likePattern(name)
	if !ok {
		v.TooShort = true
		s.render(w, r, "search", http.StatusOK, v)
		return
	}
	if !strings.Contains(name, "*") {
		known, err := s.knownName(r.Context(), name)
		if err != nil {
			s.storeFail(w, r, err)
			return
		}
		if known {
			http.Redirect(w, r, "/domains/"+url.PathEscape(name), http.StatusSeeOther)
			return
		}
	}
	v.Kind = "pattern"
	if err := s.searchPattern(r.Context(), &v, pattern); err != nil {
		s.storeFail(w, r, err)
		return
	}
	s.render(w, r, "search", http.StatusOK, v)
}

func (s *server) toggleDomain(w http.ResponseWriter, r *http.Request) {
	fqdn := resolver.Name(r.PathValue("fqdn"))
	d, err := s.pg.Domain(r.Context(), fqdn)
	if err != nil {
		s.storeFail(w, r, err)
		return
	}
	enabled := !d.Enabled
	if _, err := s.pg.UpdateDomain(r.Context(), fqdn, pg.DomainPatch{Enabled: &enabled}); err != nil {
		s.storeFail(w, r, err)
		return
	}
	s.audit(r, map[bool]string{true: "domain.enable", false: "domain.disable"}[enabled], fqdn)
	http.Redirect(w, r, backPath(r, "/domains/"+fqdn), http.StatusSeeOther)
}

func (s *server) deleteDomain(w http.ResponseWriter, r *http.Request) {
	fqdn := resolver.Name(r.PathValue("fqdn"))
	if err := s.pg.DeleteDomain(r.Context(), fqdn); err != nil {
		s.storeFail(w, r, err)
		return
	}
	s.audit(r, "domain.delete", fqdn)
	w.WriteHeader(http.StatusOK)
}

func (s *server) eventsPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	now := time.Now().UTC()
	since, until := q.Get("since"), q.Get("until")
	if since == "" {
		since = "168h"
	}
	f := ch.EventFilter{Kind: q.Get("kind"), Campaign: q.Get("campaign"), Limit: 1000}
	var err error
	if f.Since, err = parseTime(since, now); err != nil {
		s.fail(w, r, http.StatusBadRequest, err.Error(), nil)
		return
	}
	if until != "" {
		if f.Until, err = parseTime(until, now); err != nil {
			s.fail(w, r, http.StatusBadRequest, err.Error(), nil)
			return
		}
	}
	if f.Kind != "" && !slices.Contains(gjallarhorn.Kinds, f.Kind) {
		s.fail(w, r, http.StatusBadRequest, "Unknown event kind.", nil)
		return
	}
	events, err := s.ch.Events(r.Context(), f)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "events", err)
		return
	}
	if r.Header.Get("HX-Request") == "true" && r.Header.Get("HX-History-Restore-Request") != "true" {
		s.execute(w, r, "events", "events_table", http.StatusOK, events)
		return
	}
	campaigns, err := s.pg.Campaigns(r.Context())
	if err != nil {
		s.storeFail(w, r, err)
		return
	}
	s.render(w, r, "events", http.StatusOK, map[string]any{
		"Events": events, "Kinds": gjallarhorn.Kinds, "Campaigns": campaigns,
		"Filter": f, "Since": since, "Until": until,
	})
}

func (s *server) adminPage(w http.ResponseWriter, r *http.Request) {
	resolvers, err := s.pg.Resolvers(r.Context())
	if err != nil {
		s.storeFail(w, r, err)
		return
	}
	classes, err := s.pg.NSClasses(r.Context())
	if err != nil {
		s.storeFail(w, r, err)
		return
	}
	prefixes, err := s.pg.CDNPrefixes(r.Context())
	if err != nil {
		s.storeFail(w, r, err)
		return
	}
	audit, err := s.pg.AuditLog(r.Context(), 200)
	if err != nil {
		s.storeFail(w, r, err)
		return
	}
	s.render(w, r, "admin", http.StatusOK, map[string]any{
		"Resolvers": resolvers, "NSClasses": classes, "CDNPrefixes": prefixes, "Audit": audit,
	})
}

func (s *server) createResolver(w http.ResponseWriter, r *http.Request) {
	addr, err := resolver.NormalizeServer(r.PostFormValue("address"))
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, err.Error(), nil)
		return
	}
	qps, err := strconv.Atoi(r.PostFormValue("qps"))
	if err != nil || qps <= 0 {
		s.fail(w, r, http.StatusBadRequest, "QPS must be a positive integer.", nil)
		return
	}
	res, err := s.pg.CreateResolver(r.Context(), addr, strings.TrimSpace(r.PostFormValue("label")), qps)
	if err != nil {
		s.storeFail(w, r, err)
		return
	}
	s.audit(r, "resolver.create", res.Address)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *server) toggleResolver(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		s.fail(w, r, http.StatusNotFound, "Not found.", nil)
		return
	}
	res, err := s.pg.ToggleResolver(r.Context(), id)
	if err != nil {
		s.storeFail(w, r, err)
		return
	}
	s.audit(r, map[bool]string{true: "resolver.enable", false: "resolver.disable"}[res.Enabled], res.Address)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *server) deleteResolver(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	res, err := s.pg.DeleteResolver(r.Context(), id)
	if err != nil {
		s.storeFail(w, r, err)
		return
	}
	s.audit(r, "resolver.delete", res.Address)
	w.WriteHeader(http.StatusOK)
}

func (s *server) createNSClass(w http.ResponseWriter, r *http.Request) {
	pattern := gjallarhorn.NormalizePattern(r.PostFormValue("pattern"))
	kind := r.PostFormValue("kind")
	if pattern == "" || (kind != gjallarhorn.NSKindSinkhole && kind != gjallarhorn.NSKindParking) {
		s.fail(w, r, http.StatusBadRequest, "Pattern and kind (sinkhole or parking) are required.", nil)
		return
	}
	c, err := s.pg.CreateNSClass(r.Context(), pattern, kind, strings.TrimSpace(r.PostFormValue("label")))
	if err != nil {
		s.storeFail(w, r, err)
		return
	}
	s.audit(r, "nsclass.create", c.Kind+":"+c.Pattern)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *server) deleteNSClass(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	c, err := s.pg.DeleteNSClass(r.Context(), id)
	if err != nil {
		s.storeFail(w, r, err)
		return
	}
	s.audit(r, "nsclass.delete", c.Kind+":"+c.Pattern)
	w.WriteHeader(http.StatusOK)
}

func (s *server) createCDNPrefix(w http.ResponseWriter, r *http.Request) {
	prefix, err := cdn.ParsePrefix(r.PostFormValue("prefix"))
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, err.Error(), nil)
		return
	}
	provider := strings.TrimSpace(r.PostFormValue("provider"))
	if provider == "" {
		s.fail(w, r, http.StatusBadRequest, "Provider is required.", nil)
		return
	}
	p, err := s.pg.CreateCDNPrefix(r.Context(), prefix, provider, "manual")
	if err != nil {
		s.storeFail(w, r, err)
		return
	}
	s.audit(r, "cdnprefix.create", p.Provider+":"+p.Prefix.String())
	s.refreshCDN(r)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *server) deleteCDNPrefix(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	p, err := s.pg.DeleteCDNPrefix(r.Context(), id)
	if err != nil {
		s.storeFail(w, r, err)
		return
	}
	s.audit(r, "cdnprefix.delete", p.Provider+":"+p.Prefix.String())
	s.refreshCDN(r)
	w.WriteHeader(http.StatusOK)
}

// refreshCDN applies an admin change at once rather than at the next reload.
func (s *server) refreshCDN(r *http.Request) {
	if err := s.loadCDN(r.Context()); err != nil {
		s.log.Warn("reload cdn prefixes", "err", err)
	}
}
