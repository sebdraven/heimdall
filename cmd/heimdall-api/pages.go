package main

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sebdraven/heimdall/internal/auth"
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

func (s *server) domainPage(w http.ResponseWriter, r *http.Request) {
	fqdn := resolver.Name(r.PathValue("fqdn"))
	var domain *pg.Domain
	d, err := s.pg.Domain(r.Context(), fqdn)
	switch {
	case err == nil:
		domain = &d
	case !errors.Is(err, pg.ErrNotFound):
		s.storeFail(w, r, err)
		return
	}
	current, err := s.ch.CurrentState(r.Context(), fqdn)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "current state", err)
		return
	}
	changes, err := s.ch.DomainChanges(r.Context(), fqdn, 200)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "changes", err)
		return
	}
	records, err := s.ch.PDNSByName(r.Context(), fqdn, 1000)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "pdns", err)
		return
	}
	values, exclude := sharingQuery(fqdn, current)
	sharing, err := s.ch.RdataSharing(r.Context(), values, exclude)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "rdata sharing", err)
		return
	}
	s.render(w, r, "domain", http.StatusOK, map[string]any{
		"FQDN": fqdn, "Domain": domain, "Current": current, "Changes": changes, "PDNS": records, "Sharing": sharing,
	})
}

// sharingQuery returns the distinct values shown in Current state and the
// owner names not to count: the domain itself and its CNAME targets, which
// own the values reached through the chain.
func sharingQuery(fqdn string, current []ch.Current) (values, exclude []string) {
	exclude = []string{fqdn}
	for _, c := range current {
		values = append(values, c.Rdata...)
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
	audit, err := s.pg.AuditLog(r.Context(), 200)
	if err != nil {
		s.storeFail(w, r, err)
		return
	}
	s.render(w, r, "admin", http.StatusOK, map[string]any{"Resolvers": resolvers, "NSClasses": classes, "Audit": audit})
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
