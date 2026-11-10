package main

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"math"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/sebdraven/heimdall/internal/cdn"
	gjallarhorn "github.com/sebdraven/heimdall/internal/changes"
	"github.com/sebdraven/heimdall/internal/resolver"
	"github.com/sebdraven/heimdall/internal/store/ch"
	"github.com/sebdraven/heimdall/internal/store/pg"
)

const (
	analyticsShort   = 30
	analyticsLong    = 90
	analyticsEvents  = 200
	analyticsIPs     = 30
	analyticsLeads   = 50
	analyticsVTPairs = 5000
	entityEvents     = 20
)

// Liveness states of a domain on a day.
const (
	stateOK   = "ok"
	stateNX   = "nx"
	stateFail = "fail"
	stateNone = "none"
)

// analyticsStore is what /campaigns/{id}/analytics reads from ClickHouse.
type analyticsStore interface {
	CampaignLiveness(ctx context.Context, domains []string, since time.Time) ([]ch.DayState, error)
	CampaignEventCounts(ctx context.Context, campaign string, domains []string, since time.Time) ([]ch.KindCount, error)
	CampaignEvents(ctx context.Context, campaign string, domains []string, since time.Time, limit int) ([]gjallarhorn.Event, error)
	ZoneNSSets(ctx context.Context, domains []string) (map[string]*ch.NSSet, error)
	FirstSeen(ctx context.Context, names []string) (map[string]time.Time, error)
	NewIPsByDay(ctx context.Context, ips []string, since time.Time) ([]ch.NewIPs, error)
	VTPairs(ctx context.Context, hosts, ips []string, limit int) ([]ch.VTPair, error)
}

type analyticsStores struct {
	analyticsStore
	watchStore
}

type analyticsJSON struct {
	Days     int                 `json:"days"`
	Header   analyticsHeaderJSON `json:"header"`
	KPIs     kpisJSON            `json:"kpis"`
	Timeline timelineJSON        `json:"timeline"`
	Liveness livenessJSON        `json:"liveness"`
	Clusters clustersJSON        `json:"clusters"`
	Events   []eventJSON         `json:"events"`
	VTLeads  []vtLeadJSON        `json:"vt_leads"`
}

type analyticsCampaignJSON struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Family      string `json:"family"`
	Description string `json:"description"`
}

type analyticsHeaderJSON struct {
	Campaign       analyticsCampaignJSON `json:"campaign"`
	Domains        int                   `json:"domains"`
	Enabled        int                   `json:"enabled"`
	LastMeasuredAt *time.Time            `json:"last_measured_at"`
	VT             *vtBudgetJSON         `json:"vt"`
}

// kpiJSON holds one value per day of the window; Value is the last one.
type kpiJSON struct {
	Value  float64   `json:"value"`
	Series []float64 `json:"series"`
}

type kpisJSON struct {
	Resolving  kpiJSON `json:"resolving"`
	NXDomain   kpiJSON `json:"nxdomain"`
	Failing    kpiJSON `json:"failing"`
	Unmeasured kpiJSON `json:"unmeasured"`
	ActiveIPs  kpiJSON `json:"active_ips"`
	CDNShare   kpiJSON `json:"cdn_share"`
	NSSets     kpiJSON `json:"ns_sets"`
	Events7d   kpiJSON `json:"events_7d"`
}

type timelineJSON struct {
	Kinds []string          `json:"kinds"`
	Days  []timelineDayJSON `json:"days"`
}

type timelineDayJSON struct {
	Day    string            `json:"day"`
	Counts map[string]uint64 `json:"counts"`
}

type livenessJSON struct {
	Days []string          `json:"days"`
	Rows []livenessRowJSON `json:"rows"`
}

type livenessRowJSON struct {
	FQDN      string     `json:"fqdn"`
	Enabled   bool       `json:"enabled"`
	FirstSeen *time.Time `json:"first_seen"`
	Cells     []string   `json:"cells"`
}

type clustersJSON struct {
	IPs          []ipClusterJSON `json:"ips"`
	NSSets       []nsClusterJSON `json:"ns_sets"`
	NewIPsPerDay []newIPsJSON    `json:"new_ips_per_day"`
	ExcludedCDN  int             `json:"excluded_cdn"`
}

type ipClusterJSON struct {
	IP        string   `json:"ip"`
	Domains   []string `json:"domains"`
	FirstSeen string   `json:"first_seen"`
	LastSeen  string   `json:"last_seen"`
}

// nsClusterJSON is an NS set held by several zones of the campaign; Domains
// are the campaign's names under those zones.
type nsClusterJSON struct {
	NS      []string `json:"ns"`
	Zones   []string `json:"zones"`
	Domains []string `json:"domains"`
}

type newIPsJSON struct {
	Day string   `json:"day"`
	IPs []string `json:"ips"`
}

type vtLeadJSON struct {
	HostName string    `json:"host_name"`
	IPs      []string  `json:"ips"`
	LastSeen time.Time `json:"last_seen"`
}

// analyticsDays reads ?days=: 30 unless it is 90.
func analyticsDays(r *http.Request) int {
	if r.URL.Query().Get("days") == "90" {
		return analyticsLong
	}
	return analyticsShort
}

// windowDays returns the n UTC days ending today.
func windowDays(now time.Time, n int) []time.Time {
	today := now.UTC().Truncate(24 * time.Hour)
	out := make([]time.Time, n)
	for i := range out {
		out[i] = today.AddDate(0, 0, i-n+1)
	}
	return out
}

func dayKey(t time.Time) string { return t.UTC().Format(time.DateOnly) }

func dayIndex(days []time.Time) map[string]int {
	out := make(map[string]int, len(days))
	for i, d := range days {
		out[dayKey(d)] = i
	}
	return out
}

// liveState maps the rcode of the last observation of a day.
func liveState(rcode string) string {
	switch rcode {
	case "":
		return stateNone
	case "NOERROR":
		return stateOK
	case "NXDOMAIN":
		return stateNX
	}
	return stateFail
}

var stateRank = map[string]int{stateOK: 0, stateFail: 1, stateNX: 2, stateNone: 3}

func lastCell(cells []string) string {
	if len(cells) == 0 {
		return stateNone
	}
	return cells[len(cells)-1]
}

// compareFirstSeen puts names never seen last.
func compareFirstSeen(a, b *time.Time) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return 1
	case b == nil:
		return -1
	}
	return a.Compare(*b)
}

func compareLiveness(a, b livenessRowJSON) int {
	return cmp.Or(
		cmp.Compare(stateRank[lastCell(a.Cells)], stateRank[lastCell(b.Cells)]),
		compareFirstSeen(a.FirstSeen, b.FirstSeen),
		cmp.Compare(a.FQDN, b.FQDN),
	)
}

// buildLiveness gives every domain one state per day, sorted by current
// state then first seen.
func buildLiveness(domains []pg.Domain, days []time.Time, states []ch.DayState, first map[string]time.Time) livenessJSON {
	out := livenessJSON{Days: make([]string, 0, len(days)), Rows: make([]livenessRowJSON, 0, len(domains))}
	for _, d := range days {
		out.Days = append(out.Days, dayKey(d))
	}
	rows := make(map[string]int, len(domains))
	for _, d := range domains {
		row := livenessRowJSON{FQDN: d.FQDN, Enabled: d.Enabled, Cells: make([]string, len(days))}
		for i := range row.Cells {
			row.Cells[i] = stateNone
		}
		if t, ok := first[d.FQDN]; ok {
			t = t.UTC()
			row.FirstSeen = &t
		}
		rows[d.FQDN] = len(out.Rows)
		out.Rows = append(out.Rows, row)
	}
	idx := dayIndex(days)
	for _, st := range states {
		r, ok := rows[st.Domain]
		i, in := idx[st.Day]
		if ok && in {
			out.Rows[r].Cells[i] = liveState(st.Rcode)
		}
	}
	slices.SortStableFunc(out.Rows, compareLiveness)
	return out
}

type ipSpan struct {
	domains     map[string]bool
	first, last string
}

// ipSpans groups the addresses answered for the campaign, CDN ones apart.
func ipSpans(states []ch.DayState, cl *cdn.Classifier) (spans map[string]*ipSpan, cdns map[string]bool) {
	spans, cdns = map[string]*ipSpan{}, map[string]bool{}
	for _, st := range states {
		for _, ip := range st.IPs {
			if _, ok := cl.Classify(ip); ok {
				cdns[ip] = true
				continue
			}
			sp, ok := spans[ip]
			if !ok {
				sp = &ipSpan{domains: map[string]bool{}, first: st.Day, last: st.Day}
				spans[ip] = sp
			}
			sp.domains[st.Domain] = true
			sp.first, sp.last = min(sp.first, st.Day), max(sp.last, st.Day)
		}
	}
	return spans, cdns
}

// buildIPClusters keeps the addresses of at least two domains, most shared
// then most recent first.
func buildIPClusters(spans map[string]*ipSpan, limit int) []ipClusterJSON {
	out := []ipClusterJSON{}
	for ip, sp := range spans {
		if len(sp.domains) < 2 {
			continue
		}
		out = append(out, ipClusterJSON{IP: ip, Domains: slices.Sorted(maps.Keys(sp.domains)), FirstSeen: sp.first, LastSeen: sp.last})
	}
	slices.SortFunc(out, func(a, b ipClusterJSON) int {
		return cmp.Or(cmp.Compare(len(b.Domains), len(a.Domains)), cmp.Compare(b.LastSeen, a.LastSeen), cmp.Compare(a.IP, b.IP))
	})
	return out[:min(len(out), limit)]
}

type nsCluster struct {
	ns             []string
	zones, domains map[string]bool
}

// buildNSClusters groups the zones of the campaign by pairable NS set,
// keeping the sets of at least two zones.
func buildNSClusters(zones map[string]*ch.NSSet) []nsClusterJSON {
	sets := map[string]*nsCluster{}
	for fqdn, z := range zones {
		if !pairable(z) {
			continue
		}
		id := nssetID(z.NS)
		c, ok := sets[id]
		if !ok {
			c = &nsCluster{ns: slices.Compact(slices.Sorted(slices.Values(z.NS))), zones: map[string]bool{}, domains: map[string]bool{}}
			sets[id] = c
		}
		c.zones[z.Zone] = true
		c.domains[fqdn] = true
	}
	out := []nsClusterJSON{}
	for _, c := range sets {
		if len(c.zones) < 2 {
			continue
		}
		out = append(out, nsClusterJSON{NS: c.ns, Zones: slices.Sorted(maps.Keys(c.zones)), Domains: slices.Sorted(maps.Keys(c.domains))})
	}
	slices.SortFunc(out, func(a, b nsClusterJSON) int {
		return cmp.Or(cmp.Compare(len(b.Zones), len(a.Zones)), slices.Compare(a.NS, b.NS))
	})
	return out
}

// buildTimeline counts the events of each day by kind, and returns the
// totals per day.
func buildTimeline(days []time.Time, counts []ch.KindCount) (timelineJSON, []float64) {
	out := timelineJSON{Kinds: gjallarhorn.Kinds, Days: make([]timelineDayJSON, len(days))}
	for i, d := range days {
		out.Days[i] = timelineDayJSON{Day: dayKey(d), Counts: map[string]uint64{}}
	}
	totals := make([]float64, len(days))
	idx := dayIndex(days)
	for _, c := range counts {
		if i, ok := idx[c.Day]; ok {
			out.Days[i].Counts[c.Kind] += c.N
			totals[i] += float64(c.N)
		}
	}
	return out, totals
}

func buildNewIPs(days []time.Time, rows []ch.NewIPs) []newIPsJSON {
	out := make([]newIPsJSON, len(days))
	for i, d := range days {
		out[i] = newIPsJSON{Day: dayKey(d), IPs: []string{}}
	}
	idx := dayIndex(days)
	for _, r := range rows {
		if i, ok := idx[r.Day]; ok {
			out[i].IPs = append(out[i].IPs, r.IPs...)
		}
	}
	return out
}

func kpi(series []float64) kpiJSON {
	return kpiJSON{Value: series[len(series)-1], Series: series}
}

// buildKPIs computes each indicator per day. CDN addresses are not active
// addresses, cdn_share is their share of all addresses answered, ns_sets
// counts the pairable sets whose period covers the day and events_7d sums
// the events of the last 7 days.
func buildKPIs(days []time.Time, live livenessJSON, states []ch.DayState, zones map[string]*ch.NSSet, events []float64, cl *cdn.Classifier) kpisJSON {
	n := len(days)
	ok, nx, fail, none := make([]float64, n), make([]float64, n), make([]float64, n), make([]float64, n)
	for _, r := range live.Rows {
		for i, c := range r.Cells {
			switch c {
			case stateOK:
				ok[i]++
			case stateNX:
				nx[i]++
			case stateFail:
				fail[i]++
			default:
				none[i]++
			}
		}
	}

	kept, cdns := make([]map[string]bool, n), make([]map[string]bool, n)
	for i := range n {
		kept[i], cdns[i] = map[string]bool{}, map[string]bool{}
	}
	idx := dayIndex(days)
	for _, st := range states {
		i, in := idx[st.Day]
		if !in {
			continue
		}
		for _, ip := range st.IPs {
			if _, isCDN := cl.Classify(ip); isCDN {
				cdns[i][ip] = true
			} else {
				kept[i][ip] = true
			}
		}
	}
	active, share := make([]float64, n), make([]float64, n)
	for i := range n {
		active[i] = float64(len(kept[i]))
		if all := len(kept[i]) + len(cdns[i]); all > 0 {
			share[i] = math.Round(float64(len(cdns[i]))/float64(all)*1e4) / 1e4
		}
	}

	sets := make([]float64, n)
	for i, d := range days {
		end := d.Add(24 * time.Hour)
		seen := map[string]bool{}
		for _, z := range zones {
			if pairable(z) && !z.Period.Last.Before(d) && z.Period.First.Before(end) {
				seen[nssetID(z.NS)] = true
			}
		}
		sets[i] = float64(len(seen))
	}

	week := make([]float64, n)
	for i := range n {
		for j := max(0, i-6); j <= i; j++ {
			week[i] += events[j]
		}
	}
	return kpisJSON{
		Resolving: kpi(ok), NXDomain: kpi(nx), Failing: kpi(fail), Unmeasured: kpi(none),
		ActiveIPs: kpi(active), CDNShare: kpi(share), NSSets: kpi(sets), Events7d: kpi(week),
	}
}

// buildVTLeads groups by name the pairs whose name is not watched, most
// shared addresses then most recent first.
func buildVTLeads(pairs []ch.VTPair, watched map[string]pg.Domain, limit int) []vtLeadJSON {
	byHost := map[string]*vtLeadJSON{}
	for _, p := range pairs {
		if _, ok := watched[p.HostName]; ok {
			continue
		}
		l, ok := byHost[p.HostName]
		if !ok {
			l = &vtLeadJSON{HostName: p.HostName}
			byHost[p.HostName] = l
		}
		if !slices.Contains(l.IPs, p.IP) {
			l.IPs = append(l.IPs, p.IP)
		}
		if last := p.Period.Last.UTC(); last.After(l.LastSeen) {
			l.LastSeen = last
		}
	}
	out := make([]vtLeadJSON, 0, len(byHost))
	for _, l := range byHost {
		slices.Sort(l.IPs)
		out = append(out, *l)
	}
	slices.SortFunc(out, func(a, b vtLeadJSON) int {
		return cmp.Or(cmp.Compare(len(b.IPs), len(a.IPs)), b.LastSeen.Compare(a.LastSeen), cmp.Compare(a.HostName, b.HostName))
	})
	return out[:min(len(out), limit)]
}

func lastMeasured(states []ch.DayState) *time.Time {
	var last time.Time
	for _, st := range states {
		if st.LastTS.After(last) {
			last = st.LastTS
		}
	}
	if last.IsZero() {
		return nil
	}
	last = last.UTC()
	return &last
}

// loadAnalytics reads the analytics of campaign id over the last n days.
func (s *server) loadAnalytics(ctx context.Context, id int64, n int) (analyticsJSON, error) {
	c, err := s.analytics.Campaign(ctx, id)
	if err != nil {
		return analyticsJSON{}, err
	}
	domains, err := s.analytics.Domains(ctx, &id)
	if err != nil {
		return analyticsJSON{}, err
	}
	fqdns := make([]string, 0, len(domains))
	enabled := 0
	for _, d := range domains {
		fqdns = append(fqdns, d.FQDN)
		if d.Enabled {
			enabled++
		}
	}
	days := windowDays(s.now(), n)
	since := days[0]

	states, err := s.analytics.CampaignLiveness(ctx, fqdns, since)
	if err != nil {
		return analyticsJSON{}, fmt.Errorf("liveness: %w", err)
	}
	counts, err := s.analytics.CampaignEventCounts(ctx, c.Name, fqdns, since)
	if err != nil {
		return analyticsJSON{}, fmt.Errorf("event counts: %w", err)
	}
	events, err := s.analytics.CampaignEvents(ctx, c.Name, fqdns, since, analyticsEvents)
	if err != nil {
		return analyticsJSON{}, fmt.Errorf("events: %w", err)
	}
	zones, err := s.analytics.ZoneNSSets(ctx, fqdns)
	if err != nil {
		return analyticsJSON{}, fmt.Errorf("ns sets: %w", err)
	}
	first, err := s.analytics.FirstSeen(ctx, fqdns)
	if err != nil {
		return analyticsJSON{}, fmt.Errorf("first seen: %w", err)
	}
	spans, cdns := ipSpans(states, s.cdn)
	ips := slices.Sorted(maps.Keys(spans))
	newIPs, err := s.analytics.NewIPsByDay(ctx, ips, since)
	if err != nil {
		return analyticsJSON{}, fmt.Errorf("new ips: %w", err)
	}

	live := buildLiveness(domains, days, states, first)
	timeline, totals := buildTimeline(days, counts)
	header := analyticsHeaderJSON{
		Campaign:       analyticsCampaignJSON{ID: c.ID, Name: c.Name, Family: c.Family, Description: c.Description},
		Domains:        len(domains),
		Enabled:        enabled,
		LastMeasuredAt: lastMeasured(states),
	}
	clusters := clustersJSON{
		IPs:          buildIPClusters(spans, analyticsIPs),
		NSSets:       buildNSClusters(zones),
		NewIPsPerDay: buildNewIPs(days, newIPs),
		ExcludedCDN:  len(cdns),
	}
	out := analyticsJSON{
		Days:     n,
		Header:   header,
		KPIs:     buildKPIs(days, live, states, zones, totals, s.cdn),
		Timeline: timeline,
		Liveness: live,
		Clusters: clusters,
		Events:   toEventsJSON(events),
	}
	if s.vt == nil {
		return out, nil
	}
	if out.VTLeads, err = s.loadVTLeads(ctx, ips); err != nil {
		return analyticsJSON{}, err
	}
	used, remaining, err := s.vt.Usage(ctx)
	if err != nil {
		return analyticsJSON{}, fmt.Errorf("vt usage: %w", err)
	}
	out.Header.VT = &vtBudgetJSON{Budget: s.vt.Budget, UsedToday: used, Remaining: remaining}
	return out, nil
}

// loadVTLeads reads the names VirusTotal saw on ips, from the cache only.
func (s *server) loadVTLeads(ctx context.Context, ips []string) ([]vtLeadJSON, error) {
	pairs, err := s.analytics.VTPairs(ctx, nil, ips, analyticsVTPairs)
	if err != nil {
		return nil, fmt.Errorf("vt pairs: %w", err)
	}
	hosts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		hosts = append(hosts, p.HostName)
	}
	watched, err := s.analytics.DomainsByFQDN(ctx, slices.Compact(slices.Sorted(slices.Values(hosts))))
	if err != nil {
		return nil, err
	}
	return buildVTLeads(pairs, watched, analyticsLeads), nil
}

// apiAnalytics serves GET /campaigns/{id}/analytics/data and GET
// /api/campaigns/{id}/analytics?days=30|90.
func (s *server) apiAnalytics(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		apiError(w, http.StatusNotFound, "not found")
		return
	}
	a, err := s.loadAnalytics(r.Context(), id, analyticsDays(r))
	if err != nil {
		s.apiStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, a)
}

// analyticsView is what analytics.html shows. Linked are the campaigns of
// highest score linked to it, Correlated whether the links were computed.
type analyticsView struct {
	Campaign   pg.Campaign
	Days       int
	Linked     []linkedCampaign
	Correlated bool
}

func (s *server) analyticsPage(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		s.fail(w, r, http.StatusNotFound, "Not found.", nil)
		return
	}
	c, err := s.analytics.Campaign(r.Context(), id)
	if err != nil {
		s.storeFail(w, r, err)
		return
	}
	v := analyticsView{Campaign: c, Days: analyticsDays(r)}
	if v.Linked, v.Correlated, err = s.linkedCampaigns(r.Context(), id); err != nil {
		s.storeFail(w, r, err)
		return
	}
	s.render(w, r, "analytics", http.StatusOK, v)
}

// entityDomainJSON is the side panel of a name on the analytics page.
type entityDomainJSON struct {
	FQDN      string        `json:"fqdn"`
	Domain    *domainJSON   `json:"domain"`
	FirstSeen *time.Time    `json:"first_seen"`
	LastSeen  *time.Time    `json:"last_seen"`
	Current   []currentJSON `json:"current"`
	Events    []eventJSON   `json:"events"`
	VT        *vtDetailJSON `json:"vt"`
	Href      string        `json:"href"`
	Graph     string        `json:"graph"`
}

// pdnsPeriod returns when the records were first and last seen, nil without
// records.
func pdnsPeriod(records []ch.PDNSRecord) (first, last *time.Time) {
	for _, r := range records {
		f, l := r.FirstSeen.UTC(), r.LastSeen.UTC()
		if first == nil || f.Before(*first) {
			first = &f
		}
		if last == nil || l.After(*last) {
			last = &l
		}
	}
	return first, last
}

// entityDomain serves GET /entity/domain/{fqdn}.
func (s *server) entityDomain(w http.ResponseWriter, r *http.Request) {
	fqdn := resolver.Name(r.PathValue("fqdn"))
	dd, err := s.loadDomain(r.Context(), fqdn, entityEvents)
	if err != nil {
		s.apiStoreError(w, r, err)
		return
	}
	events, err := s.ch.Events(r.Context(), ch.EventFilter{Since: s.now().AddDate(0, 0, -analyticsLong), Domain: fqdn, Limit: entityEvents})
	if err != nil {
		s.apiStoreError(w, r, fmt.Errorf("events: %w", err))
		return
	}
	d := toDomainDetailJSON(dd, s.cdn)
	out := entityDomainJSON{
		FQDN: fqdn, Domain: d.Domain, Current: d.Current, Events: toEventsJSON(events), VT: d.VT,
		Href: "/domains/" + url.PathEscape(fqdn), Graph: "/graph/domain/" + url.PathEscape(fqdn),
	}
	out.FirstSeen, out.LastSeen = pdnsPeriod(dd.PDNS)
	writeJSON(w, http.StatusOK, out)
}

// entityIPJSON is the side panel of an address: the names Heimdall saw on
// it and, with VirusTotal, those of the cache.
type entityIPJSON struct {
	IP        string           `json:"ip"`
	CDN       string           `json:"cdn"`
	Names     []searchNameJSON `json:"names"`
	Truncated bool             `json:"truncated"`
	VT        *vtIPJSON        `json:"vt"`
	Href      string           `json:"href"`
}

// entityIP serves GET /entity/ip/{ip}.
func (s *server) entityIP(w http.ResponseWriter, r *http.Request) {
	a, err := netip.ParseAddr(strings.TrimSpace(r.PathValue("ip")))
	if err != nil {
		apiError(w, http.StatusBadRequest, "not an IP address")
		return
	}
	ip := a.String()
	records, err := s.ch.PDNSByRdata(r.Context(), ip, rdataLimit)
	if err != nil {
		s.apiStoreError(w, r, fmt.Errorf("pdns by rdata: %w", err))
		return
	}
	names, _ := groupRecords(records)
	rows, err := s.attachWatched(r.Context(), names)
	if err != nil {
		s.apiStoreError(w, r, err)
		return
	}
	out := entityIPJSON{IP: ip, Names: toSearchNamesJSON(rows), Truncated: len(records) == rdataLimit, Href: "/rdata/" + url.PathEscape(ip)}
	out.CDN, _ = s.cdn.Classify(ip)
	if s.vt != nil {
		v, err := s.loadVTIP(r.Context(), ip)
		if err != nil {
			s.apiStoreError(w, r, err)
			return
		}
		out.VT = &v
	}
	writeJSON(w, http.StatusOK, out)
}
