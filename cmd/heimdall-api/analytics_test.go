package main

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	gjallarhorn "github.com/sebdraven/heimdall/internal/changes"
	"github.com/sebdraven/heimdall/internal/store/ch"
	"github.com/sebdraven/heimdall/internal/store/pg"
	"github.com/sebdraven/heimdall/internal/vt"
)

var analyticsNow = time.Date(2026, 3, 3, 15, 0, 0, 0, time.UTC)

func utcDay(d string) time.Time {
	t, err := time.Parse(time.DateOnly, d)
	if err != nil {
		panic(err)
	}
	return t
}

func TestLiveState(t *testing.T) {
	for _, tt := range []struct{ rcode, want string }{
		{"NOERROR", stateOK},
		{"NXDOMAIN", stateNX},
		{"SERVFAIL", stateFail},
		{"TIMEOUT", stateFail},
		{"REFUSED", stateFail},
		{"NETERR", stateFail},
		{"", stateNone},
	} {
		if got := liveState(tt.rcode); got != tt.want {
			t.Errorf("liveState(%q) = %s, want %s", tt.rcode, got, tt.want)
		}
	}
}

func TestWindowDays(t *testing.T) {
	cest := time.FixedZone("CEST", 2*3600)
	days := windowDays(time.Date(2026, 3, 3, 0, 30, 0, 0, cest), 30)
	if len(days) != 30 {
		t.Fatalf("%d days, want 30", len(days))
	}
	if !days[0].Equal(utcDay("2026-02-01")) || !days[29].Equal(utcDay("2026-03-02")) {
		t.Errorf("window from %s to %s, want UTC days 2026-02-01 to 2026-03-02", days[0], days[29])
	}
}

func TestBuildLiveness(t *testing.T) {
	domains := []pg.Domain{
		{FQDN: "a.example", Enabled: true},
		{FQDN: "b.example", Enabled: true},
		{FQDN: "c.example"},
		{FQDN: "d.example", Enabled: true},
	}
	states := []ch.DayState{
		{Domain: "a.example", Day: "2026-03-01", Rcode: "NOERROR"},
		{Domain: "a.example", Day: "2026-03-03", Rcode: "NXDOMAIN"},
		{Domain: "b.example", Day: "2026-03-02", Rcode: "SERVFAIL"},
		{Domain: "b.example", Day: "2026-03-03", Rcode: "NOERROR"},
		{Domain: "c.example", Day: "2026-03-02", Rcode: ""},
		{Domain: "c.example", Day: "2026-03-03", Rcode: "NOERROR"},
		{Domain: "d.example", Day: "2026-03-03", Rcode: "NOERROR"},
		{Domain: "a.example", Day: "2026-02-01", Rcode: "NOERROR"},
		{Domain: "unwatched.example", Day: "2026-03-03", Rcode: "NOERROR"},
	}
	first := map[string]time.Time{"b.example": utcDay("2026-02-01"), "c.example": utcDay("2026-01-01")}
	live := buildLiveness(domains, windowDays(analyticsNow, 3), states, first)

	if got := strings.Join(live.Days, " "); got != "2026-03-01 2026-03-02 2026-03-03" {
		t.Errorf("days = %s", got)
	}
	var rows []string
	for _, r := range live.Rows {
		rows = append(rows, r.FQDN+":"+strings.Join(r.Cells, ","))
	}
	// Resolving today first, by first seen, never seen last; then failing, NXDOMAIN, unmeasured.
	if got, want := strings.Join(rows, " "), "c.example:none,none,ok b.example:none,fail,ok d.example:none,none,ok a.example:ok,none,nx"; got != want {
		t.Errorf("rows =\n%s\nwant\n%s", got, want)
	}
	if got := encode(t, live.Rows[0]); got != `{"fqdn":"c.example","enabled":false,"first_seen":"2026-01-01T00:00:00Z","cells":["none","none","ok"]}` {
		t.Errorf("row = %s", got)
	}
	if live.Rows[2].FirstSeen != nil {
		t.Errorf("d.example first seen = %v, want null", live.Rows[2].FirstSeen)
	}
}

func TestIPClustersCDN(t *testing.T) {
	spans, cdns := ipSpans([]ch.DayState{
		{Domain: "a.example", Day: "2026-03-01", IPs: []string{"192.0.2.1", "104.16.0.1", "192.0.2.9"}},
		{Domain: "b.example", Day: "2026-03-02", IPs: []string{"192.0.2.1", "104.16.0.1", "192.0.2.2"}},
		{Domain: "c.example", Day: "2026-03-03", IPs: []string{"192.0.2.2", "192.0.2.1", "2606:4700::1"}},
	}, testCDN())
	if len(cdns) != 2 || !cdns["104.16.0.1"] || !cdns["2606:4700::1"] {
		t.Errorf("cdn = %v, want 104.16.0.1 and 2606:4700::1", cdns)
	}
	if got := strings.Join(slices.Sorted(maps.Keys(spans)), " "); got != "192.0.2.1 192.0.2.2 192.0.2.9" {
		t.Errorf("addresses = %s, want the non-CDN ones", got)
	}

	want := `[{"ip":"192.0.2.1","domains":["a.example","b.example","c.example"],"first_seen":"2026-03-01","last_seen":"2026-03-03"},` +
		`{"ip":"192.0.2.2","domains":["b.example","c.example"],"first_seen":"2026-03-02","last_seen":"2026-03-03"}]`
	if got := encode(t, buildIPClusters(spans, analyticsIPs)); got != want {
		t.Errorf("clusters =\n%s\nwant\n%s", got, want)
	}
	if got := buildIPClusters(spans, 1); len(got) != 1 || got[0].IP != "192.0.2.1" {
		t.Errorf("limit 1 = %+v, want 192.0.2.1 only", got)
	}
	if got := encode(t, buildIPClusters(map[string]*ipSpan{}, analyticsIPs)); got != "[]" {
		t.Errorf("no address = %s, want []", got)
	}
}

func TestBuildNSClusters(t *testing.T) {
	zones := map[string]*ch.NSSet{}
	for _, z := range []struct {
		fqdn string
		ns   *ch.NSSet
	}{
		{"www.a.example", pairNS("a.example")},
		{"a.example", pairNS("a.example")},
		{"b.example", pairNS("b.example")},
		{"c.example", &ch.NSSet{Zone: "c.example", NS: []string{"ns1.q.example", "ns2.q.example"}}},
		{"d.example", &ch.NSSet{Zone: "d.example", NS: []string{"ns1.p.example"}}},
		{"e.example", &ch.NSSet{Zone: "e.example", NS: []string{"ns1.p.example"}}},
	} {
		zones[z.fqdn] = z.ns
	}
	want := `[{"ns":["ns1.p.example","ns2.p.example"],"zones":["a.example","b.example"],"domains":["a.example","b.example","www.a.example"]}]`
	if got := encode(t, buildNSClusters(zones)); got != want {
		t.Errorf("ns clusters =\n%s\nwant\n%s", got, want)
	}
}

func vtLead(host, ip, last string) ch.VTPair {
	return ch.VTPair{HostName: host, IP: ip, Period: ch.Period{First: utcDay("2025-12-01"), Last: utcDay(last)}}
}

func vtLeadPairs() []ch.VTPair {
	return []ch.VTPair{
		vtLead("evil.example", "192.0.2.1", "2026-03-01"),
		vtLead("evil.example", "192.0.2.2", "2026-02-20"),
		vtLead("other.example", "192.0.2.2", "2026-03-02"),
		vtLead("a.example", "192.0.2.1", "2026-03-03"),
		vtLead("old.example", "192.0.2.1", "2026-01-01"),
	}
}

const analyticsLeadsJSON = `[{"host_name":"evil.example","ips":["192.0.2.1","192.0.2.2"],"last_seen":"2026-03-01T00:00:00Z"},` +
	`{"host_name":"other.example","ips":["192.0.2.2"],"last_seen":"2026-03-02T00:00:00Z"},` +
	`{"host_name":"old.example","ips":["192.0.2.1"],"last_seen":"2026-01-01T00:00:00Z"}]`

func TestBuildVTLeads(t *testing.T) {
	pairs := append(vtLeadPairs(), vtLead("evil.example", "192.0.2.1", "2026-02-25"))
	watched := map[string]pg.Domain{"a.example": {FQDN: "a.example"}}
	if got := encode(t, buildVTLeads(pairs, watched, analyticsLeads)); got != analyticsLeadsJSON {
		t.Errorf("leads =\n%s\nwant\n%s", got, analyticsLeadsJSON)
	}
	if got := buildVTLeads(pairs, watched, 2); len(got) != 2 || got[1].HostName != "other.example" {
		t.Errorf("limit 2 = %+v", got)
	}
	if got := encode(t, buildVTLeads(nil, nil, analyticsLeads)); got != "[]" {
		t.Errorf("no pair = %s, want []", got)
	}
}

func TestBuildKPIs(t *testing.T) {
	days := windowDays(analyticsNow, 3)
	live := livenessJSON{Rows: []livenessRowJSON{
		{Cells: []string{stateOK, stateOK, stateNX}},
		{Cells: []string{stateNone, stateOK, stateOK}},
		{Cells: []string{stateNone, stateNone, stateFail}},
	}}
	states := []ch.DayState{
		{Domain: "a.example", Day: "2026-03-01", IPs: []string{"192.0.2.1", "104.16.0.1"}},
		{Domain: "a.example", Day: "2026-03-02", IPs: []string{"192.0.2.1"}},
		{Domain: "b.example", Day: "2026-03-02", IPs: []string{"192.0.2.1", "192.0.2.2"}},
		{Domain: "b.example", Day: "2026-03-03", IPs: []string{"192.0.2.2", "104.16.0.1", "104.16.0.2"}},
		{Domain: "b.example", Day: "2026-02-01", IPs: []string{"198.51.100.1"}},
	}
	a := pairNS("a.example")
	a.Period = ch.Period{First: utcDay("2026-02-25"), Last: utcDay("2026-03-02").Add(12 * time.Hour)}
	b := &ch.NSSet{Zone: "b.example", NS: []string{"ns1.q.example", "ns2.q.example"}}
	b.Period = ch.Period{First: utcDay("2026-03-02").Add(6 * time.Hour), Last: utcDay("2026-03-03").Add(6 * time.Hour)}
	c := &ch.NSSet{Zone: "c.example", NS: []string{"ns1.r.example"}, Period: a.Period}
	zones := map[string]*ch.NSSet{"a.example": a, "b.example": b, "c.example": c}

	got := encode(t, buildKPIs(days, live, states, zones, []float64{2, 0, 1}, testCDN()))
	want := `{"resolving":{"value":1,"series":[1,2,1]},"nxdomain":{"value":1,"series":[0,0,1]},` +
		`"failing":{"value":1,"series":[0,0,1]},"unmeasured":{"value":0,"series":[2,1,0]},` +
		`"active_ips":{"value":1,"series":[1,2,1]},"cdn_share":{"value":0.6667,"series":[0.5,0,0.6667]},` +
		`"ns_sets":{"value":1,"series":[1,2,1]},"events_7d":{"value":3,"series":[2,2,3]}}`
	if got != want {
		t.Errorf("kpis =\n%s\nwant\n%s", got, want)
	}

	week := buildKPIs(windowDays(analyticsNow, 9), livenessJSON{}, nil, nil, []float64{1, 2, 3, 4, 5, 6, 7, 8, 9}, testCDN()).Events7d
	if !slices.Equal(week.Series, []float64{1, 3, 6, 10, 15, 21, 28, 35, 42}) || week.Value != 42 {
		t.Errorf("events_7d = %+v, want a 7-day rolling sum", week)
	}
}

type fakeAnalyticsStore struct {
	domains []pg.Domain
	states  []ch.DayState
	counts  []ch.KindCount
	events  []gjallarhorn.Event
	zones   map[string]*ch.NSSet
	first   map[string]time.Time
	newIPs  []ch.NewIPs
	vt      []ch.VTPair
	watched map[string]pg.Domain
	since   time.Time
	ips     []string
	vtCalls int
}

func (f *fakeAnalyticsStore) Campaign(_ context.Context, id int64) (pg.Campaign, error) {
	if id != 7 {
		return pg.Campaign{}, pg.ErrNotFound
	}
	return pg.Campaign{ID: 7, Name: "spynote", Family: "SpyNote", Description: "Android RAT"}, nil
}

func (f *fakeAnalyticsStore) Domains(context.Context, *int64) ([]pg.Domain, error) {
	return f.domains, nil
}

func (f *fakeAnalyticsStore) DomainsByFQDN(_ context.Context, fqdns []string) (map[string]pg.Domain, error) {
	out := map[string]pg.Domain{}
	for _, fqdn := range fqdns {
		if d, ok := f.watched[fqdn]; ok {
			out[fqdn] = d
		}
	}
	return out, nil
}

func (f *fakeAnalyticsStore) CampaignLiveness(_ context.Context, _ []string, since time.Time) ([]ch.DayState, error) {
	f.since = since
	return f.states, nil
}

func (f *fakeAnalyticsStore) CampaignEventCounts(context.Context, string, []string, time.Time) ([]ch.KindCount, error) {
	return f.counts, nil
}

func (f *fakeAnalyticsStore) CampaignEvents(context.Context, string, []string, time.Time, int) ([]gjallarhorn.Event, error) {
	return f.events, nil
}

func (f *fakeAnalyticsStore) ZoneNSSets(context.Context, []string) (map[string]*ch.NSSet, error) {
	return f.zones, nil
}

func (f *fakeAnalyticsStore) FirstSeen(context.Context, []string) (map[string]time.Time, error) {
	return f.first, nil
}

func (f *fakeAnalyticsStore) NewIPsByDay(_ context.Context, ips []string, _ time.Time) ([]ch.NewIPs, error) {
	f.ips = ips
	return f.newIPs, nil
}

func (f *fakeAnalyticsStore) VTPairs(context.Context, []string, []string, int) ([]ch.VTPair, error) {
	f.vtCalls++
	return f.vt, nil
}

func utcAt(day string, d time.Duration) time.Time { return utcDay(day).Add(d) }

func analyticsTestServer(t *testing.T) (*server, *fakeAnalyticsStore) {
	t.Helper()
	f := &fakeAnalyticsStore{}
	f.domains = []pg.Domain{
		{FQDN: "a.example", Enabled: true},
		{FQDN: "b.example", Enabled: true},
		{FQDN: "c.example"},
	}
	f.states = []ch.DayState{
		{Domain: "a.example", Day: "2026-03-01", Rcode: "NOERROR", LastTS: utcAt("2026-03-01", 10*time.Hour), IPs: []string{"192.0.2.1", "104.16.0.1"}},
		{Domain: "a.example", Day: "2026-03-02", Rcode: "NOERROR", LastTS: utcAt("2026-03-02", 10*time.Hour), IPs: []string{"192.0.2.1"}},
		{Domain: "a.example", Day: "2026-03-03", Rcode: "NXDOMAIN", LastTS: utcAt("2026-03-03", 14*time.Hour), IPs: []string{}},
		{Domain: "b.example", Day: "2026-03-02", Rcode: "NOERROR", LastTS: utcAt("2026-03-02", 11*time.Hour), IPs: []string{"192.0.2.1", "192.0.2.2"}},
		{Domain: "b.example", Day: "2026-03-03", Rcode: "NOERROR", LastTS: utcAt("2026-03-03", 14*time.Hour+30*time.Minute), IPs: []string{"192.0.2.2", "104.16.0.1"}},
		{Domain: "c.example", Day: "2026-03-03", Rcode: "TIMEOUT", LastTS: utcAt("2026-03-03", 9*time.Hour), IPs: []string{}},
	}
	f.counts = []ch.KindCount{
		{Day: "2026-01-01", Kind: gjallarhorn.KindNewRdata, N: 5},
		{Day: "2026-03-01", Kind: gjallarhorn.KindNewRdata, N: 2},
		{Day: "2026-03-03", Kind: gjallarhorn.KindNXDomain, N: 1},
	}
	f.events = []gjallarhorn.Event{{
		TS: utcAt("2026-03-03", 14*time.Hour), Domain: "a.example", Campaign: "spynote", Kind: gjallarhorn.KindNXDomain,
		QType: "A", Resolver: "9.9.9.9:53", Detail: `{"prev_rdata":["192.0.2.1"]}`,
	}}
	a, b := pairNS("a.example"), pairNS("b.example")
	a.Period = ch.Period{First: utcDay("2026-02-25"), Last: utcDay("2026-03-03")}
	b.Period = ch.Period{First: utcDay("2026-03-01"), Last: utcDay("2026-03-03")}
	f.zones = map[string]*ch.NSSet{"a.example": a, "b.example": b, "c.example": {Zone: "c.example", NS: []string{"ns1.q.example"}}}
	f.first = map[string]time.Time{"a.example": utcDay("2026-01-10"), "b.example": utcDay("2026-02-20")}
	f.newIPs = []ch.NewIPs{{Day: "2026-03-02", IPs: []string{"192.0.2.2"}}}
	f.vt = vtLeadPairs()
	f.watched = map[string]pg.Domain{"a.example": {FQDN: "a.example", Campaign: "spynote"}}

	s := testServer(t)
	s.cdn = testCDN()
	s.now = func() time.Time { return analyticsNow }
	s.analytics = analyticsStores{f, f}
	return s, f
}

func decodeAnalytics(t *testing.T, body string) analyticsJSON {
	t.Helper()
	var a analyticsJSON
	if err := json.Unmarshal([]byte(body), &a); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}
	return a
}

func TestAPIAnalytics(t *testing.T) {
	s, f := analyticsTestServer(t)
	code, body := serveGraph(t, s, s.apiAnalytics, "/campaigns/7/analytics/data", "id", "7")
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	for _, want := range []string{
		`{"days":30,"header":{"campaign":{"id":7,"name":"spynote","family":"SpyNote","description":"Android RAT"},` +
			`"domains":3,"enabled":2,"last_measured_at":"2026-03-03T14:30:00Z","vt":null},`,
		`"ips":[{"ip":"192.0.2.1","domains":["a.example","b.example"],"first_seen":"2026-03-01","last_seen":"2026-03-02"}],` +
			`"ns_sets":[{"ns":["ns1.p.example","ns2.p.example"],"zones":["a.example","b.example"],"domains":["a.example","b.example"]}],`,
		`{"day":"2026-03-02","ips":["192.0.2.2"]},{"day":"2026-03-03","ips":[]}],"excluded_cdn":1}`,
		`"events":[{"ts":"2026-03-03T14:00:00Z","domain":"a.example","campaign":"spynote","kind":"nxdomain","qtype":"A",` +
			`"resolver":"9.9.9.9:53","detail":{"prev_rdata":["192.0.2.1"]}}],"vt_leads":null}`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %s\n%s", want, body)
		}
	}
	if f.vtCalls != 0 {
		t.Errorf("%d VirusTotal cache reads without VirusTotal", f.vtCalls)
	}
	if !f.since.Equal(utcDay("2026-02-02")) {
		t.Errorf("since = %s, want 2026-02-02", f.since)
	}
	if got := strings.Join(f.ips, " "); got != "192.0.2.1 192.0.2.2" {
		t.Errorf("new ips asked for %s, want the non-CDN addresses", got)
	}

	a := decodeAnalytics(t, body)
	var rows []string
	for _, r := range a.Liveness.Rows {
		rows = append(rows, r.FQDN+":"+strings.Join(r.Cells[27:], ","))
	}
	if got, want := strings.Join(rows, " "), "b.example:none,ok,ok c.example:none,none,fail a.example:ok,ok,nx"; got != want {
		t.Errorf("liveness = %s, want %s", got, want)
	}
	if got := a.Timeline.Days[27]; got.Day != "2026-03-01" || got.Counts[gjallarhorn.KindNewRdata] != 2 || len(a.Timeline.Days[0].Counts) != 0 {
		t.Errorf("timeline = %+v ... %+v", a.Timeline.Days[0], got)
	}
	k := a.KPIs
	for _, tt := range []struct {
		name string
		got  kpiJSON
		want float64
	}{
		{"resolving", k.Resolving, 1},
		{"nxdomain", k.NXDomain, 1},
		{"failing", k.Failing, 1},
		{"unmeasured", k.Unmeasured, 0},
		{"active_ips", k.ActiveIPs, 1},
		{"cdn_share", k.CDNShare, 0.5},
		{"ns_sets", k.NSSets, 1},
		{"events_7d", k.Events7d, 3},
	} {
		if tt.got.Value != tt.want || len(tt.got.Series) != 30 {
			t.Errorf("%s = %v over %d days, want %v over 30", tt.name, tt.got.Value, len(tt.got.Series), tt.want)
		}
	}
}

func TestAPIAnalyticsDays(t *testing.T) {
	s, f := analyticsTestServer(t)
	for _, tt := range []struct {
		query string
		days  int
	}{
		{"", 30},
		{"?days=30", 30},
		{"?days=90", 90},
		{"?days=7", 30},
		{"?days=365", 30},
		{"?days=-90", 30},
		{"?days=abc", 30},
	} {
		code, body := serveGraph(t, s, s.apiAnalytics, "/campaigns/7/analytics/data"+tt.query, "id", "7")
		if code != http.StatusOK {
			t.Fatalf("%q: status %d: %s", tt.query, code, body)
		}
		a := decodeAnalytics(t, body)
		if a.Days != tt.days || len(a.Liveness.Days) != tt.days || len(a.Timeline.Days) != tt.days ||
			len(a.KPIs.Resolving.Series) != tt.days || len(a.Clusters.NewIPsPerDay) != tt.days {
			t.Errorf("%q: window of %d days, want %d", tt.query, a.Days, tt.days)
		}
		if want := windowDays(analyticsNow, tt.days)[0]; !f.since.Equal(want) {
			t.Errorf("%q: since = %s, want %s", tt.query, f.since, want)
		}
	}
}

func TestAPIAnalyticsVT(t *testing.T) {
	s, f := analyticsTestServer(t)
	s.vt = &vt.Enricher{Ledger: usedLedger{n: 120}, Budget: 500}
	_, body := serveGraph(t, s, s.apiAnalytics, "/campaigns/7/analytics/data", "id", "7")
	if want := `"last_measured_at":"2026-03-03T14:30:00Z","vt":{"budget":500,"used_today":120,"remaining":380}},`; !strings.Contains(body, want) {
		t.Errorf("body lacks %s\n%s", want, body)
	}
	if want := `"vt_leads":` + analyticsLeadsJSON + `}`; !strings.HasSuffix(body, want) {
		t.Errorf("body does not end with %s\n%s", want, body)
	}
	if f.vtCalls != 1 {
		t.Errorf("%d VirusTotal cache reads, want 1", f.vtCalls)
	}

	f.vt = nil
	if _, body := serveGraph(t, s, s.apiAnalytics, "/campaigns/7/analytics/data", "id", "7"); !strings.HasSuffix(body, `"vt_leads":[]}`) {
		t.Errorf("empty cache: %s, want vt_leads []", body)
	}
}

func TestAPIAnalyticsRoutes(t *testing.T) {
	s, _ := analyticsTestServer(t)
	_, session := serveGraph(t, s, s.apiAnalytics, "/campaigns/7/analytics/data?days=90", "id", "7")
	h := withTokens(s)
	if code, body := serveAPI(h, http.MethodGet, "/api/campaigns/7/analytics?days=90", "viewer"); code != http.StatusOK || body != session {
		t.Errorf("bearer route: status %d, body differs from the session route", code)
	}
	if code, body := serveAPI(h, http.MethodGet, "/api/campaigns/8/analytics", "viewer"); code != http.StatusNotFound || body != `{"error":"not found"}` {
		t.Errorf("unknown campaign: status %d: %s", code, body)
	}
	if code, _ := serveAPI(h, http.MethodGet, "/api/campaigns/7/analytics", "nobody"); code != http.StatusUnauthorized {
		t.Errorf("unknown token: status %d, want 401", code)
	}
	if code, body := serveGraph(t, s, s.apiAnalytics, "/campaigns/x/analytics/data", "id", "x"); code != http.StatusNotFound || body != `{"error":"not found"}` {
		t.Errorf("invalid id: status %d: %s", code, body)
	}
}

func TestRenderAnalyticsPage(t *testing.T) {
	body := renderPage(t, "analytics", analyticsView{
		Campaign: pg.Campaign{ID: 7, Name: "spynote", Family: "SpyNote", Description: "Android RAT"},
		Days:     90,
	})
	for _, want := range []string{
		`<link rel="stylesheet" href="/static/analytics.css">`,
		`<script src="/static/analytics.js" defer></script>`,
		`<div class="an" id="analytics" data-source="/campaigns/7/analytics/data" data-campaign="7" data-window="90"`,
		`id="an-kpis"`, `id="an-legend"`, `id="an-timeline"`, `id="an-reset"`, `id="an-matrix"`, `id="an-sort"`,
		`id="an-ips"`, `id="an-ns"`, `id="an-newips"`, `id="an-ev-kind"`, `id="an-ev-body"`, `id="an-leads-body"`,
		`id="an-drawer"`, `id="an-tip"`,
		`<a href="/graph/campaign/7">Graph</a>`, `<a href="/campaigns/7">Campaign</a>`,
		`<span class="an-tag">SpyNote</span>`, "Android RAT",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("analytics page lacks %q", want)
		}
	}
	if n := strings.Count(body, "<script"); n != 2 || strings.Count(body, "<script src=") != 2 {
		t.Errorf("%d script tags, want 2 external ones", n)
	}
	if strings.Contains(body, "style=") || strings.Contains(body, "<style") || regexp.MustCompile(`\son[a-z]+=`).MatchString(body) {
		t.Error("inline style or event handler in the analytics page")
	}
	if strings.Contains(body, "data-analyst") {
		t.Error("analyst controls offered without the analyst role")
	}

	body = renderPage(t, "campaign", map[string]any{"Campaign": pg.Campaign{ID: 7, Name: "spynote"}, "Domains": []pg.Domain{}, "Events": []gjallarhorn.Event{}})
	if !strings.Contains(body, `<a class="title-link" href="/campaigns/7/analytics">Analytics</a>`) {
		t.Error("campaign page lacks the Analytics link")
	}
}
