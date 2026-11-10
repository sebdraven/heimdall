package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sebdraven/heimdall/internal/correlate"
	"github.com/sebdraven/heimdall/internal/store/ch"
	"github.com/sebdraven/heimdall/internal/store/pg"
)

var (
	corrT0  = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	corrRun = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	corrSHA = strings.Repeat("0123456789abcdef", 4)
)

func corrSpan(from, to int) ch.Period {
	return ch.Period{First: corrT0.AddDate(0, 0, from), Last: corrT0.AddDate(0, 0, to)}
}

// fakeCorrStore holds campaigns 7 spynote (a.example), 8 other (b.example)
// and 9 third (c.example), and free.example outside any campaign.
type fakeCorrStore struct {
	mu        sync.Mutex
	campaigns map[int64]pg.Campaign
	domains   []pg.Domain
	owned     []ch.Owned
	certs     []pg.EnrichCert
	history   map[correlate.Key]pg.CorrelationLink
	nextID    int64
	upserts   int
	block     bool
}

func newFakeCorrStore() *fakeCorrStore {
	id := func(n int64) *int64 { return &n }
	return &fakeCorrStore{
		campaigns: map[int64]pg.Campaign{7: {ID: 7, Name: "spynote"}, 8: {ID: 8, Name: "other"}, 9: {ID: 9, Name: "third"}},
		domains: []pg.Domain{
			{FQDN: "a.example", CampaignID: id(7)}, {FQDN: "b.example", CampaignID: id(8)},
			{FQDN: "c.example", CampaignID: id(9)}, {FQDN: "free.example"},
		},
		owned: []ch.Owned{
			{RRName: "a.example", RRType: "A", RData: "192.0.2.1", Period: corrSpan(0, 10)},
			{RRName: "b.example", RRType: "A", RData: "192.0.2.1", Period: corrSpan(5, 20)},
			{RRName: "a.example", RRType: "A", RData: "104.16.0.1", Period: corrSpan(0, 10)},
			{RRName: "b.example", RRType: "A", RData: "104.16.0.1", Period: corrSpan(0, 10)},
			{RRName: "a.example", RRType: "CNAME", RData: "Edge.X.example.", Period: corrSpan(0, 10)},
			{RRName: "c.example", RRType: "CNAME", RData: "edge.x.example.", Period: corrSpan(0, 10)},
			{RRName: "edge.x.example", RRType: "A", RData: "198.51.100.1", Period: corrSpan(0, 10)},
			{RRName: "a.example", RRType: "MX", RData: "10 mx.evil.example.", Period: corrSpan(0, 10)},
			{RRName: "c.example", RRType: "MX", RData: "10 mx.evil.example.", Period: corrSpan(0, 10)},
		},
		certs: []pg.EnrichCert{
			{FQDN: "a.example", SHA256: corrSHA},
			{FQDN: "b.example", SHA256: corrSHA},
		},
		history: map[correlate.Key]pg.CorrelationLink{},
	}
}

func (f *fakeCorrStore) OwnedRecords(ctx context.Context, names, rrtypes []string) ([]ch.Owned, error) {
	f.mu.Lock()
	block := f.block
	f.mu.Unlock()
	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []ch.Owned
	for _, o := range f.owned {
		if slices.Contains(names, o.RRName) && slices.Contains(rrtypes, o.RRType) {
			out = append(out, o)
		}
	}
	return out, nil
}

func (f *fakeCorrStore) ZoneNSSets(context.Context, []string) (map[string]*ch.NSSet, error) {
	return map[string]*ch.NSSet{}, nil
}

func (f *fakeCorrStore) ZoneSOAs(context.Context, []string) (map[string]*ch.SOA, error) {
	return map[string]*ch.SOA{}, nil
}

func (f *fakeCorrStore) VTPairs(context.Context, []string, []string, int) ([]ch.VTPair, error) {
	return nil, nil
}

func (f *fakeCorrStore) Campaign(_ context.Context, id int64) (pg.Campaign, error) {
	c, ok := f.campaigns[id]
	if !ok {
		return pg.Campaign{}, pg.ErrNotFound
	}
	return c, nil
}

func (f *fakeCorrStore) Campaigns(context.Context) ([]pg.Campaign, error) {
	return slices.SortedFunc(maps.Values(f.campaigns), func(a, b pg.Campaign) int { return cmp.Compare(a.Name, b.Name) }), nil
}

func (f *fakeCorrStore) Domains(context.Context, *int64) ([]pg.Domain, error) { return f.domains, nil }

func (f *fakeCorrStore) EnrichCerts(context.Context) ([]pg.EnrichCert, error) { return f.certs, nil }

func (f *fakeCorrStore) EnrichRegistrations(context.Context) ([]pg.EnrichRegistration, error) {
	return nil, nil
}

func (f *fakeCorrStore) UpsertCorrelationLinks(_ context.Context, links []pg.CorrelationLink, at time.Time) ([]pg.CorrelationLink, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.upserts++
	out := make([]pg.CorrelationLink, 0, len(links))
	for _, l := range links {
		k := correlate.Key{Kind: l.Kind, Value: l.Value, DomainA: l.DomainA, DomainB: l.DomainB}
		old, ok := f.history[k]
		if ok {
			l.ID, l.FirstSeen, l.LastSeen = old.ID, old.FirstSeen, old.LastSeen
			if at.After(l.LastSeen) {
				l.LastSeen = at
			}
		} else {
			f.nextID++
			l.ID, l.FirstSeen, l.LastSeen = f.nextID, at, at
		}
		f.history[k] = l
		out = append(out, l)
	}
	return out, nil
}

func (f *fakeCorrStore) CorrelationLinks(_ context.Context, flt pg.CorrelationFilter) ([]pg.CorrelationLink, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []pg.CorrelationLink
	for _, l := range f.history {
		pair := (l.CampaignA == flt.CampaignA && l.CampaignB == flt.CampaignB) || (l.CampaignA == flt.CampaignB && l.CampaignB == flt.CampaignA)
		if l.FirstSeen.Before(flt.Since) || (len(flt.Kinds) > 0 && !slices.Contains(flt.Kinds, l.Kind)) || (flt.CampaignA != 0 && !pair) {
			continue
		}
		out = append(out, l)
	}
	slices.SortFunc(out, func(a, b pg.CorrelationLink) int { return cmp.Or(b.FirstSeen.Compare(a.FirstSeen), cmp.Compare(b.ID, a.ID)) })
	if flt.Limit > 0 && len(out) > flt.Limit {
		out = out[:flt.Limit]
	}
	return out, nil
}

func corrTestServer(t *testing.T) (*server, *fakeCorrStore) {
	t.Helper()
	f := newFakeCorrStore()
	s := testServer(t)
	s.cdn = testCDN()
	s.corr = correlationStores{f, f}
	s.now = func() time.Time { return corrRun }
	return s, f
}

func runAt(t *testing.T, s *server, at time.Time) {
	t.Helper()
	s.now = func() time.Time { return at }
	s.runCorrelation(context.Background(), time.Minute)
}

func serveCorr(h http.HandlerFunc, target string, kv ...string) (int, string) {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	for i := 0; i+1 < len(kv); i += 2 {
		r.SetPathValue(kv[i], kv[i+1])
	}
	rec := httptest.NewRecorder()
	h(rec, r)
	return rec.Code, strings.TrimSpace(rec.Body.String())
}

func evidenceLines(ev []correlate.Evidence) string {
	var out []string
	for _, e := range ev {
		out = append(out, fmt.Sprintf("%s %s %s/%d %s/%d %g %s %s", e.Kind, e.Value, e.DomainA, e.CampaignA, e.DomainB, e.CampaignB, e.Weight,
			e.FirstSeen.Format(time.RFC3339), e.LastSeen.Format(time.RFC3339)))
	}
	return strings.Join(out, "\n")
}

func TestRunCorrelation(t *testing.T) {
	s, f := corrTestServer(t)
	runAt(t, s, corrRun)
	snap := s.corrSnap.Load()
	if snap == nil || !snap.ComputedAt.Equal(corrRun) {
		t.Fatalf("snapshot = %+v", snap)
	}
	at := corrRun.Format(time.RFC3339)
	want := []string{
		"cert " + corrSHA + " a.example/7 b.example/8 1 " + at + " " + at,
		"ip 192.0.2.1 a.example/7 b.example/8 0.4 " + at + " " + at,
		"cname edge.x.example a.example/7 c.example/9 0.7 " + at + " " + at,
		"mx mx.evil.example a.example/7 c.example/9 0.5 " + at + " " + at,
	}
	if got := evidenceLines(snap.Evidence); got != strings.Join(want, "\n") {
		t.Fatalf("links =\n%s\nwant\n%s", got, strings.Join(want, "\n"))
	}

	// An hour later the MX is gone: its link keeps its last sighting, the
	// others keep their first one.
	f.owned = slices.DeleteFunc(f.owned, func(o ch.Owned) bool { return o.RRType == "MX" })
	later := corrRun.Add(time.Hour)
	runAt(t, s, later)
	snap = s.corrSnap.Load()
	if len(snap.Evidence) != 3 || !snap.Evidence[0].FirstSeen.Equal(corrRun) || !snap.Evidence[0].LastSeen.Equal(later) {
		t.Errorf("second run:\n%s", evidenceLines(snap.Evidence))
	}
	mx := f.history[correlate.Key{Kind: correlate.KindMX, Value: "mx.evil.example", DomainA: "a.example", DomainB: "c.example"}]
	if !mx.FirstSeen.Equal(corrRun) || !mx.LastSeen.Equal(corrRun) {
		t.Errorf("gone mx link = %+v, want its last sighting kept", mx)
	}
	if f.upserts != 2 || len(f.history) != 4 {
		t.Errorf("%d upserts, %d links in history", f.upserts, len(f.history))
	}
}

func TestRunCorrelationAbandoned(t *testing.T) {
	s, f := corrTestServer(t)
	runAt(t, s, corrRun)
	before := s.corrSnap.Load()

	var logs bytes.Buffer
	s.log = slog.New(slog.NewTextHandler(&logs, nil))
	f.block = true
	s.now = func() time.Time { return corrRun.Add(time.Hour) }
	s.runCorrelation(context.Background(), 20*time.Millisecond)
	if s.corrSnap.Load() != before {
		t.Error("snapshot replaced by an abandoned run")
	}
	if f.upserts != 1 {
		t.Errorf("%d upserts, want none from the abandoned run", f.upserts)
	}
	if !strings.Contains(logs.String(), "correlation abandoned") || !strings.Contains(logs.String(), "timeout=20ms") {
		t.Errorf("log = %s", logs.String())
	}
}

func decodeCorrelations(t *testing.T, body string) correlationsJSON {
	t.Helper()
	var c correlationsJSON
	if err := json.Unmarshal([]byte(body), &c); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}
	return c
}

func pairLines(c correlationsJSON) string {
	var out []string
	for _, p := range c.Pairs {
		out = append(out, fmt.Sprintf("%d-%d %g %v", p.A, p.B, p.Score, p.Counts))
	}
	return strings.Join(out, " | ")
}

func TestAPICorrelations(t *testing.T) {
	s, _ := corrTestServer(t)
	code, body := serveCorr(s.apiCorrelations, "/api/correlations")
	if code != http.StatusOK || body != `{"campaigns":[{"id":8,"name":"other"},{"id":7,"name":"spynote"},{"id":9,"name":"third"}],"pairs":[],"new_links":[],"computed_at":null}` {
		t.Errorf("before the first run: %d %s", code, body)
	}

	runAt(t, s, corrRun)
	_, body = serveCorr(s.apiCorrelations, "/api/correlations")
	c := decodeCorrelations(t, body)
	if got := pairLines(c); got != "7-8 1 map[cert:1 ip:1] | 7-9 0.85 map[cname:1 mx:1]" {
		t.Errorf("pairs = %s", got)
	}
	if c.ComputedAt == nil || !c.ComputedAt.Equal(corrRun) || len(c.NewLinks) != 4 || c.Pairs[0].FirstSeen == nil || !c.Pairs[0].FirstSeen.Equal(corrRun) {
		t.Errorf("computed_at %v, %d new links, pair %+v", c.ComputedAt, len(c.NewLinks), c.Pairs[0])
	}
	if !strings.Contains(body, `"kind":"cert","value":"`+corrSHA+`"`) {
		t.Errorf("full SHA-256 missing: %s", body)
	}

	_, body = serveCorr(s.apiCorrelations, "/api/correlations?min_score=0.9")
	if got := pairLines(decodeCorrelations(t, body)); got != "7-8 1 map[cert:1 ip:1]" {
		t.Errorf("min_score 0.9: %s", got)
	}
	_, body = serveCorr(s.apiCorrelations, "/api/correlations?kinds=mx,ip")
	c = decodeCorrelations(t, body)
	if got := pairLines(c); got != "7-9 0.5 map[mx:1] | 7-8 0.4 map[ip:1]" || len(c.NewLinks) != 2 {
		t.Errorf("kinds mx,ip: %s, %d new links", got, len(c.NewLinks))
	}
	s.now = func() time.Time { return corrRun.AddDate(0, 0, 8) }
	if _, body = serveCorr(s.apiCorrelations, "/api/correlations"); len(decodeCorrelations(t, body).NewLinks) != 0 {
		t.Errorf("new links older than 7 days: %s", body)
	}
	if _, body = serveCorr(s.apiCorrelations, "/api/correlations?since=2026-11-01"); len(decodeCorrelations(t, body).NewLinks) != 4 {
		t.Errorf("since 2026-11-01: %s", body)
	}

	for _, q := range []string{"min_score=2", "min_score=-0.1", "min_score=NaN", "kinds=cert,dns", "since=yesterday"} {
		if code, _ := serveCorr(s.apiCorrelations, "/api/correlations?"+q); code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", q, code)
		}
	}
}

func TestAPICorrelationPair(t *testing.T) {
	s, f := corrTestServer(t)
	runAt(t, s, corrRun)
	f.owned = slices.DeleteFunc(f.owned, func(o ch.Owned) bool { return o.RRType == "MX" })
	runAt(t, s, corrRun.Add(time.Hour))

	code, body := serveCorr(s.apiCorrelationPair, "/api/correlations/8/7", "a", "8", "b", "7")
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	for _, want := range []string{
		`{"a":{"id":8,"name":"other"},"b":{"id":7,"name":"spynote"},"score":1,"counts":{"cert":1,"ip":1},"evidence":[`,
		`{"kind":"cert","value":"` + corrSHA + `","domain_a":"a.example","campaign_a":7,"domain_b":"b.example","campaign_b":8,"weight":1,"period":null,`,
		`{"kind":"ip","value":"192.0.2.1","domain_a":"a.example","campaign_a":7,"domain_b":"b.example","campaign_b":8,"weight":0.4,` +
			`"period":{"first":"2026-11-06T00:00:00Z","last":"2026-11-11T00:00:00Z"},"first_seen":"2026-11-10T12:00:00Z","last_seen":"2026-11-10T13:00:00Z"}],"past":[]`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("pair lacks %s\n%s", want, body)
		}
	}

	_, body = serveCorr(s.apiCorrelationPair, "/api/correlations/7/9", "a", "7", "b", "9")
	if !strings.Contains(body, `"score":0.7,"counts":{"cname":1},`) ||
		!strings.Contains(body, `"past":[{"kind":"mx","value":"mx.evil.example","domain_a":"a.example","campaign_a":7,"domain_b":"c.example","campaign_b":9,"first_seen":"2026-11-10T12:00:00Z","last_seen":"2026-11-10T12:00:00Z"}]`) {
		t.Errorf("pair 7/9 = %s", body)
	}

	for _, tt := range []struct{ a, b string }{{"7", "7"}, {"7", "x"}, {"0", "7"}} {
		if code, _ := serveCorr(s.apiCorrelationPair, "/", "a", tt.a, "b", tt.b); code != http.StatusNotFound {
			t.Errorf("%s/%s: status %d, want 404", tt.a, tt.b, code)
		}
	}
	if code, body := serveCorr(s.apiCorrelationPair, "/", "a", "7", "b", "99"); code != http.StatusNotFound || body != `{"error":"not found"}` {
		t.Errorf("unknown campaign: %d %s", code, body)
	}
}

func TestAPICorrelationGraph(t *testing.T) {
	s, _ := corrTestServer(t)
	if _, body := serveCorr(s.apiCorrelationGraph, "/api/correlations/graph"); body != `{"nodes":[],"edges":[],"truncated":false,"excluded_cdn":0}` {
		t.Errorf("before the first run: %s", body)
	}
	runAt(t, s, corrRun)
	_, body := serveCorr(s.apiCorrelationGraph, "/api/correlations/graph")
	want := `{"nodes":[` +
		`{"id":"c:8","kind":"campaign","label":"other","watched":false,"campaign":"","href":"/campaigns/8/analytics","source":"heimdall"},` +
		`{"id":"c:7","kind":"campaign","label":"spynote","watched":false,"campaign":"","href":"/campaigns/7/analytics","source":"heimdall"},` +
		`{"id":"c:9","kind":"campaign","label":"third","watched":false,"campaign":"","href":"/campaigns/9/analytics","source":"heimdall"}],` +
		`"edges":[{"from":"c:7","to":"c:8","kind":"cert"},{"from":"c:7","to":"c:8","kind":"ip"},` +
		`{"from":"c:7","to":"c:9","kind":"cname"},{"from":"c:7","to":"c:9","kind":"mx"}],"truncated":false,"excluded_cdn":0}`
	if body != want {
		t.Errorf("graph =\n%s\nwant\n%s", body, want)
	}

	_, body = serveCorr(s.apiCorrelationGraph, "/api/correlations/graph?expand=8,7&kinds=cert")
	var g graphJSON
	if err := json.Unmarshal([]byte(body), &g); err != nil {
		t.Fatal(err)
	}
	var nodes, edges []string
	for _, n := range g.Nodes {
		nodes = append(nodes, n.ID+"/"+n.Kind+"/"+n.Label+"/"+n.Campaign)
	}
	for _, e := range g.Edges {
		edges = append(edges, e.From+">"+e.To+":"+e.Kind)
	}
	if got := strings.Join(nodes, " "); got != "c:8/campaign/other/ c:7/campaign/spynote/ d:a.example/domain/a.example/spynote d:b.example/domain/b.example/other cert:"+corrSHA+"/cert/"+corrSHA+"/" {
		t.Errorf("expanded nodes = %s", got)
	}
	if got := strings.Join(edges, " "); got != "c:7>c:8:cert c:7>d:a.example:member c:8>d:b.example:member d:a.example>cert:"+corrSHA+":cert d:b.example>cert:"+corrSHA+":cert" {
		t.Errorf("expanded edges = %s", got)
	}

	for _, q := range []string{"expand=7", "expand=7,7", "expand=x,8", "min_score=3"} {
		if code, _ := serveCorr(s.apiCorrelationGraph, "/api/correlations/graph?"+q); code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", q, code)
		}
	}
	if code, _ := serveCorr(s.apiCorrelationGraph, "/api/correlations/graph?expand=7,99"); code != http.StatusNotFound {
		t.Errorf("unknown campaign: status %d, want 404", code)
	}
}

func TestCorrelationRoutes(t *testing.T) {
	s, _ := corrTestServer(t)
	runAt(t, s, corrRun)
	h := withTokens(s)
	for _, target := range []string{"/api/correlations", "/api/correlations/7/8", "/api/correlations/graph?expand=7,8"} {
		code, body := serveAPI(h, http.MethodGet, target, "viewer")
		if code != http.StatusOK || !strings.HasPrefix(body, "{") {
			t.Errorf("viewer %s: %d %s", target, code, body)
		}
		if code, _ := serveAPI(h, http.MethodGet, target, "nobody"); code != http.StatusUnauthorized {
			t.Errorf("unknown token %s: status %d, want 401", target, code)
		}
	}
	_, api := serveAPI(h, http.MethodGet, "/api/correlations?min_score=0.5", "viewer")
	if code, body := serveSession(h, http.MethodGet, "/correlations/data?min_score=0.5", "viewer"); code != http.StatusOK || body != api {
		t.Errorf("session route: status %d, body differs from the bearer route", code)
	}
	_, api = serveAPI(h, http.MethodGet, "/api/correlations/7/8", "viewer")
	if code, body := serveSession(h, http.MethodGet, "/correlations/7/8/data", "viewer"); code != http.StatusOK || body != api {
		t.Errorf("pair session route: status %d", code)
	}
	_, api = serveAPI(h, http.MethodGet, "/api/correlations/graph", "viewer")
	if code, body := serveSession(h, http.MethodGet, "/correlations/graph/data", "viewer"); code != http.StatusOK || body != api {
		t.Errorf("graph session route: status %d", code)
	}
	if code, body := serveSession(h, http.MethodGet, "/correlations", "viewer"); code != http.StatusOK || !strings.Contains(body, `id="correlations"`) {
		t.Errorf("page: status %d", code)
	}
	if code, _ := serveSession(h, http.MethodGet, "/correlations/data", "nobody"); code == http.StatusOK {
		t.Error("data served without a session")
	}
}

func TestRenderCorrelationsPage(t *testing.T) {
	body := renderPage(t, "correlations", correlationsView{Kinds: correlationKinds(), MaxNodes: graphMaxNodes})
	for _, want := range []string{
		`<link rel="stylesheet" href="/static/correlations.css">`,
		`<script src="/static/correlations.js" defer></script>`,
		`<script src="/static/vendor/pivotick/pivotick.iife.js" defer></script>`,
		`data-source="/correlations/data" data-graph="/correlations/graph/data" data-pair="/correlations/"`,
		`id="cx-matrix"`, `id="cx-graph"`, `id="cx-pair"`, `id="cx-new"`, "New links (7 days)",
		`value="cert" checked`, `cx-line-ns_set`, `<span class="meta">0.8/n</span>`, `<span class="meta">1.0</span>`,
		"truncated at 500 nodes",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("correlations page lacks %q", want)
		}
	}
	if strings.Contains(body, "style=") || strings.Contains(body, "<style") || regexp.MustCompile(`\son[a-z]+=`).MatchString(body) {
		t.Error("inline style or event handler in the correlations page")
	}
	s := testServer(t)
	if body := renderAs(t, s, "viewer", "correlations", correlationsView{Kinds: correlationKinds()}); !strings.Contains(body, `<a href="/correlations">Correlations</a>`) {
		t.Error("navigation lacks Correlations")
	}
}

func TestLinkedCampaigns(t *testing.T) {
	s, _ := corrTestServer(t)
	ctx := context.Background()
	if linked, done, err := s.linkedCampaigns(ctx, 7); err != nil || done || linked != nil {
		t.Errorf("before the first run: %v %v %v", linked, done, err)
	}
	body := renderPage(t, "analytics", analyticsView{Campaign: pg.Campaign{ID: 7, Name: "spynote"}, Days: 30})
	if !strings.Contains(body, "Links not computed yet.") {
		t.Error("analytics card lacks the pending notice")
	}

	runAt(t, s, corrRun)
	linked, done, err := s.linkedCampaigns(ctx, 7)
	if err != nil || !done {
		t.Fatal(err)
	}
	if got := fmt.Sprint(linked); got != "[{8 other 1 cert 1, ip 1} {9 third 0.85 cname 1, mx 1}]" {
		t.Errorf("linked = %s", got)
	}
	if linked, _, _ := s.linkedCampaigns(ctx, 8); len(linked) != 1 || linked[0].ID != 7 {
		t.Errorf("linked to 8 = %v", linked)
	}
	body = renderPage(t, "analytics", analyticsView{Campaign: pg.Campaign{ID: 7, Name: "spynote"}, Days: 30, Linked: linked, Correlated: true})
	for _, want := range []string{
		`<h2 id="an-linked-title">Linked campaigns</h2>`,
		`<a href="/correlations?a=7&amp;b=8">other</a>`,
		`<span class="an-count">0.85</span>`,
		`<span class="an-dim an-mono">cname 1, mx 1</span>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("analytics card lacks %q", want)
		}
	}
	if linked, _, _ := s.linkedCampaigns(ctx, 42); linked != nil {
		t.Errorf("unlinked campaign: %v", linked)
	}
	if body := renderPage(t, "analytics", analyticsView{Campaign: pg.Campaign{ID: 42}, Correlated: true}); !strings.Contains(body, "No link to another campaign.") {
		t.Error("analytics card lacks the no-link notice")
	}
}
