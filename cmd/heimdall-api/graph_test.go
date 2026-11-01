package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/sebdraven/heimdall/internal/store/ch"
	"github.com/sebdraven/heimdall/internal/store/pg"
)

const testNSSet = "ns:ns1.p.example,ns2.p.example"

func pairNS(zone string) *ch.NSSet {
	return &ch.NSSet{Zone: zone, NS: []string{"ns2.p.example", "ns1.p.example"}}
}

func pivotA(v string) ch.PivotValue { return ch.PivotValue{RRType: "A", RData: v} }

func graphSummary(g graphJSON) (nodes, edges string) {
	var ns, es []string
	for _, n := range g.Nodes {
		ns = append(ns, n.ID)
	}
	for _, e := range g.Edges {
		es = append(es, e.From+">"+e.To+"/"+e.Kind)
	}
	return strings.Join(ns, " "), strings.Join(es, " ")
}

func TestBuildGraphDomain(t *testing.T) {
	g := buildGraph(graphInput{
		Domains: []graphDomain{{
			FQDN:   "www.x.example",
			Values: []ch.PivotValue{pivotA("192.0.2.1"), pivotA("192.0.2.1"), {RRType: "AAAA", RData: "2001:db8::1"}, pivotA("104.16.0.1"), pivotA("104.16.0.2")},
			CNAMEs: []string{"cdn.y.example", "cdn.y.example"},
			NS:     pairNS("x.example"),
		}},
		IPPeers: []ch.Pivot{
			{Domain: "b.example", RRType: "A", RData: "192.0.2.1"},
			{Domain: "b.example", RRType: "A", RData: "192.0.2.1"},
			{Domain: "c.example", RRType: "A", RData: "104.16.0.1"},
		},
		NSPeers:   map[string][]ch.NSPairPivot{testNSSet: {{Domain: "z.example"}}},
		MinShared: 1,
	}, testCDN(), graphMaxNodes)

	nodes, edges := graphSummary(g)
	if want := "d:www.x.example ip:192.0.2.1 ip:2001:db8::1 d:cdn.y.example " + testNSSet + " d:b.example d:z.example"; nodes != want {
		t.Errorf("nodes = %s\nwant    %s", nodes, want)
	}
	if want := "d:www.x.example>ip:192.0.2.1/A d:www.x.example>ip:2001:db8::1/AAAA d:www.x.example>d:cdn.y.example/CNAME " +
		"d:www.x.example>" + testNSSet + "/NS_SET d:b.example>ip:192.0.2.1/A d:z.example>" + testNSSet + "/NS_SET"; edges != want {
		t.Errorf("edges = %s\nwant    %s", edges, want)
	}
	if g.ExcludedCDN != 2 || g.Truncated {
		t.Errorf("excluded_cdn %d truncated %v, want 2 and false", g.ExcludedCDN, g.Truncated)
	}
	if got, want := encode(t, g.Nodes[4]), `{"id":"`+testNSSet+`","kind":"nsset","label":"ns1.p.example, ns2.p.example","watched":false,"campaign":"","href":"/domains/x.example"}`; got != want {
		t.Errorf("nsset node = %s, want %s", got, want)
	}
	if got, want := encode(t, g.Nodes[2]), `{"id":"ip:2001:db8::1","kind":"ip","label":"2001:db8::1","watched":false,"campaign":"","href":"/rdata/2001:db8::1"}`; got != want {
		t.Errorf("ip node = %s, want %s", got, want)
	}
}

func TestBuildGraphSmallNSSet(t *testing.T) {
	g := buildGraph(graphInput{
		Domains: []graphDomain{
			{FQDN: "a.example", NS: &ch.NSSet{Zone: "a.example", NS: []string{"ns1.p.example"}}},
			{FQDN: "b.example"},
		},
		NSPeers:   map[string][]ch.NSPairPivot{"ns:ns1.p.example": {{Domain: "z.example"}}},
		MinShared: 1,
	}, testCDN(), graphMaxNodes)
	if nodes, edges := graphSummary(g); nodes != "d:a.example d:b.example" || edges != "" {
		t.Errorf("nodes %q edges %q, want the two domains alone", nodes, edges)
	}
}

func TestBuildGraphTruncated(t *testing.T) {
	in := graphInput{Domains: []graphDomain{{FQDN: "a.example", Values: []ch.PivotValue{pivotA("192.0.2.1"), pivotA("192.0.2.2"), pivotA("192.0.2.3"), pivotA("192.0.2.4")}}}}
	g := buildGraph(in, testCDN(), 3)
	nodes, edges := graphSummary(g)
	if nodes != "d:a.example ip:192.0.2.1 ip:192.0.2.2" || edges != "d:a.example>ip:192.0.2.1/A d:a.example>ip:192.0.2.2/A" || !g.Truncated {
		t.Errorf("nodes %q edges %q truncated %v", nodes, edges, g.Truncated)
	}
	if g := buildGraph(in, testCDN(), 5); g.Truncated || len(g.Nodes) != 5 {
		t.Errorf("graph of exactly the limit: %d nodes, truncated %v", len(g.Nodes), g.Truncated)
	}
	if g := buildGraph(graphInput{Domains: []graphDomain{{FQDN: "a.example"}}, Partial: true}, testCDN(), graphMaxNodes); !g.Truncated {
		t.Error("partial store result not flagged as truncated")
	}
}

func TestBuildGraphCampaign(t *testing.T) {
	g := buildGraph(graphInput{
		Domains: []graphDomain{
			{FQDN: "a.example", Values: []ch.PivotValue{pivotA("192.0.2.1"), pivotA("192.0.2.2")}, NS: pairNS("a.example")},
			{FQDN: "b.example", Values: []ch.PivotValue{pivotA("192.0.2.1"), pivotA("192.0.2.3")}},
			{FQDN: "c.example", Values: []ch.PivotValue{pivotA("192.0.2.4")}, NS: pairNS("c.example")},
		},
		IPPeers: []ch.Pivot{
			{Domain: "b.example", RRType: "A", RData: "192.0.2.1"},
			{Domain: "out1.example", RRType: "A", RData: "192.0.2.1"},
			{Domain: "out2.example", RRType: "A", RData: "192.0.2.2"},
			{Domain: "out3.example", RRType: "A", RData: "192.0.2.3"},
			{Domain: "out3.example", RRType: "A", RData: "192.0.2.4"},
			{Domain: "out5.example", RRType: "A", RData: "192.0.2.3"},
		},
		NSPeers:   map[string][]ch.NSPairPivot{testNSSet: {{Domain: "c.example"}, {Domain: "out4.example"}}},
		MinShared: 2,
	}, testCDN(), graphMaxNodes)

	nodes, edges := graphSummary(g)
	if want := "d:a.example d:b.example d:c.example ip:192.0.2.1 ip:192.0.2.2 " + testNSSet + " ip:192.0.2.3 ip:192.0.2.4 " +
		"d:out1.example d:out3.example d:out4.example"; nodes != want {
		t.Errorf("nodes = %s\nwant    %s", nodes, want)
	}
	if want := "d:a.example>ip:192.0.2.1/A d:a.example>ip:192.0.2.2/A d:a.example>" + testNSSet + "/NS_SET " +
		"d:b.example>ip:192.0.2.1/A d:b.example>ip:192.0.2.3/A d:c.example>ip:192.0.2.4/A d:c.example>" + testNSSet + "/NS_SET " +
		"d:out1.example>ip:192.0.2.1/A d:out3.example>ip:192.0.2.3/A d:out3.example>ip:192.0.2.4/A d:out4.example>" + testNSSet + "/NS_SET"; edges != want {
		t.Errorf("edges = %s\nwant    %s", edges, want)
	}
}

func TestCNAMETargets(t *testing.T) {
	got := cnameTargets([]ch.Current{
		{QType: "CNAME", Resolver: "9.9.9.9:53", Rdata: []string{"CDN.Y.example."}},
		{QType: "CNAME", Resolver: "1.1.1.1:53", Rdata: []string{"cdn.y.example"}},
		{QType: "A", Rdata: []string{"192.0.2.1"}},
	})
	if strings.Join(got, " ") != "cdn.y.example" {
		t.Errorf("targets = %v, want [cdn.y.example]", got)
	}
}

type fakeGraphStore struct {
	values  map[string][]ch.PivotValue
	current map[string][]ch.Current
	ns      map[string]*ch.NSSet
	pivots  map[string][]ch.Pivot
	pairs   map[string][]ch.NSPairPivot
	watched map[string]pg.Domain
	lookups int
}

func (f *fakeGraphStore) PivotValues(_ context.Context, fqdn string) ([]ch.PivotValue, error) {
	return f.values[fqdn], nil
}

func (f *fakeGraphStore) CurrentState(_ context.Context, domain string) ([]ch.Current, error) {
	return f.current[domain], nil
}

func (f *fakeGraphStore) NSSet(_ context.Context, fqdn string) (*ch.NSSet, error) {
	return f.ns[fqdn], nil
}

func (f *fakeGraphStore) Pivots(_ context.Context, fqdn string, values []ch.PivotValue, _ int) ([]ch.Pivot, error) {
	var out []ch.Pivot
	for _, p := range f.pivots[fqdn] {
		if slices.ContainsFunc(values, func(v ch.PivotValue) bool { return v.RData == p.RData }) {
			out = append(out, p)
		}
	}
	return out, nil
}

func (f *fakeGraphStore) NSPairPivots(_ context.Context, zone string, _ []string, _ int) ([]ch.NSPairPivot, error) {
	return f.pairs[zone], nil
}

func (f *fakeGraphStore) Campaign(_ context.Context, id int64) (pg.Campaign, error) {
	if id != 7 {
		return pg.Campaign{}, pg.ErrNotFound
	}
	return pg.Campaign{ID: 7, Name: "spynote"}, nil
}

func (f *fakeGraphStore) Domains(_ context.Context, _ *int64) ([]pg.Domain, error) {
	return []pg.Domain{f.watched["www.x.example"]}, nil
}

func (f *fakeGraphStore) DomainsByFQDN(_ context.Context, fqdns []string) (map[string]pg.Domain, error) {
	f.lookups++
	out := map[string]pg.Domain{}
	for _, fqdn := range fqdns {
		if d, ok := f.watched[fqdn]; ok {
			out[fqdn] = d
		}
	}
	return out, nil
}

func graphTestServer(t *testing.T) (*server, *fakeGraphStore) {
	t.Helper()
	f := &fakeGraphStore{
		values:  map[string][]ch.PivotValue{"www.x.example": {pivotA("192.0.2.1"), pivotA("104.16.0.1")}},
		current: map[string][]ch.Current{"www.x.example": {{QType: "CNAME", Rdata: []string{"CDN.Y.example."}}}},
		ns:      map[string]*ch.NSSet{"www.x.example": pairNS("x.example")},
		pivots: map[string][]ch.Pivot{"www.x.example": {
			{Domain: "b.example", RRType: "A", RData: "192.0.2.1"},
			{Domain: "cdn-peer.example", RRType: "A", RData: "104.16.0.1"},
		}},
		pairs: map[string][]ch.NSPairPivot{"x.example": {{Domain: "z.example"}}},
		watched: map[string]pg.Domain{
			"www.x.example": {FQDN: "www.x.example", Campaign: "spynote"},
			"b.example":     {FQDN: "b.example"},
		},
	}
	s := testServer(t)
	s.cdn = testCDN()
	s.graph = graphStores{f, f}
	return s, f
}

func serveGraph(t *testing.T, s *server, h http.HandlerFunc, target, name, value string) (int, string) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.SetPathValue(name, value)
	rec := httptest.NewRecorder()
	h(rec, r)
	return rec.Code, strings.TrimSpace(rec.Body.String())
}

func TestAPIGraphDomain(t *testing.T) {
	s, f := graphTestServer(t)
	code, body := serveGraph(t, s, s.apiGraphDomain, "/api/graph/domain/www.x.example", "fqdn", "WWW.X.example.")
	want := `{"nodes":[` +
		`{"id":"d:www.x.example","kind":"domain","label":"www.x.example","watched":true,"campaign":"spynote","href":"/domains/www.x.example"},` +
		`{"id":"ip:192.0.2.1","kind":"ip","label":"192.0.2.1","watched":false,"campaign":"","href":"/rdata/192.0.2.1"},` +
		`{"id":"d:cdn.y.example","kind":"domain","label":"cdn.y.example","watched":false,"campaign":"","href":"/domains/cdn.y.example"},` +
		`{"id":"` + testNSSet + `","kind":"nsset","label":"ns1.p.example, ns2.p.example","watched":false,"campaign":"","href":"/domains/x.example"}],` +
		`"edges":[{"from":"d:www.x.example","to":"ip:192.0.2.1","kind":"A"},` +
		`{"from":"d:www.x.example","to":"d:cdn.y.example","kind":"CNAME"},` +
		`{"from":"d:www.x.example","to":"` + testNSSet + `","kind":"NS_SET"}],` +
		`"truncated":false,"excluded_cdn":1}`
	if code != http.StatusOK || body != want {
		t.Errorf("depth 1: status %d\n%s\nwant\n%s", code, body, want)
	}
	if f.lookups != 1 {
		t.Errorf("%d watchlist lookups, want 1", f.lookups)
	}

	_, depth2 := serveGraph(t, s, s.apiGraphDomain, "/api/graph/domain/www.x.example?depth=2", "fqdn", "www.x.example")
	for _, want := range []string{
		`{"id":"d:b.example","kind":"domain","label":"b.example","watched":true,"campaign":"","href":"/domains/b.example"}`,
		`{"from":"d:b.example","to":"ip:192.0.2.1","kind":"A"}`,
		`{"from":"d:z.example","to":"` + testNSSet + `","kind":"NS_SET"}`,
	} {
		if !strings.Contains(depth2, want) {
			t.Errorf("depth 2 lacks %s", want)
		}
	}
	if strings.Contains(depth2, "cdn-peer.example") {
		t.Error("depth 2 pivots on a CDN address")
	}
	if _, body := serveGraph(t, s, s.apiGraphDomain, "/api/graph/domain/www.x.example?depth=5", "fqdn", "www.x.example"); body != depth2 {
		t.Errorf("depth 5 =\n%s\nwant depth 2\n%s", body, depth2)
	}
}

func TestAPIGraphCampaign(t *testing.T) {
	s, _ := graphTestServer(t)
	code, body := serveGraph(t, s, s.apiGraphCampaign, "/api/graph/campaign/7", "id", "7")
	if code != http.StatusOK || !strings.HasPrefix(body, `{"nodes":[{"id":"d:www.x.example","kind":"domain","label":"www.x.example","watched":true,"campaign":"spynote"`) {
		t.Errorf("campaign graph: status %d: %s", code, body)
	}
	if strings.Contains(body, "d:b.example") || strings.Contains(body, "d:z.example") {
		t.Error("campaign graph keeps a name shared with a single campaign domain")
	}
	if code, body := serveGraph(t, s, s.apiGraphCampaign, "/api/graph/campaign/8", "id", "8"); code != http.StatusNotFound || body != `{"error":"not found"}` {
		t.Errorf("unknown campaign: status %d: %s", code, body)
	}
}

func TestRenderGraphPage(t *testing.T) {
	body := renderPage(t, "graph", graphView{
		Title: "www.x.example", Back: "/domains/www.x.example",
		Source: "/graph/domain/www.x.example/data?depth=2", Path: "/graph/domain/www.x.example", Depth: 2, MaxNodes: graphMaxNodes,
	})
	for _, want := range []string{
		`<link rel="stylesheet" href="/static/vendor/pivotick/pivotick.css">`,
		`<script src="/static/vendor/pivotick/pivotick.iife.js" defer></script>`,
		`<script src="/static/graph.js" defer></script>`,
		`<script src="/static/htmx.min.js" defer></script>`,
		`data-source="/graph/domain/www.x.example/data?depth=2"`,
		`<a href="/graph/domain/www.x.example?depth=1">1</a> · 2`,
		"domain watched", "domain unwatched", "CDN addresses left out", "truncated at 500 nodes",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("graph page lacks %q", want)
		}
	}
	if n := strings.Count(body, "<script"); n != 3 || strings.Count(body, "<script src=") != 3 {
		t.Errorf("%d script tags, want 3 external ones", n)
	}

	body = renderPage(t, "graph", graphView{Title: "spynote", Back: "/campaigns/7", Source: "/graph/campaign/7/data", MaxNodes: graphMaxNodes})
	if strings.Contains(body, "Depth") {
		t.Error("campaign graph offers depths")
	}

	body = renderPage(t, "domain", map[string]any{"FQDN": "www.x.example", "Domain": (*pg.Domain)(nil), "Sharing": map[string]uint64{}})
	if !strings.Contains(body, `<a class="title-link" href="/graph/domain/www.x.example">Graph</a>`) {
		t.Error("domain page lacks the Graph link")
	}
}
