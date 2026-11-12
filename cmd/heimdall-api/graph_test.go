package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sebdraven/heimdall/internal/enrich"
	"github.com/sebdraven/heimdall/internal/store/ch"
	"github.com/sebdraven/heimdall/internal/store/pg"
	"github.com/sebdraven/heimdall/internal/vt"
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
	if got, want := encode(t, g.Nodes[4]), `{"id":"`+testNSSet+`","kind":"nsset","label":"ns1.p.example, ns2.p.example","watched":false,"campaign":"","href":"/domains/x.example","source":"heimdall"}`; got != want {
		t.Errorf("nsset node = %s, want %s", got, want)
	}
	if got, want := encode(t, g.Nodes[2]), `{"id":"ip:2001:db8::1","kind":"ip","label":"2001:db8::1","watched":false,"campaign":"","href":"/rdata/2001:db8::1","source":"heimdall"}`; got != want {
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

func vtPair(host, ip string) ch.VTPair {
	return ch.VTPair{HostName: host, IP: ip, Period: ch.Period{
		First: time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC), Last: time.Date(2024, 3, 4, 0, 0, 0, 0, time.UTC),
	}}
}

func TestBuildGraphVT(t *testing.T) {
	g := buildGraph(graphInput{
		Domains: []graphDomain{
			{FQDN: "a.example", Values: []ch.PivotValue{pivotA("192.0.2.1")}},
		},
		VT: []ch.VTPair{
			vtPair("a.example", "192.0.2.1"),
			vtPair("a.example", "192.0.2.1"),
			vtPair("a.example", "198.51.100.7"),
			vtPair("other.example", "192.0.2.1"),
			vtPair("a.example", "104.16.0.9"),
			vtPair("far.example", "203.0.113.5"),
		},
		MinShared: 1,
	}, testCDN(), graphMaxNodes)

	nodes, edges := graphSummary(g)
	if want := "d:a.example ip:192.0.2.1 ip:198.51.100.7 d:other.example"; nodes != want {
		t.Errorf("nodes = %s\nwant    %s", nodes, want)
	}
	if want := "d:a.example>ip:192.0.2.1/A d:a.example>ip:192.0.2.1/VT d:a.example>ip:198.51.100.7/VT d:other.example>ip:192.0.2.1/VT"; edges != want {
		t.Errorf("edges = %s\nwant    %s", edges, want)
	}
	var sources []string
	for _, n := range g.Nodes {
		sources = append(sources, n.Source)
	}
	if got := strings.Join(sources, " "); got != "heimdall heimdall vt vt" {
		t.Errorf("sources = %s", got)
	}
	if g.ExcludedCDN != 1 || g.Truncated {
		t.Errorf("excluded_cdn %d truncated %v, want 1 and false", g.ExcludedCDN, g.Truncated)
	}
	if got, want := encode(t, g.Edges[1]), `{"from":"d:a.example","to":"ip:192.0.2.1","kind":"VT","first_seen":"2024-01-02T00:00:00Z","last_seen":"2024-03-04T00:00:00Z"}`; got != want {
		t.Errorf("vt edge = %s, want %s", got, want)
	}
	if got, want := encode(t, g.Edges[0]), `{"from":"d:a.example","to":"ip:192.0.2.1","kind":"A"}`; got != want {
		t.Errorf("A edge = %s, want %s", got, want)
	}
}

func TestBuildGraphVTLimit(t *testing.T) {
	g := buildGraph(graphInput{
		Domains:   []graphDomain{{FQDN: "a.example", Values: []ch.PivotValue{pivotA("192.0.2.1")}}},
		IPPeers:   []ch.Pivot{{Domain: "b.example", RRType: "A", RData: "192.0.2.1"}},
		VT:        []ch.VTPair{vtPair("a.example", "198.51.100.7"), vtPair("b.example", "192.0.2.1")},
		MinShared: 1,
	}, testCDN(), 3)
	nodes, edges := graphSummary(g)
	if nodes != "d:a.example ip:192.0.2.1 d:b.example" || !g.Truncated {
		t.Errorf("nodes %q truncated %v, want the Heimdall nodes only", nodes, g.Truncated)
	}
	if want := "d:a.example>ip:192.0.2.1/A d:b.example>ip:192.0.2.1/A d:b.example>ip:192.0.2.1/VT"; edges != want {
		t.Errorf("edges = %s\nwant    %s", edges, want)
	}
}

func TestBuildGraphIP(t *testing.T) {
	in := graphInput{Addr: "9.9.9.9", VT: []ch.VTPair{vtPair("b.example", "9.9.9.9"), vtPair("v.example", "9.9.9.9")}}
	in.IPPeers = []ch.Pivot{
		{Domain: "b.example", RRType: "A", RData: "9.9.9.9"},
		{Domain: "a.example", RRType: "A", RData: "9.9.9.9"},
		{Domain: "a.example", RRType: "A", RData: "9.9.9.9"},
		{Domain: "other.example", RRType: "A", RData: "192.0.2.1"},
	}
	g := buildGraph(in, testCDN(), graphMaxNodes)
	nodes, edges := graphSummary(g)
	if want := "ip:9.9.9.9 d:a.example d:b.example d:v.example"; nodes != want {
		t.Errorf("nodes = %s\nwant    %s", nodes, want)
	}
	if want := "d:a.example>ip:9.9.9.9/A d:b.example>ip:9.9.9.9/A d:b.example>ip:9.9.9.9/VT d:v.example>ip:9.9.9.9/VT"; edges != want {
		t.Errorf("edges = %s\nwant    %s", edges, want)
	}
	var sources []string
	for _, n := range g.Nodes {
		sources = append(sources, n.Source)
	}
	if got := strings.Join(sources, " "); got != "heimdall heimdall heimdall vt" {
		t.Errorf("sources = %s", got)
	}
	if g.ExcludedCDN != 0 || g.Truncated {
		t.Errorf("excluded_cdn %d truncated %v, want 0 and false", g.ExcludedCDN, g.Truncated)
	}

	capped := buildGraph(graphInput{Addr: "9.9.9.9", IPPeers: []ch.Pivot{
		{Domain: "c.example", RRType: "A", RData: "9.9.9.9"},
		{Domain: "b.example", RRType: "A", RData: "9.9.9.9"},
		{Domain: "a.example", RRType: "A", RData: "9.9.9.9"},
	}}, testCDN(), 3)
	if nodes, _ := graphSummary(capped); nodes != "ip:9.9.9.9 d:a.example d:b.example" || !capped.Truncated {
		t.Errorf("capped graph: nodes %q truncated %v, want the address first", nodes, capped.Truncated)
	}

	cdnIn := graphInput{Addr: "104.16.0.1", VT: []ch.VTPair{vtPair("v.example", "104.16.0.1")}}
	cdnIn.IPPeers = []ch.Pivot{{Domain: "a.example", RRType: "A", RData: "104.16.0.1"}}
	g = buildGraph(cdnIn, testCDN(), graphMaxNodes)
	if got, want := encode(t, g), `{"nodes":[],"edges":[],"truncated":false,"excluded_cdn":1}`; got != want {
		t.Errorf("CDN address = %s, want %s", got, want)
	}
}

type fakeGraphStore struct {
	values  map[string][]ch.PivotValue
	current map[string][]ch.Current
	ns      map[string]*ch.NSSet
	pivots  map[string][]ch.Pivot
	pairs   map[string][]ch.NSPairPivot
	vt      []ch.VTPair
	vtHosts []string
	vtIPs   []string
	vtCalls int
	watched map[string]pg.Domain
	lookups int
	pdns    []ch.PDNSRecord
	// enriched are the stored enrichments, asked the names read by each call.
	enriched map[string]enrich.Result
	asked    [][]string
}

func (f *fakeGraphStore) DomainEnrichments(_ context.Context, fqdns []string) (map[string]enrich.Result, error) {
	f.asked = append(f.asked, fqdns)
	out := map[string]enrich.Result{}
	for _, fqdn := range fqdns {
		if r, ok := f.enriched[fqdn]; ok {
			out[fqdn] = r
		}
	}
	return out, nil
}

func (f *fakeGraphStore) VTPairs(_ context.Context, hosts, ips []string, _ int) ([]ch.VTPair, error) {
	f.vtCalls++
	f.vtHosts, f.vtIPs = hosts, ips
	return f.vt, nil
}

func (f *fakeGraphStore) VTPairsByIP(_ context.Context, ip string, _ int) ([]ch.VTPair, error) {
	var out []ch.VTPair
	for _, p := range f.vt {
		if p.IP == ip {
			out = append(out, p)
		}
	}
	return out, nil
}

func (f *fakeGraphStore) PDNSByRdata(_ context.Context, rdata string, _ int) ([]ch.PDNSRecord, error) {
	var out []ch.PDNSRecord
	for _, r := range f.pdns {
		if r.RData == rdata {
			out = append(out, r)
		}
	}
	return out, nil
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
	s.subdomains = f
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
		`{"id":"d:www.x.example","kind":"domain","label":"www.x.example","watched":true,"campaign":"spynote","href":"/domains/www.x.example","source":"heimdall"},` +
		`{"id":"ip:192.0.2.1","kind":"ip","label":"192.0.2.1","watched":false,"campaign":"","href":"/rdata/192.0.2.1","source":"heimdall"},` +
		`{"id":"d:cdn.y.example","kind":"domain","label":"cdn.y.example","watched":false,"campaign":"","href":"/domains/cdn.y.example","source":"heimdall"},` +
		`{"id":"` + testNSSet + `","kind":"nsset","label":"ns1.p.example, ns2.p.example","watched":false,"campaign":"","href":"/domains/x.example","source":"heimdall"}],` +
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
		`{"id":"d:b.example","kind":"domain","label":"b.example","watched":true,"campaign":"","href":"/domains/b.example","source":"heimdall"}`,
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

func TestAPIGraphDomainVT(t *testing.T) {
	s, f := graphTestServer(t)
	f.vt = []ch.VTPair{vtPair("www.x.example", "198.51.100.7")}

	_, body := serveGraph(t, s, s.apiGraphDomain, "/api/graph/domain/www.x.example?vt=1", "fqdn", "www.x.example")
	if f.vtCalls != 0 || strings.Contains(body, `"kind":"VT"`) {
		t.Error("vt=1 read the VirusTotal cache without VirusTotal configured")
	}

	s.vt = &vt.Enricher{}
	if _, body := serveGraph(t, s, s.apiGraphDomain, "/api/graph/domain/www.x.example", "fqdn", "www.x.example"); f.vtCalls != 0 || strings.Contains(body, `"kind":"VT"`) {
		t.Error("graph without vt=1 has VirusTotal edges")
	}
	_, body = serveGraph(t, s, s.apiGraphDomain, "/api/graph/domain/www.x.example?vt=1", "fqdn", "www.x.example")
	for _, want := range []string{
		`{"id":"ip:198.51.100.7","kind":"ip","label":"198.51.100.7","watched":false,"campaign":"","href":"/rdata/198.51.100.7","source":"vt"}`,
		`{"from":"d:www.x.example","to":"ip:198.51.100.7","kind":"VT","first_seen":"2024-01-02T00:00:00Z","last_seen":"2024-03-04T00:00:00Z"}`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("vt graph lacks %s", want)
		}
	}
	if got := strings.Join(f.vtHosts, " ") + " | " + strings.Join(f.vtIPs, " "); got != "cdn.y.example www.x.example | 192.0.2.1" {
		t.Errorf("vt query = %s, want the names and non-CDN addresses", got)
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
		`<script src="/static/vtjob.js" defer></script>`,
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
	if n := strings.Count(body, "<script"); n != 4 || strings.Count(body, "<script src=") != 4 {
		t.Errorf("%d script tags, want 4 external ones", n)
	}

	if strings.Contains(body, "VirusTotal") {
		t.Error("graph page offers VirusTotal without it configured")
	}

	if !strings.Contains(body, "SUB: subdomain</li>") || strings.Contains(body, "graph-subs-toggle") {
		t.Error("graph page legend lacks SUB, or offers subdomains without SubsToggle")
	}

	body = renderPage(t, "graph", graphView{Title: "spynote", Back: "/campaigns/7", Source: "/graph/campaign/7/data", MaxNodes: graphMaxNodes, SubsToggle: true, Subs: true})
	if strings.Contains(body, "Depth") {
		t.Error("campaign graph offers depths")
	}
	if !strings.Contains(body, `<input type="checkbox" id="graph-subs-toggle" checked> Subdomains`) {
		t.Error("campaign graph lacks the checked Subdomains box")
	}

	body = renderPage(t, "graph", graphView{
		Title: "www.x.example", Back: "/domains/www.x.example",
		Source: "/graph/domain/www.x.example/data?depth=1&subs=0", Path: "/graph/domain/www.x.example", Depth: 1, MaxNodes: graphMaxNodes,
		SubsToggle: true,
	})
	for _, want := range []string{
		`data-source="/graph/domain/www.x.example/data?depth=1&amp;subs=0"`,
		`<a href="/graph/domain/www.x.example?depth=2&amp;subs=0">2</a>`,
		`<input type="checkbox" id="graph-subs-toggle"> Subdomains`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("graph page without subdomains lacks %q", want)
		}
	}

	v := graphView{
		Title: "www.x.example", Back: "/domains/www.x.example",
		Source: "/graph/domain/www.x.example/data?depth=1&vt=1", Path: "/graph/domain/www.x.example", Depth: 1, MaxNodes: graphMaxNodes,
	}
	v.VT = &graphVTView{On: true, Endpoint: "/graph/domain/www.x.example/vt?depth=1", Budget: 500, Remaining: 480}
	body = renderPage(t, "graph", v)
	for _, want := range []string{
		`data-source="/graph/domain/www.x.example/data?depth=1&amp;vt=1"`,
		`<a href="/graph/domain/www.x.example?depth=2&amp;vt=1">2</a>`,
		`<input type="checkbox" id="graph-vt-toggle" checked> VirusTotal`,
		"VT lookups left today: 480 / 500", "seen by VirusTotal only", "VirusTotal resolution",
		`id="graph-vt-summary" data-endpoint="/graph/domain/www.x.example/vt?depth=1"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("vt graph page lacks %q", want)
		}
	}
	if strings.Contains(body, "Enrich with VT") {
		t.Error("Enrich with VT offered without the analyst role")
	}

	body = renderPage(t, "domain", map[string]any{"FQDN": "www.x.example", "Domain": (*pg.Domain)(nil), "Sharing": map[string]uint64{}})
	if !strings.Contains(body, `<a class="title-link" href="/graph/domain/www.x.example">Graph</a>`) {
		t.Error("domain page lacks the Graph link")
	}
}

// domainGraph is a graph of domain nodes and the given edges.
func domainGraph(fqdns []string, edges ...graphEdge) graphJSON {
	g := graphJSON{Nodes: []graphNode{}, Edges: append([]graphEdge{}, edges...)}
	for _, fqdn := range fqdns {
		g.Nodes = append(g.Nodes, domainNode(fqdn))
	}
	return g
}

func TestLinkSubdomains(t *testing.T) {
	g := domainGraph([]string{"x.example", "b.x.example", "c.b.x.example", "a.d.x.example", "www.x.example", "b.y.example", "co.uk", "x.co.uk"},
		graphEdge{From: "d:x.example", To: "d:www.x.example", Kind: edgeSub})
	g.Nodes = append(g.Nodes, ipNode("192.0.2.1"))
	g.Edges = append(g.Edges, graphEdge{From: "d:x.example", To: "ip:192.0.2.1", Kind: "A"})

	linkSubdomains(&g)
	_, edges := graphSummary(g)
	want := "d:x.example>d:www.x.example/SUB d:x.example>ip:192.0.2.1/A " +
		"d:x.example>d:b.x.example/SUB d:b.x.example>d:c.b.x.example/SUB d:x.example>d:a.d.x.example/SUB"
	if edges != want {
		t.Errorf("edges = %s\nwant    %s", edges, want)
	}
	linkSubdomains(&g)
	if _, again := graphSummary(g); again != want {
		t.Errorf("linked twice: %s", again)
	}
	if len(g.Nodes) != 9 {
		t.Errorf("%d nodes, want the 9 of the graph", len(g.Nodes))
	}
}

func TestEnrichedSubdomains(t *testing.T) {
	jan, mar := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	r := enrich.Result{
		Subdomains: &enrich.Subdomains{Zone: "x.example", Names: []enrich.Subdomain{
			{Name: "old.x.example", LastSeen: jan},
			{Name: "new.x.example", LastSeen: mar},
			{Name: "x.example", LastSeen: mar},
			{Name: "other.example", LastSeen: mar},
		}},
		CT: &enrich.CT{Zone: "x.example", Names: []string{"*.x.example", "*.api.x.example", "NEW.x.example.", "deep.api.x.example", "www.other.example", "notx.example"}},
	}
	if got, want := strings.Join(enrichedSubdomains(r, "x.example"), " "),
		"new.x.example old.x.example api.x.example deep.api.x.example"; got != want {
		t.Errorf("subdomains = %s\nwant         %s", got, want)
	}
	if got := enrichedSubdomains(enrich.Result{}, "x.example"); got != nil {
		t.Errorf("no source: %v", got)
	}

	g := addSubdomains(domainGraph([]string{"x.example", "b.y.example"}), map[string]enrich.Result{"x.example": r}, graphMaxNodes)
	linkSubdomains(&g)
	nodes, edges := graphSummary(g)
	if want := "d:x.example d:b.y.example d:new.x.example d:old.x.example d:api.x.example d:deep.api.x.example"; nodes != want {
		t.Errorf("nodes = %s\nwant    %s", nodes, want)
	}
	if want := "d:x.example>d:new.x.example/SUB d:x.example>d:old.x.example/SUB d:x.example>d:api.x.example/SUB d:api.x.example>d:deep.api.x.example/SUB"; edges != want {
		t.Errorf("edges = %s\nwant    %s", edges, want)
	}
	if g.Truncated {
		t.Error("truncated under the caps")
	}
}

func TestAddSubdomainsCaps(t *testing.T) {
	var names []string
	for i := range graphSubdomainsPerDomain + 10 {
		names = append(names, fmt.Sprintf("h%d.x.example", i))
	}
	enriched := map[string]enrich.Result{"x.example": {CT: &enrich.CT{Names: names}}}

	g := addSubdomains(domainGraph([]string{"x.example"}), enriched, graphMaxNodes)
	if len(g.Nodes) != 1+graphSubdomainsPerDomain || !g.Truncated || g.Nodes[graphSubdomainsPerDomain].Label != names[graphSubdomainsPerDomain-1] {
		t.Errorf("%d nodes, truncated %v, want the first %d subdomains", len(g.Nodes), g.Truncated, graphSubdomainsPerDomain)
	}

	enriched["x.example"] = enrich.Result{CT: &enrich.CT{Names: names[:3]}}
	g = addSubdomains(domainGraph([]string{"x.example"}, graphEdge{From: "d:x.example", To: "d:x.example", Kind: edgeCNAME}), enriched, 3)
	if nodes, edges := graphSummary(g); nodes != "d:x.example d:h0.x.example d:h1.x.example" || edges != "d:x.example>d:x.example/CNAME" || !g.Truncated {
		t.Errorf("node limit: nodes %q edges %q truncated %v", nodes, edges, g.Truncated)
	}
}

func TestAPIGraphSubdomains(t *testing.T) {
	s, f := graphTestServer(t)
	_, plain := serveGraph(t, s, s.apiGraphDomain, "/api/graph/domain/www.x.example?subs=0", "fqdn", "www.x.example")
	if len(f.asked) != 0 {
		t.Errorf("subs=0 read the enrichments of %v", f.asked)
	}
	_, none := serveGraph(t, s, s.apiGraphDomain, "/api/graph/domain/www.x.example", "fqdn", "www.x.example")
	if none != plain {
		t.Errorf("without enrichment or parent:\n%s\nwant the graph unchanged\n%s", none, plain)
	}
	if len(f.asked) != 1 || strings.Join(f.asked[0], " ") != "www.x.example cdn.y.example" {
		t.Errorf("enrichments read %v, want one read of the domains of the graph", f.asked)
	}

	f.enriched = map[string]enrich.Result{"www.x.example": {
		Subdomains: &enrich.Subdomains{Zone: "x.example", Names: []enrich.Subdomain{{Name: "mail.www.x.example"}, {Name: "api.x.example"}}},
		CT:         &enrich.CT{Zone: "x.example", Names: []string{"*.www.x.example", "*.a.mail.www.x.example"}},
	}}
	f.watched["mail.www.x.example"] = pg.Domain{FQDN: "mail.www.x.example", Campaign: "spynote"}
	_, body := serveGraph(t, s, s.apiGraphDomain, "/api/graph/domain/www.x.example", "fqdn", "www.x.example")
	for _, want := range []string{
		`{"id":"d:mail.www.x.example","kind":"domain","label":"mail.www.x.example","watched":true,"campaign":"spynote","href":"/domains/mail.www.x.example","source":"heimdall"}`,
		`{"from":"d:www.x.example","to":"d:mail.www.x.example","kind":"SUB"}`,
		`{"from":"d:mail.www.x.example","to":"d:a.mail.www.x.example","kind":"SUB"}`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("graph lacks %s", want)
		}
	}
	if strings.Contains(body, "d:api.x.example") || strings.Contains(body, `"d:www.x.example","kind":"SUB"`) {
		t.Errorf("a name outside the domain or the wildcard of the domain itself was added: %s", body)
	}
	if _, body := serveGraph(t, s, s.apiGraphDomain, "/api/graph/domain/www.x.example?subs=0", "fqdn", "www.x.example"); body != plain {
		t.Errorf("subs=0 with an enrichment:\n%s\nwant\n%s", body, plain)
	}

	_, body = serveGraph(t, s, s.apiGraphCampaign, "/api/graph/campaign/7", "id", "7")
	if !strings.Contains(body, `{"from":"d:www.x.example","to":"d:mail.www.x.example","kind":"SUB"}`) {
		t.Errorf("campaign graph lacks the SUB edges: %s", body)
	}
	if _, body := serveGraph(t, s, s.apiGraphCampaign, "/api/graph/campaign/7?subs=0", "id", "7"); strings.Contains(body, `"SUB"`) {
		t.Errorf("campaign graph with subs=0 has SUB edges: %s", body)
	}
}
