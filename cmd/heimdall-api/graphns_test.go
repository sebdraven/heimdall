package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/sebdraven/heimdall/internal/store/ch"
)

// nsGraphStore records the NS set asked for and answers matches.
type nsGraphStore struct {
	*fakeGraphStore
	zone    string
	set     []string
	limit   int
	matches []ch.NSPairPivot
}

func (f *nsGraphStore) NSPairPivots(_ context.Context, zone string, set []string, limit int) ([]ch.NSPairPivot, error) {
	f.zone, f.set, f.limit = zone, set, limit
	return f.matches, nil
}

func nsGraphServer(t *testing.T) (*server, *nsGraphStore) {
	t.Helper()
	s, f := graphTestServer(t)
	ns := &nsGraphStore{fakeGraphStore: f}
	s.graph = graphStores{ns, f}
	return s, ns
}

func nsList(n int) string {
	var ns []string
	for i := range n {
		ns = append(ns, fmt.Sprintf("ns%02d.p.example", i))
	}
	return strings.Join(ns, ",")
}

func TestParseNSSet(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want string
	}{
		{"ns2.p.example,ns1.p.example", "ns1.p.example ns2.p.example"},
		{"NS2.P.Example.,ns1.p.example,ns2.p.example", "ns1.p.example ns2.p.example"},
		{" ns1.p.example , ns3.p.example. ", "ns1.p.example ns3.p.example"},
		{nsList(16), strings.ReplaceAll(nsList(16), ",", " ")},
	} {
		if got, ok := parseNSSet(tt.in); !ok || strings.Join(got, " ") != tt.want {
			t.Errorf("parseNSSet(%q) = %v, %v; want %s", tt.in, got, ok, tt.want)
		}
	}
	for _, in := range []string{
		"", "ns1.p.example", "ns1.p.example,NS1.P.example.", "ns1.p.example,ns 2.p.example",
		"ns1.p.example,localhost", "ns1.p.example,,ns2.p.example", nsList(17),
	} {
		if got, ok := parseNSSet(in); ok {
			t.Errorf("parseNSSet(%q) = %v, want invalid", in, got)
		}
	}
}

func TestAPIGraphNS(t *testing.T) {
	s, f := nsGraphServer(t)
	f.matches = []ch.NSPairPivot{{Domain: "x.example"}, {Domain: "b.example"}}

	code, body := serveGraph(t, s, s.apiGraphNS, "/api/graph/ns/x", "set", "NS2.P.example.,ns1.p.example,ns2.p.example")
	want := `{"nodes":[` +
		`{"id":"` + testNSSet + `","kind":"nsset","label":"ns1.p.example, ns2.p.example","watched":false,"campaign":"","href":"","source":"heimdall"},` +
		`{"id":"d:b.example","kind":"domain","label":"b.example","watched":true,"campaign":"","href":"/domains/b.example","source":"heimdall"},` +
		`{"id":"d:x.example","kind":"domain","label":"x.example","watched":false,"campaign":"","href":"/domains/x.example","source":"heimdall"}],` +
		`"edges":[{"from":"d:b.example","to":"` + testNSSet + `","kind":"NS_SET"},` +
		`{"from":"d:x.example","to":"` + testNSSet + `","kind":"NS_SET"}],` +
		`"truncated":false,"excluded_cdn":0}`
	if code != http.StatusOK || body != want {
		t.Errorf("status %d\n%s\nwant\n%s", code, body, want)
	}
	if got := strings.Join(f.set, ","); f.zone != "" || got != "ns1.p.example,ns2.p.example" || f.limit != graphMaxNodes {
		t.Errorf("NSPairPivots(zone %q, set %s, limit %d), want no zone, the normalized set and %d", f.zone, got, f.limit, graphMaxNodes)
	}

	h := withTokens(s)
	if code, routed := serveAPI(h, http.MethodGet, "/api/graph/ns/ns2.p.example,ns1.p.example", "viewer"); code != http.StatusOK || routed != want {
		t.Errorf("API route: status %d: %s", code, routed)
	}

	for _, set := range []string{"ns1.p.example", "ns1.p.example,ns_2..p.example", nsList(17)} {
		if code, body := serveGraph(t, s, s.apiGraphNS, "/api/graph/ns/x", "set", set); code != http.StatusBadRequest || body != `{"error":"invalid NS set"}` {
			t.Errorf("%q: status %d: %s, want 400", set, code, body)
		}
	}

	f.matches = nil
	for i := range graphMaxNodes {
		f.matches = append(f.matches, ch.NSPairPivot{Domain: fmt.Sprintf("d%03d.example", i)})
	}
	_, body = serveGraph(t, s, s.apiGraphNS, "/api/graph/ns/x", "set", "ns1.p.example,ns2.p.example")
	if !strings.Contains(body, `"truncated":true`) || strings.Count(body, `"kind":"domain"`) != graphMaxNodes-1 || !strings.HasPrefix(body, `{"nodes":[{"id":"`+testNSSet+`"`) {
		t.Errorf("%d matches: %d domain nodes, truncated %v, want the set first", graphMaxNodes, strings.Count(body, `"kind":"domain"`), strings.Contains(body, `"truncated":true`))
	}
}
