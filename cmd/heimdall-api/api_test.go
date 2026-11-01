package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gjallarhorn "github.com/sebdraven/heimdall/internal/changes"
	"github.com/sebdraven/heimdall/internal/store/ch"
	"github.com/sebdraven/heimdall/internal/store/pg"
)

func encode(t *testing.T, v any) string {
	t.Helper()
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, v)
	return strings.TrimSpace(rec.Body.String())
}

func TestDomainDetailJSON(t *testing.T) {
	cet := time.FixedZone("CET", 3600)
	dd := domainDetail{
		Domain: &pg.Domain{FQDN: "www.x.example", Campaign: "spynote", IntervalSeconds: 300, Enabled: true, Source: "web:alice", AddedAt: t0.In(cet)},
		Current: []ch.Current{
			{QType: "A", Resolver: "9.9.9.9:53", TS: t0.Add(time.Hour).In(cet), Rcode: "NOERROR", TTL: 300, Rdata: []string{"192.0.2.1"}},
			{QType: "AAAA", Resolver: "9.9.9.9:53", TS: t0.In(cet), Rcode: "NOERROR"},
			{QType: "A", Resolver: "1.1.1.1:53", TS: t0.In(cet), Rcode: "NOERROR", TTL: 60, Rdata: []string{"104.16.0.1", "192.0.2.9"}},
		},
		Changes: []gjallarhorn.Change{
			{
				TS: t0.Add(time.Minute).In(cet), Key: gjallarhorn.Key{Domain: "zone:www.x.example", QType: "NS", Resolver: "9.9.9.9:53"},
				PrevTrackedHash: 3, NewTrackedHash: 4, PrevRcode: "NOERROR", NewRcode: "NOERROR",
				Added: []string{"ns1.sinkhole.example"}, Removed: []string{"ns1.x.example"}, PrevTTL: 3600, NewTTL: 3600,
			},
			{
				TS: t0.In(cet), Key: gjallarhorn.Key{Domain: "www.x.example", QType: "A", Resolver: "9.9.9.9:53"},
				PrevTrackedHash: 1, NewTrackedHash: 2, PrevRcode: "NXDOMAIN", NewRcode: "NOERROR",
				Added: []string{"192.0.2.1"}, NewTTL: 300,
			},
		},
		PDNS: []ch.PDNSRecord{
			{RRName: "www.x.example", RRType: "A", RData: "192.0.2.1", FirstSeen: t0.In(cet), LastSeen: t0.Add(time.Hour).In(cet), Count: 3},
		},
	}
	want := `{"domain":{"fqdn":"www.x.example","campaign":"spynote","interval_seconds":300,"enabled":true,"source":"web:alice","added_at":"2026-03-01T12:00:00Z"},` +
		`"current":[{"qtype":"A","resolver":"9.9.9.9:53","ts":"2026-03-01T13:00:00Z","rcode":"NOERROR","ttl":300,"rdata":["192.0.2.1"]},` +
		`{"qtype":"AAAA","resolver":"9.9.9.9:53","ts":"2026-03-01T12:00:00Z","rcode":"NOERROR","ttl":0,"rdata":[]},` +
		`{"qtype":"A","resolver":"1.1.1.1:53","ts":"2026-03-01T12:00:00Z","rcode":"NOERROR","ttl":60,"rdata":["104.16.0.1","192.0.2.9"],"cdn":{"104.16.0.1":"Cloudflare"}}],` +
		`"changes":[{"ts":"2026-03-01T12:01:00Z","scope":"zone","qtype":"NS","resolver":"9.9.9.9:53","prev_rcode":"NOERROR","new_rcode":"NOERROR","added":["ns1.sinkhole.example"],"removed":["ns1.x.example"],"prev_ttl":3600,"new_ttl":3600},` +
		`{"ts":"2026-03-01T12:00:00Z","scope":"name","qtype":"A","resolver":"9.9.9.9:53","prev_rcode":"NXDOMAIN","new_rcode":"NOERROR","added":["192.0.2.1"],"removed":[],"prev_ttl":0,"new_ttl":300}],` +
		`"pdns":[{"rrname":"www.x.example","rrtype":"A","rdata":"192.0.2.1","first_seen":"2026-03-01T12:00:00Z","last_seen":"2026-03-01T13:00:00Z","count":3}]}`
	if got := encode(t, toDomainDetailJSON(dd, testCDN())); got != want {
		t.Errorf("detail =\n%s\nwant\n%s", got, want)
	}
}

func TestDomainDetailJSONUnwatched(t *testing.T) {
	want := `{"domain":null,"current":[],"changes":[],"pdns":[]}`
	if got := encode(t, toDomainDetailJSON(domainDetail{}, testCDN())); got != want {
		t.Errorf("detail = %s, want %s", got, want)
	}
}

func TestSplitCDN(t *testing.T) {
	kept, excluded := splitCDN([]ch.PivotValue{
		{RRType: "A", RData: "104.16.0.1"},
		{RRType: "A", RData: "192.0.2.1"},
		{RRType: "AAAA", RData: "2001:db8::1"},
		{RRType: "AAAA", RData: "2606:4700::6810:84e5"},
		{RRType: "NS", RData: "ns1.example.net"},
		{RRType: "NS", RData: "104.16.0.2"},
	}, testCDN())
	var values []string
	for _, v := range kept {
		values = append(values, v.RRType+"/"+v.RData)
	}
	if got, want := strings.Join(values, " "), "A/192.0.2.1 AAAA/2001:db8::1 NS/ns1.example.net NS/104.16.0.2"; got != want {
		t.Errorf("kept = %s, want %s", got, want)
	}
	if got, want := encode(t, excluded), `[{"value":"104.16.0.1","provider":"Cloudflare"},{"value":"2606:4700::6810:84e5","provider":"Cloudflare"}]`; got != want {
		t.Errorf("excluded = %s, want %s", got, want)
	}

	kept, excluded = splitCDN([]ch.PivotValue{{RRType: "A", RData: "192.0.2.1"}}, testCDN())
	if len(kept) != 1 || encode(t, excluded) != "[]" {
		t.Errorf("no CDN value: kept %v, excluded %s", kept, encode(t, excluded))
	}
	if got := encode(t, pivotsJSON{Pivots: []pivotJSON{}, ExcludedCDN: excluded}); got != `{"pivots":[],"excluded_cdn":[]}` {
		t.Errorf("empty pivots = %s", got)
	}
}

func TestDomainDetailLimit(t *testing.T) {
	for q, want := range map[string]int{"": 200, "?limit=50": 50, "?limit=5000": 1000, "?limit=0": 200, "?limit=x": 200} {
		r := httptest.NewRequest(http.MethodGet, "/api/domains/x.example/detail"+q, nil)
		if got := intParam(r, "limit", domainChanges, domainChangesMax); got != want {
			t.Errorf("%q: limit %d, want %d", q, got, want)
		}
	}
}

func TestDomainsJSON(t *testing.T) {
	if got := encode(t, toDomainsJSON(nil)); got != "[]" {
		t.Errorf("empty list = %s, want []", got)
	}
}

func TestSearchIPGrouping(t *testing.T) {
	names, values := groupRecords([]ch.PDNSRecord{
		{RRName: "a.example", RRType: "A", RData: "192.0.2.1", FirstSeen: t0, LastSeen: t0.Add(time.Hour), Count: 3},
		{RRName: "b.example", RRType: "A", RData: "192.0.2.1", FirstSeen: t0.Add(-time.Hour), LastSeen: t0.Add(2 * time.Hour), Count: 1},
		{RRName: "a.example", RRType: "TXT", RData: "192.0.2.1", FirstSeen: t0.Add(-2 * time.Hour), LastSeen: t0, Count: 2},
	})
	if len(names) != 2 || names[0].RRName != "b.example" || names[1].RRName != "a.example" {
		t.Fatalf("names = %+v, want b.example then a.example", names)
	}
	if a := names[1]; strings.Join(a.RRTypes, ",") != "A,TXT" || a.Count != 5 || !a.FirstSeen.Equal(t0.Add(-2*time.Hour)) || !a.LastSeen.Equal(t0.Add(time.Hour)) {
		t.Errorf("a.example = %+v", a)
	}
	if len(values) != 2 || values[0].RRType != "A" || values[0].Names != 2 || values[1].RRType != "TXT" || values[1].Names != 1 {
		t.Errorf("values = %+v", values)
	}
}

func TestSearchJSON(t *testing.T) {
	cet := time.FixedZone("CET", 3600)
	d := pg.Domain{FQDN: "node1.otax.fun", Campaign: "spynote", IntervalSeconds: 300, Enabled: true, Source: "web:alice", AddedAt: t0.In(cet)}
	v := searchView{
		Query: "otax", Kind: "pattern", Limit: 200,
		Domains: []pg.Domain{d},
		Names: []nameRow{
			{NameMatch: ch.NameMatch{RRName: "node1.otax.fun", RRTypes: []string{"A"}, FirstSeen: t0.In(cet), LastSeen: t0.In(cet), Count: 2}, Domain: &d},
		},
		Values:    []ch.ValueMatch{{RData: "ns1.otax.fun", RRType: "NS", Names: 3, FirstSeen: t0.In(cet), LastSeen: t0.In(cet)}},
		Truncated: searchTruncated{Values: true},
	}
	want := `{"query":"otax","kind":"pattern",` +
		`"domains":[{"fqdn":"node1.otax.fun","campaign":"spynote","interval_seconds":300,"enabled":true,"source":"web:alice","added_at":"2026-03-01T12:00:00Z"}],` +
		`"names":[{"rrname":"node1.otax.fun","rrtypes":["A"],"first_seen":"2026-03-01T12:00:00Z","last_seen":"2026-03-01T12:00:00Z","count":2,"watched":true,"campaign":"spynote"}],` +
		`"values":[{"rdata":"ns1.otax.fun","rrtype":"NS","names":3,"first_seen":"2026-03-01T12:00:00Z","last_seen":"2026-03-01T12:00:00Z"}],` +
		`"truncated":{"domains":false,"names":false,"values":true}}`
	if got := encode(t, toSearchJSON(v)); got != want {
		t.Errorf("search =\n%s\nwant\n%s", got, want)
	}
	if got := encode(t, toSearchJSON(searchView{Query: "x.example", Kind: "exact"})); got !=
		`{"query":"x.example","kind":"exact","domains":[],"names":[],"values":[],"truncated":{"domains":false,"names":false,"values":false}}` {
		t.Errorf("empty search = %s", got)
	}
}
