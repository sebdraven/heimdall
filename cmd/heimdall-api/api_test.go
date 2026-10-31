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
		},
		Changes: []gjallarhorn.Change{{
			TS: t0.In(cet), Key: gjallarhorn.Key{Domain: "www.x.example", QType: "A", Resolver: "9.9.9.9:53"},
			PrevTrackedHash: 1, NewTrackedHash: 2, PrevRcode: "NXDOMAIN", NewRcode: "NOERROR",
			Added: []string{"192.0.2.1"}, NewTTL: 300,
		}},
		PDNS: []ch.PDNSRecord{
			{RRName: "www.x.example", RRType: "A", RData: "192.0.2.1", FirstSeen: t0.In(cet), LastSeen: t0.Add(time.Hour).In(cet), Count: 3},
		},
	}
	want := `{"domain":{"fqdn":"www.x.example","campaign":"spynote","interval_seconds":300,"enabled":true,"source":"web:alice","added_at":"2026-03-01T12:00:00Z"},` +
		`"current":[{"qtype":"A","resolver":"9.9.9.9:53","ts":"2026-03-01T13:00:00Z","rcode":"NOERROR","ttl":300,"rdata":["192.0.2.1"]},` +
		`{"qtype":"AAAA","resolver":"9.9.9.9:53","ts":"2026-03-01T12:00:00Z","rcode":"NOERROR","ttl":0,"rdata":[]}],` +
		`"changes":[{"ts":"2026-03-01T12:00:00Z","qtype":"A","resolver":"9.9.9.9:53","prev_rcode":"NXDOMAIN","new_rcode":"NOERROR","added":["192.0.2.1"],"removed":[],"prev_ttl":0,"new_ttl":300}],` +
		`"pdns":[{"rrname":"www.x.example","rrtype":"A","rdata":"192.0.2.1","first_seen":"2026-03-01T12:00:00Z","last_seen":"2026-03-01T13:00:00Z","count":3}]}`
	if got := encode(t, toDomainDetailJSON(dd)); got != want {
		t.Errorf("detail =\n%s\nwant\n%s", got, want)
	}
}

func TestDomainDetailJSONUnwatched(t *testing.T) {
	want := `{"domain":null,"current":[],"changes":[],"pdns":[]}`
	if got := encode(t, toDomainDetailJSON(domainDetail{})); got != want {
		t.Errorf("detail = %s, want %s", got, want)
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
