//go:build integration

package ch

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sebdraven/heimdall/internal/resolver"
)

func TestOwnedRecords(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	w := resolver.Observation{TS: now, Domain: "www.a.example", QType: "A", Resolver: "9.9.9.9:53", Rcode: "NOERROR", Rdata: []string{"192.0.2.1"},
		Answers: []resolver.Answer{
			{Name: "www.a.example", Type: "CNAME", Value: "edge.b.example."},
			{Name: "edge.b.example", Type: "A", Value: "192.0.2.1"},
		}}
	mx := analyticsObs(0, 1, "a.example", "MX", "NOERROR", "10 mx.evil.example.")
	ip := analyticsObs(0, 1, "a.example", "A", "NOERROR", "192.0.2.2")
	txt := analyticsObs(0, 1, "a.example", "TXT", "NOERROR", "v=spf1 -all")
	if err := s.InsertObservations(ctx, []resolver.Observation{w, mx, ip, txt}); err != nil {
		t.Fatal(err)
	}
	// Past maxNames names, the query is split.
	names := []string{"www.a.example", "a.example", "edge.b.example"}
	for i := range maxNames + 10 {
		names = append(names, fmt.Sprintf("n%d.example", i))
	}
	got, err := s.OwnedRecords(ctx, names, []string{"A", "AAAA", "CNAME", "MX"})
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, o := range got {
		lines = append(lines, o.RRName+" "+o.RRType+" "+o.RData)
	}
	want := "a.example A 192.0.2.2|a.example MX 10 mx.evil.example.|edge.b.example A 192.0.2.1|www.a.example CNAME edge.b.example."
	if strings.Join(lines, "|") != want {
		t.Errorf("owned = %s\nwant %s", strings.Join(lines, "|"), want)
	}
	if got, err := s.OwnedRecords(ctx, names, nil); err != nil || got != nil {
		t.Errorf("no rrtype: %v, %v", got, err)
	}
}

func TestZoneSOAs(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	soa := func(ts time.Time, zone, value string) resolver.Observation {
		return resolver.Observation{TS: ts, Domain: "www." + zone, QType: "AAAA", Resolver: "9.9.9.9:53", Rcode: "NOERROR",
			Authority: []resolver.Answer{{Name: zone, Type: "SOA", Value: value}}}
	}
	if err := s.InsertObservations(ctx, []resolver.Observation{
		soa(now.Add(-2*time.Hour), "a.example", "ns1.old.example. admin.old.example. 1 7200 900 1209600 300"),
		soa(now.Add(-time.Hour), "a.example", "ns1.evil.example. admin.evil.example. 2 7200 900 1209600 300"),
		soa(now.Add(-10*24*time.Hour), "stale.example", "ns1.evil.example. admin.evil.example. 2 7200 900 1209600 300"),
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ZoneSOAs(ctx, []string{"x.www.a.example", "a.example", "stale.example", "none.example"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("soas = %v, want a.example for two names", got)
	}
	for _, d := range []string{"x.www.a.example", "a.example"} {
		if z := got[d]; z == nil || z.Zone != "a.example" || z.MName != "ns1.evil.example" || z.RName != "admin.evil.example" {
			t.Errorf("%s: %+v", d, z)
		}
	}
}
