package ch

import (
	"context"
	"strings"
	"testing"
	"time"
)

var q0 = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func period(fromH, toH int) Period {
	return Period{First: q0.Add(time.Duration(fromH) * time.Hour), Last: q0.Add(time.Duration(toH) * time.Hour)}
}

func TestZoneCandidates(t *testing.T) {
	for fqdn, want := range map[string]string{
		"x.y.z":         "x.y.z y.z",
		"www.a.example": "www.a.example a.example",
		"a.example":     "a.example",
		"example":       "",
		"":              "",
	} {
		if got := strings.Join(zoneCandidates(fqdn), " "); got != want {
			t.Errorf("zoneCandidates(%q) = %q, want %q", fqdn, got, want)
		}
	}
}

func TestPickZone(t *testing.T) {
	recs := []nsRecord{
		{rrname: "a.example", rdata: "ns2.p.example", period: period(2, 10)},
		{rrname: "a.example", rdata: "ns1.p.example", period: period(0, 8)},
		{rrname: "other.example", rdata: "ns9.p.example", period: period(0, 1)},
	}
	z := pickZone(zoneCandidates("x.www.a.example"), recs)
	if z == nil || z.Zone != "a.example" || strings.Join(z.NS, " ") != "ns1.p.example ns2.p.example" || z.Period != period(0, 10) {
		t.Fatalf("zone of x.www.a.example = %+v, want a.example, its two NS over hours 0 to 10", z)
	}

	recs = append(recs, nsRecord{rrname: "www.a.example", rdata: "ns.delegated.example", period: period(1, 2)})
	if z := pickZone(zoneCandidates("www.a.example"), recs); z == nil || z.Zone != "www.a.example" || len(z.NS) != 1 {
		t.Errorf("a name owning NS is its own zone: %+v", z)
	}

	if z := pickZone(zoneCandidates("b.example"), recs); z != nil {
		t.Errorf("no NS anywhere: %+v, want nil", z)
	}
}

func TestMatchNSSet(t *testing.T) {
	set := []string{"a.ns.example", "b.ns.example"}
	got := matchNSSet("z.example", set, []NSSet{
		{Zone: "same.example", NS: []string{"b.ns.example", "a.ns.example"}, Period: period(5, 20)},
		{Zone: "superset.example", NS: []string{"a.ns.example", "b.ns.example", "c.ns.example"}, Period: period(0, 10)},
		{Zone: "subset.example", NS: []string{"a.ns.example"}, Period: period(0, 10)},
		{Zone: "z.example", NS: []string{"a.ns.example", "b.ns.example"}, Period: period(0, 10)},
		{Zone: "later.example", NS: []string{"a.ns.example", "b.ns.example"}, Period: period(11, 12)},
	}, 0)
	var names []string
	for _, p := range got {
		names = append(names, p.Domain)
	}
	if got, want := strings.Join(names, " "), "same.example later.example"; got != want {
		t.Fatalf("matches = %s, want %s: equal sets only, zone itself left out", got, want)
	}
	if p := got[0]; p.Target != period(0, 10) || p.Other != period(5, 20) || p.Overlap == nil || *p.Overlap != period(5, 10) {
		t.Errorf("same.example = %+v, want target 0-10, other 5-20, overlap 5-10", p)
	}
	if got[1].Overlap != nil {
		t.Errorf("later.example overlap = %+v, want nil", got[1].Overlap)
	}

	if got := matchNSSet("z.example", set, []NSSet{
		{Zone: "same.example", NS: set},
		{Zone: "later.example", NS: set},
	}, 1); len(got) != 1 {
		t.Errorf("limit 1: %d matches", len(got))
	}
}

func TestNSPairPivotsNeedsTwo(t *testing.T) {
	var s *Store // never queried below MinNSSet
	for _, set := range [][]string{nil, {"a.ns.example"}, {"a.ns.example", "a.ns.example"}} {
		got, err := s.NSPairPivots(context.Background(), "z.example", set, 10)
		if got != nil || err != nil {
			t.Errorf("set %v: %v, %v; want nil", set, got, err)
		}
	}
}
