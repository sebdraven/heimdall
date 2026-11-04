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

var analyticsDay = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

// analyticsObs is an observation of day d (0 is analyticsDay) at hour h,
// whose answers are owned by the queried name.
func analyticsObs(d, h int, domain, qtype, rcode string, rdata ...string) resolver.Observation {
	o := resolver.Observation{
		TS: analyticsDay.Add(time.Duration(24*d+h) * time.Hour), Domain: domain, QType: qtype, Resolver: "9.9.9.9:53",
		Rcode: rcode, Rdata: rdata,
	}
	for _, v := range rdata {
		o.Answers = append(o.Answers, resolver.Answer{Name: domain, Type: qtype, Value: v})
	}
	return o
}

func TestCampaignLiveness(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if err := s.InsertObservations(ctx, []resolver.Observation{
		analyticsObs(-1, 23, "a.example", "A", "NOERROR", "192.0.2.9"),
		analyticsObs(0, 10, "a.example", "A", "NOERROR", "192.0.2.1"),
		analyticsObs(0, 12, "a.example", "A", "NXDOMAIN"),
		analyticsObs(1, 10, "a.example", "A", "NOERROR", "192.0.2.2"),
		analyticsObs(1, 11, "a.example", "AAAA", "NOERROR"),
		analyticsObs(1, 23, "a.example", "NS", "NOERROR", "ns1.p.example"),
		analyticsObs(1, 8, "b.example", "AAAA", "NOERROR"),
		analyticsObs(2, 8, "b.example", "A", "TIMEOUT"),
		analyticsObs(0, 9, "c.example", "A", "NOERROR", "192.0.2.3"),
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	states, err := s.CampaignLiveness(ctx, []string{"a.example", "b.example"}, analyticsDay)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, d := range states {
		got = append(got, fmt.Sprintf("%s %s %q %v %s", d.Domain, d.Day, d.Rcode, d.IPs, d.LastTS.UTC().Format("15:04")))
	}
	// The NXDOMAIN of 12:00 ends day 0; the AAAA without data and the NS
	// query do not change day 1; a day of answers without data has no rcode.
	want := []string{
		`a.example 2026-03-01 "NXDOMAIN" [192.0.2.1] 12:00`,
		`a.example 2026-03-02 "NOERROR" [192.0.2.2] 11:00`,
		`b.example 2026-03-02 "" [] 08:00`,
		`b.example 2026-03-03 "TIMEOUT" [] 08:00`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("liveness =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	if states, err := s.CampaignLiveness(ctx, nil, analyticsDay); err != nil || states != nil {
		t.Errorf("no domain = %v, %v; want nothing", states, err)
	}
}

func TestNewIPsByDay(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	cname := analyticsObs(1, 9, "w.example", "A", "NOERROR", "192.0.2.4")
	cname.Answers = []resolver.Answer{
		{Name: "w.example", Type: "CNAME", Value: "cdn.w.example"},
		{Name: "cdn.w.example", Type: "A", Value: "192.0.2.4"},
	}
	if err := s.InsertObservations(ctx, []resolver.Observation{
		analyticsObs(-10, 9, "x.example", "A", "NOERROR", "192.0.2.1"),
		analyticsObs(1, 9, "x.example", "A", "NOERROR", "192.0.2.1"),
		analyticsObs(0, 10, "y.example", "A", "NOERROR", "192.0.2.2"),
		analyticsObs(0, 11, "z.example", "A", "NOERROR", "192.0.2.3"),
		analyticsObs(2, 11, "z.example", "AAAA", "NOERROR", "2001:db8::3"),
		cname,
		analyticsObs(1, 9, "other.example", "A", "NOERROR", "192.0.2.5"),
		analyticsObs(1, 9, "txt.example", "TXT", "NOERROR", "192.0.2.6"),
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	days, err := s.NewIPsByDay(ctx, []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "2001:db8::3", "192.0.2.4", "192.0.2.6"}, analyticsDay)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, d := range days {
		got = append(got, d.Day+" "+strings.Join(d.IPs, ","))
	}
	// 192.0.2.1 was seen before the window, 192.0.2.5 was not asked for and
	// 192.0.2.6 is TXT data; 192.0.2.4 counts under its CNAME target.
	want := "2026-03-01 192.0.2.2,192.0.2.3 | 2026-03-02 192.0.2.4 | 2026-03-03 2001:db8::3"
	if strings.Join(got, " | ") != want {
		t.Errorf("new ips = %s, want %s", strings.Join(got, " | "), want)
	}

	if days, err := s.NewIPsByDay(ctx, nil, analyticsDay); err != nil || days != nil {
		t.Errorf("no address = %v, %v; want nothing", days, err)
	}
}
