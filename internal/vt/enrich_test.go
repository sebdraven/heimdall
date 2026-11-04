package vt

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sebdraven/heimdall/internal/cdn"
)

var now = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

type fakeLookup struct {
	res   map[string][]Resolution
	errs  map[string]error
	calls []string
}

func (f *fakeLookup) DomainResolutions(_ context.Context, domain string) ([]Resolution, error) {
	return f.get("d:" + domain)
}

func (f *fakeLookup) IPResolutions(_ context.Context, ip string) ([]Resolution, error) {
	return f.get("ip:" + ip)
}

func (f *fakeLookup) get(o string) ([]Resolution, error) {
	f.calls = append(f.calls, o)
	return f.res[o], f.errs[o]
}

type fakeLedger struct {
	used    int
	fetched map[string]time.Time
	records map[string]string
}

func (f *fakeLedger) ReserveVTLookup(_ context.Context, budget int) (bool, error) {
	if f.used >= budget {
		return false, nil
	}
	f.used++
	return true, nil
}

func (f *fakeLedger) VTUsageToday(context.Context) (int, error) { return f.used, nil }

func (f *fakeLedger) FreshVTObjects(_ context.Context, objects []string, since time.Time) (map[string]bool, error) {
	out := map[string]bool{}
	for _, o := range objects {
		if t, ok := f.fetched[o]; ok && !t.Before(since) {
			out[o] = true
		}
	}
	return out, nil
}

func (f *fakeLedger) RecordVTFetch(_ context.Context, object, status string, count int) error {
	f.records[object] = fmt.Sprintf("%s/%d", status, count)
	return nil
}

type fakeSink struct{ rs []Resolution }

func (f *fakeSink) InsertVTResolutions(_ context.Context, rs []Resolution, _ time.Time) error {
	f.rs = append(f.rs, rs...)
	return nil
}

func testEnricher(budget int) (*Enricher, *fakeLookup, *fakeLedger, *fakeSink) {
	l := &fakeLookup{res: map[string][]Resolution{}, errs: map[string]error{}}
	g := &fakeLedger{fetched: map[string]time.Time{}, records: map[string]string{}}
	s := &fakeSink{}
	e := &Enricher{
		Lookup: l,
		Ledger: g,
		Sink:   s,
		CDN:    cdn.New([]cdn.Prefix{{Prefix: netip.MustParsePrefix("104.16.0.0/13"), Provider: "Cloudflare"}}),
		Budget: budget,
		TTL:    168 * time.Hour,
		Log:    slog.New(slog.DiscardHandler),
		Now:    func() time.Time { return now },
	}
	return e, l, g, s
}

func TestEnrichSkips(t *testing.T) {
	e, l, g, s := testEnricher(500)
	g.fetched["d:fresh.example"] = now.Add(-time.Hour)
	g.fetched["d:stale.example"] = now.Add(-200 * time.Hour)
	l.res["d:stale.example"] = []Resolution{{HostName: "Stale.Example.", IP: "93.184.215.14", Date: now}}
	l.res["ip:93.184.215.14"] = []Resolution{{HostName: "other.example", IP: "93.184.215.14", Date: now}, {HostName: "bad.example", IP: "not-an-ip"}}

	sum, err := e.Enrich(context.Background(), []string{
		"d:fresh.example", "d:stale.example", "d:stale.example", "d:none.example",
		"ip:93.184.215.14", "ip:104.16.0.1", "ip:192.168.1.1", "ip:192.0.2.1", "ip:2001:db8::1",
		"ns:ns1.p.example,ns2.p.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := (Summary{LookedUp: 3, Cached: 1, SkippedCDN: 1, SkippedReserved: 3}); sum != want {
		t.Errorf("summary = %+v, want %+v", sum, want)
	}
	if got := strings.Join(l.calls, " "); got != "d:none.example d:stale.example ip:93.184.215.14" {
		t.Errorf("lookups = %s", got)
	}
	if g.used != 3 {
		t.Errorf("%d lookups counted, want 3", g.used)
	}
	want := map[string]string{"d:none.example": "empty/0", "d:stale.example": "ok/1", "ip:93.184.215.14": "ok/1"}
	if fmt.Sprint(g.records) != fmt.Sprint(want) {
		t.Errorf("fetches = %v, want %v", g.records, want)
	}
	if len(s.rs) != 2 || s.rs[0].HostName != "stale.example" || s.rs[1].HostName != "other.example" {
		t.Errorf("inserted %+v", s.rs)
	}
}

func TestEnrichBudget(t *testing.T) {
	e, l, g, _ := testEnricher(2)
	g.used = 1
	g.fetched["d:c.example"] = now
	sum, err := e.Enrich(context.Background(), []string{"d:a.example", "d:b.example", "d:c.example", "d:d.example"})
	if err != nil {
		t.Fatal(err)
	}
	if want := (Summary{LookedUp: 1, Cached: 1, SkippedBudget: 2, StoppedReason: StopDailyBudget}); sum != want {
		t.Errorf("summary = %+v, want %+v", sum, want)
	}
	if len(l.calls) != 1 || g.used != 2 {
		t.Errorf("%d lookups, %d counted, want 1 and 2", len(l.calls), g.used)
	}
}

func TestEnrichCallCap(t *testing.T) {
	e, l, _, _ := testEnricher(1000)
	var objects []string
	for i := range MaxLookups + 2 {
		objects = append(objects, fmt.Sprintf("d:n%03d.example", i))
	}
	sum, err := e.Enrich(context.Background(), objects)
	if err != nil {
		t.Fatal(err)
	}
	if sum.LookedUp != MaxLookups || sum.SkippedBudget != 2 || sum.StoppedReason != StopCallCap || len(l.calls) != MaxLookups {
		t.Errorf("summary = %+v, %d lookups", sum, len(l.calls))
	}
}

func TestEnrichQuota(t *testing.T) {
	e, l, g, _ := testEnricher(500)
	l.errs["d:b.example"] = fmt.Errorf("%w (QuotaExceededError)", ErrQuota)
	sum, err := e.Enrich(context.Background(), []string{"d:a.example", "d:b.example", "d:c.example", "d:d.example"})
	if err != nil {
		t.Fatal(err)
	}
	if want := (Summary{LookedUp: 2, SkippedBudget: 2, StoppedReason: StopQuota}); sum != want {
		t.Errorf("summary = %+v, want %+v", sum, want)
	}
	if !slices.Equal(l.calls, []string{"d:a.example", "d:b.example"}) {
		t.Errorf("lookups = %v", l.calls)
	}
	if _, ok := g.records["d:b.example"]; ok {
		t.Error("a quota error is recorded as a fetch")
	}
}

func TestEnrichAPIErrorStops(t *testing.T) {
	e, l, g, _ := testEnricher(500)
	l.errs["d:a.example"] = &APIError{Status: 401, Code: "WrongCredentialsError"}
	sum, err := e.Enrich(context.Background(), []string{"d:a.example", "d:b.example"})
	if err != nil {
		t.Fatal(err)
	}
	if sum.LookedUp != 1 || sum.SkippedBudget != 1 || sum.StoppedReason != "VirusTotal error 401 WrongCredentialsError" {
		t.Errorf("summary = %+v", sum)
	}
	if g.records["d:a.example"] != "error/0" {
		t.Errorf("fetch of d:a.example = %q, want error/0", g.records["d:a.example"])
	}
}

func TestPublic(t *testing.T) {
	for addr, want := range map[string]bool{
		"93.184.215.14": true, "2606:2800:21f:cb07:6820:80da:af6b:8b2c": true,
		"10.1.2.3": false, "127.0.0.1": false, "169.254.1.1": false, "100.64.0.1": false,
		"192.0.2.1": false, "224.0.0.1": false, "::1": false, "fe80::1": false, "fd00::1": false,
		"2001:db8::1": false, "::ffff:192.168.1.1": false,
	} {
		if got := Public(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Public(%s) = %v, want %v", addr, got, want)
		}
	}
}
