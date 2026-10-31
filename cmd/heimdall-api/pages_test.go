package main

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gjallarhorn "github.com/sebdraven/heimdall/internal/changes"
	"github.com/sebdraven/heimdall/internal/config"
	"github.com/sebdraven/heimdall/internal/store/ch"
	"github.com/sebdraven/heimdall/internal/store/pg"
)

var t0 = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func rdataFixture(limit int) rdataView {
	campaign := int64(7)
	records := []ch.PDNSRecord{
		{RRName: "a.example", RRType: "A", RData: "192.0.2.1", FirstSeen: t0, LastSeen: t0.Add(time.Hour), Count: 3},
		{RRName: "b.example", RRType: "A", RData: "192.0.2.1", FirstSeen: t0, LastSeen: t0.Add(3 * time.Hour), Count: 5},
		{RRName: "c.example", RRType: "A", RData: "192.0.2.1", FirstSeen: t0, LastSeen: t0.Add(2 * time.Hour), Count: 1},
		{RRName: "b.example", RRType: "TXT", RData: "192.0.2.1", FirstSeen: t0, LastSeen: t0, Count: 1},
	}
	watched := map[string]pg.Domain{
		"a.example": {FQDN: "a.example", CampaignID: &campaign, Campaign: "spynote"},
		"c.example": {FQDN: "c.example"},
	}
	return buildRdataView("192.0.2.1", records, watched, limit)
}

func TestBuildRdataView(t *testing.T) {
	v := rdataFixture(rdataLimit)
	if v.Truncated {
		t.Error("4 records under a limit of 1000 flagged as truncated")
	}
	if !rdataFixture(4).Truncated {
		t.Error("result of exactly the limit not flagged as truncated")
	}
	var order []string
	for _, r := range v.Rows {
		order = append(order, r.RRName+"/"+r.RRType)
	}
	if got, want := strings.Join(order, " "), "b.example/A c.example/A a.example/A b.example/TXT"; got != want {
		t.Errorf("order = %s, want %s", got, want)
	}
	if v.Names != 3 || v.Outside != 1 {
		t.Errorf("names %d outside %d, want 3 and 1", v.Names, v.Outside)
	}
	for _, r := range v.Rows {
		if watched := r.Domain != nil; watched == (r.RRName == "b.example") {
			t.Errorf("%s: watched = %v", r.RRName, watched)
		}
	}
}

func testServer(t *testing.T) *server {
	t.Helper()
	s, err := newServer(&config.Config{}, slog.New(slog.DiscardHandler), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func renderPage(t *testing.T, page string, data any) string {
	t.Helper()
	rec := httptest.NewRecorder()
	testServer(t).render(rec, httptest.NewRequest(http.MethodGet, "/", nil), page, http.StatusOK, data)
	if rec.Code != http.StatusOK {
		t.Fatalf("render %s: status %d: %s", page, rec.Code, rec.Body)
	}
	return rec.Body.String()
}

func TestRenderRdataPage(t *testing.T) {
	body := renderPage(t, "rdata", rdataFixture(rdataLimit))
	for _, want := range []string{
		"3 distinct names", "1 outside the watchlist",
		`href="/domains/b.example"`, `href="/campaigns/7"`, ">spynote<",
		"watched, no campaign", "<td>—</td>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("rdata page lacks %q", want)
		}
	}
	if strings.Contains(body, "counts are partial") {
		t.Error("truncation notice shown for a complete result")
	}
	if body := renderPage(t, "rdata", rdataFixture(4)); !strings.Contains(body, "limited to the 4 most recent records, counts are partial") {
		t.Error("truncation notice missing")
	}
}

func TestSharingQuery(t *testing.T) {
	values, exclude := sharingQuery("www.x.example", []ch.Current{
		{QType: "CNAME", Rdata: []string{"CDN.Y.example."}},
		{QType: "A", Rdata: []string{"192.0.2.2", "192.0.2.1"}},
		{QType: "A", Resolver: "1.1.1.1:53", Rdata: []string{"192.0.2.1"}},
	})
	if got, want := strings.Join(values, " "), "192.0.2.1 192.0.2.2 CDN.Y.example."; got != want {
		t.Errorf("values = %s, want %s", got, want)
	}
	if got, want := strings.Join(exclude, " "), "cdn.y.example www.x.example"; got != want {
		t.Errorf("exclude = %s, want %s", got, want)
	}
}

func TestRenderDomainLinks(t *testing.T) {
	body := renderPage(t, "domain", map[string]any{
		"FQDN":   "www.x.example",
		"Domain": (*pg.Domain)(nil),
		"Current": []ch.Current{
			{QType: "A", Resolver: "9.9.9.9:53", Rcode: "NOERROR", Rdata: []string{"192.0.2.1"}},
			{QType: "TXT", Resolver: "9.9.9.9:53", Rcode: "NOERROR", Rdata: []string{`"v=spf1 -all"`}},
		},
		"Changes": []gjallarhorn.Change{{Added: []string{"192.0.2.2"}, Removed: []string{"192.0.2.3"}}},
		"PDNS": []ch.PDNSRecord{
			{RRName: "www.x.example", RRType: "CNAME", RData: "cdn.y.example"},
			{RRName: "cdn.y.example", RRType: "A", RData: "192.0.2.1"},
		},
		"Sharing": map[string]uint64{"192.0.2.1": 2},
	})
	for _, want := range []string{
		`href="/rdata/192.0.2.1"`, `href="/rdata/192.0.2.2"`, `href="/rdata/192.0.2.3"`,
		`href="/rdata/cdn.y.example"`, `href="/rdata/%22v=spf1%20-all%22"`,
		`<span class="badge">2 names</span>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("domain page lacks %q", want)
		}
	}
	if n := strings.Count(body, `class="badge"`); n != 1 {
		t.Errorf("%d badges, want 1 (none for values held by no other name)", n)
	}
}
