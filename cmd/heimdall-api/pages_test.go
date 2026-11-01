package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sebdraven/heimdall/internal/cdn"
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

func testCDN() *cdn.Classifier {
	return cdn.New([]cdn.Prefix{
		{Prefix: netip.MustParsePrefix("104.16.0.0/13"), Provider: "Cloudflare"},
		{Prefix: netip.MustParsePrefix("2606:4700::/32"), Provider: "Cloudflare"},
	})
}

func renderPage(t *testing.T, page string, data any) string {
	t.Helper()
	return renderWith(t, testServer(t), page, data)
}

func renderWith(t *testing.T, s *server, page string, data any) string {
	t.Helper()
	rec := httptest.NewRecorder()
	s.render(rec, httptest.NewRequest(http.MethodGet, "/", nil), page, http.StatusOK, data)
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
		{QType: "A", Resolver: "8.8.8.8:53", Rdata: []string{"104.16.0.1"}},
	}, testCDN())
	if got, want := strings.Join(values, " "), "192.0.2.1 192.0.2.2 CDN.Y.example."; got != want {
		t.Errorf("values = %s, want %s", got, want)
	}
	if got, want := strings.Join(exclude, " "), "cdn.y.example www.x.example"; got != want {
		t.Errorf("exclude = %s, want %s", got, want)
	}
}

func TestRenderCDN(t *testing.T) {
	s := testServer(t)
	s.cdn.Set([]cdn.Prefix{{Prefix: netip.MustParsePrefix("104.16.0.0/13"), Provider: "Cloudflare"}})
	const marker = `<span class="cdn">CDN Cloudflare</span>`

	body := renderWith(t, s, "domain", map[string]any{
		"FQDN": "www.x.example", "Domain": (*pg.Domain)(nil),
		"Current": []ch.Current{{QType: "A", Resolver: "9.9.9.9:53", Rcode: "NOERROR", Rdata: []string{"104.16.0.1", "192.0.2.1"}}},
		"Changes": []gjallarhorn.Change{{Key: gjallarhorn.Key{Domain: "www.x.example", QType: "A"}, Added: []string{"104.16.0.1"}, Removed: []string{"192.0.2.3"}}},
		"Sharing": map[string]uint64{"104.16.0.1": 40, "192.0.2.1": 2},
	})
	if n := strings.Count(body, marker); n != 2 {
		t.Errorf("domain page: %d CDN markers, want 2 (current state and timeline)", n)
	}
	if !strings.Contains(body, `<span class="badge">2 names</span>`) || strings.Contains(body, "40 names") {
		t.Error("domain page: sharing badge missing for 192.0.2.1 or shown for a CDN address")
	}

	body = renderWith(t, s, "rdata", buildRdataView("104.16.0.1", nil, nil, rdataLimit))
	if !strings.Contains(body, `<p class="notice">CDN address (Cloudflare): sharing it is not an infrastructure link</p>`) {
		t.Error("rdata page: CDN banner missing")
	}
	if body := renderWith(t, s, "rdata", rdataFixture(rdataLimit)); strings.Contains(body, "CDN address") {
		t.Error("rdata page: CDN banner on a non-CDN address")
	}

	body = renderWith(t, s, "search", searchView{Query: "104.16", Kind: "pattern", Limit: searchLimit, Values: []ch.ValueMatch{
		{RData: "104.16.0.1", RRType: "A", Names: 3},
		{RData: "192.0.2.1", RRType: "A", Names: 1},
		{RData: "cdn.example", RRType: "CNAME", Names: 1},
	}})
	if n := strings.Count(body, marker); n != 1 {
		t.Errorf("search page: %d CDN markers, want 1", n)
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

func TestLikePattern(t *testing.T) {
	tests := []struct {
		q    string
		want string
		ok   bool
	}{
		{"otax", "%otax%", true},
		{"*.otax.fun", "%.otax.fun", true},
		{"node*", "node%", true},
		{"node*.otax.*", "node%.otax.%", true},
		{"a_b%c", `%a\_b\%c%`, true},
		{"_dmarc*", `\_dmarc%`, true},
		{`a\b`, `%a\\b%`, true},
		{"ab", "", false},
		{"*a*b*", "", false},
		{"***", "", false},
		{"é.f", "%é.f%", true},
	}
	for _, tt := range tests {
		got, ok := likePattern(tt.q)
		if got != tt.want || ok != tt.ok {
			t.Errorf("likePattern(%q) = %q, %v; want %q, %v", tt.q, got, ok, tt.want, tt.ok)
		}
	}
}

func searchFixture(limit int) searchView {
	campaign := int64(7)
	spynote := pg.Domain{FQDN: "node1.otax.fun", CampaignID: &campaign, Campaign: "spynote", IntervalSeconds: 300, Enabled: true}
	return searchView{
		Query: "otax", Kind: "pattern", Limit: limit,
		Domains: []pg.Domain{spynote, {FQDN: "node2.otax.fun", IntervalSeconds: 600}},
		Names: []nameRow{
			{NameMatch: ch.NameMatch{RRName: "node1.otax.fun", RRTypes: []string{"A", "NS"}, FirstSeen: t0, LastSeen: t0.Add(time.Hour), Count: 12}, Domain: &spynote},
			{NameMatch: ch.NameMatch{RRName: "cdn.otax.fun", RRTypes: []string{"CNAME"}, FirstSeen: t0, LastSeen: t0, Count: 1}},
		},
		Values: []ch.ValueMatch{
			{RData: "ns1.otax.fun", RRType: "NS", Names: 2, FirstSeen: t0, LastSeen: t0.Add(time.Hour)},
		},
		Truncated: searchTruncated{Names: limit == 2},
	}
}

func TestRenderSearchPage(t *testing.T) {
	body := renderPage(t, "search", searchFixture(searchLimit))
	for _, want := range []string{
		"<h2>Watchlist</h2>", "<h2>Passive DNS names</h2>", "<h2>Passive DNS values</h2>",
		`href="/domains/node1.otax.fun"`, `href="/domains/node2.otax.fun"`, `href="/domains/cdn.otax.fun"`,
		`href="/campaigns/7"`, ">spynote<", "A, NS", "600s",
		`href="/rdata/ns1.otax.fun"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("search page lacks %q", want)
		}
	}
	if strings.Contains(body, "Limited to") {
		t.Error("truncation notice shown for a complete result")
	}

	body = renderPage(t, "search", searchFixture(2))
	if !strings.Contains(body, "Limited to the 2 most recently seen names.") {
		t.Error("names truncation notice missing")
	}
	if n := strings.Count(body, "Limited to"); n != 1 {
		t.Errorf("%d truncation notices, want 1", n)
	}

	body = renderPage(t, "search", searchView{Query: "ab", TooShort: true, Limit: searchLimit})
	if !strings.Contains(body, "at least 3 characters") || strings.Contains(body, "<table>") {
		t.Error("too short query: message missing or tables shown")
	}

	body = renderPage(t, "search", searchView{Limit: searchLimit})
	if strings.Contains(body, "<table>") || strings.Contains(body, "at least 3 characters") {
		t.Error("empty query renders results or an error")
	}
}

func TestCurrentZoneRecords(t *testing.T) {
	soa := func(serial string, last time.Time) ch.PDNSRecord {
		return ch.PDNSRecord{RRName: "syamcloud.com", RRType: "SOA", RData: "ns1.syamcloud.com h.syamcloud.com " + serial + " 7200 3600 1209600 300", LastSeen: last}
	}
	ns := func(v string, last time.Time) ch.PDNSRecord {
		return ch.PDNSRecord{RRName: "syamcloud.com", RRType: "NS", RData: v, LastSeen: last}
	}
	now := t0.Add(48 * time.Hour)
	got := currentZoneRecords([]ch.PDNSRecord{
		soa("1", t0), soa("2", now), ns("old.example.net", t0), ns("ns2.example.net", now.Add(-10*time.Minute)), ns("ns1.example.net", now),
		{RRName: "syamcloud.com", RRType: "A", RData: "192.0.2.1", LastSeen: now},
	})
	var order []string
	for _, r := range got {
		order = append(order, r.RRType+"/"+strings.Fields(r.RData)[0])
	}
	if got, want := strings.Join(order, " "), "NS/ns1.example.net NS/ns2.example.net SOA/ns1.syamcloud.com"; got != want {
		t.Errorf("current = %s, want %s", got, want)
	}
	if len(got) == 3 && !strings.Contains(got[2].RData, " 2 ") {
		t.Errorf("SOA = %q, want serial 2", got[2].RData)
	}
	if got := currentZoneRecords([]ch.PDNSRecord{{RRType: "A", RData: "192.0.2.1"}}); len(got) != 0 {
		t.Errorf("no NS or SOA: %+v", got)
	}
}

func TestRenderDomainZone(t *testing.T) {
	data := map[string]any{
		"FQDN": "proxy.syamcloud.com", "Domain": (*pg.Domain)(nil), "Sharing": map[string]uint64{},
		"Zone": &zoneView{Name: "syamcloud.com", Records: []ch.PDNSRecord{
			{RRName: "syamcloud.com", RRType: "NS", RData: "ns1.example.net", LastSeen: t0},
			{RRName: "syamcloud.com", RRType: "SOA", RData: "ns1.syamcloud.com h.syamcloud.com 2 7200 3600 1209600 300", LastSeen: t0},
		}},
	}
	body := renderPage(t, "domain", data)
	for _, want := range []string{
		"<h2>Zone</h2>", `href="/domains/syamcloud.com"`, `href="/rdata/ns1.example.net"`,
		`href="/rdata/ns1.syamcloud.com%20h.syamcloud.com%202%207200%203600%201209600%20300"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("domain page lacks %q", want)
		}
	}
	if strings.Contains(body, `class="badge"`) {
		t.Error("badge in the zone block")
	}
	if strings.Contains(body, "Same NS set") {
		t.Error("NS set line shown without ns pairs")
	}
	data["Zone"] = (*zoneView)(nil)
	if body := renderPage(t, "domain", data); strings.Contains(body, "<h2>Zone</h2>") {
		t.Error("zone block shown for an apex")
	}
}

func TestRenderNSPairs(t *testing.T) {
	overlap := ch.Period{First: t0.Add(time.Hour), Last: t0.Add(2 * time.Hour)}
	pairs := &nsPairsView{Zone: "syamcloud.com", NS: []string{"a.ns.example", "b.ns.example"}, Matches: []ch.NSPairPivot{
		{Domain: "other.example", Overlap: &overlap},
		{Domain: "later.example"},
	}}
	data := map[string]any{
		"FQDN": "proxy.syamcloud.com", "Domain": (*pg.Domain)(nil), "Sharing": map[string]uint64{},
		"Zone":    &zoneView{Name: "syamcloud.com"},
		"NSPairs": pairs,
	}
	body := renderPage(t, "domain", data)
	if want := `Same NS set: <a href="/domains/other.example">other.example</a> (2026-03-01 13:00:00 → 2026-03-01 14:00:00) · ` +
		`<a href="/domains/later.example">later.example</a> (no overlap)</p>`; !strings.Contains(body, want) {
		t.Errorf("domain page lacks %q", want)
	}

	pairs.Matches = nil
	if body := renderPage(t, "domain", data); !strings.Contains(body, "Same NS set: no other zone</p>") {
		t.Error("empty match list not reported")
	}

	data["Zone"] = (*zoneView)(nil)
	body = renderPage(t, "domain", data)
	if !strings.Contains(body, "<h2>Zone</h2>") || !strings.Contains(body, "Same NS set: no other zone") || strings.Contains(body, "Enclosing zone") {
		t.Error("apex: NS set line missing, or enclosing zone shown")
	}

	data["NSPairs"] = (*nsPairsView)(nil)
	if body := renderPage(t, "domain", data); strings.Contains(body, "Same NS set") || strings.Contains(body, "<h2>Zone</h2>") {
		t.Error("NS set line or zone block shown with null ns pairs")
	}
}

func TestDomainLink(t *testing.T) {
	for in, want := range map[string]string{
		"x.example":          `<a href="/domains/x.example">x.example</a>`,
		"zone:syamcloud.com": `<a href="/domains/syamcloud.com">zone syamcloud.com</a>`,
		`a"<b>.example`:      `<a href="/domains/a%22%3Cb%3E.example">a&#34;&lt;b&gt;.example</a>`,
	} {
		if got := string(domainLink(in)); got != want {
			t.Errorf("domainLink(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestRenderZoneTuples(t *testing.T) {
	body := renderPage(t, "events", map[string]any{
		"Events": []gjallarhorn.Event{{TS: t0, Domain: "zone:syamcloud.com", Kind: gjallarhorn.KindNSSinkhole, QType: "NS"}},
		"Kinds": gjallarhorn.Kinds, "Filter": ch.EventFilter{}, "Since": "168h", "Until": "",
	})
	if !strings.Contains(body, `<a href="/domains/syamcloud.com">zone syamcloud.com</a>`) || strings.Contains(body, "zone:") {
		t.Error("events page does not link the zone tuple to its zone")
	}

	body = renderPage(t, "domain", map[string]any{
		"FQDN": "syamcloud.com", "Domain": (*pg.Domain)(nil), "Sharing": map[string]uint64{},
		"Changes": []gjallarhorn.Change{
			{TS: t0.Add(time.Minute), Key: gjallarhorn.Key{Domain: "zone:syamcloud.com", QType: "NS"}, Added: []string{"ns1.sinkhole.example"}},
			{TS: t0, Key: gjallarhorn.Key{Domain: "syamcloud.com", QType: "A"}},
		},
	})
	if !strings.Contains(body, `NS · <a href="/domains/syamcloud.com">zone syamcloud.com</a>`) {
		t.Error("zone change not marked in the timeline")
	}
	if strings.Count(body, "zone syamcloud.com") != 1 {
		t.Error("own change marked as a zone change")
	}
}

func TestMergeChanges(t *testing.T) {
	change := func(domain string, minutes int) gjallarhorn.Change {
		return gjallarhorn.Change{TS: t0.Add(time.Duration(minutes) * time.Minute), Key: gjallarhorn.Key{Domain: domain}}
	}
	got := mergeChanges(
		[]gjallarhorn.Change{change("x", 5), change("x", 1)},
		[]gjallarhorn.Change{change("zone:x", 3), change("zone:x", 0)},
		3,
	)
	var order []string
	for _, c := range got {
		order = append(order, fmt.Sprintf("%s@%d", c.Domain, int(c.TS.Sub(t0).Minutes())))
	}
	if got, want := strings.Join(order, " "), "x@5 zone:x@3 x@1"; got != want {
		t.Errorf("merged = %s, want %s", got, want)
	}
}
