package main

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sebdraven/heimdall/internal/cdn"
	"github.com/sebdraven/heimdall/internal/store/ch"
	"github.com/sebdraven/heimdall/internal/store/pg"
)

const vtEndpoint = "/graph/domain/www.x.example/vt?depth=1"

func vtPeriod(first, last time.Duration) ch.Period {
	return ch.Period{First: t0.Add(first), Last: t0.Add(last)}
}

func domainPageData(vt *vtView) map[string]any {
	return map[string]any{
		"FQDN": "www.x.example", "Domain": (*pg.Domain)(nil), "Sharing": map[string]uint64{},
		"PDNS": []ch.PDNSRecord{{RRName: "www.x.example", RRType: "A", RData: "192.0.2.1", FirstSeen: t0, LastSeen: t0}},
		"VT":   vt,
	}
}

func TestRenderDomainVT(t *testing.T) {
	s := testServer(t)
	s.cdn.Set([]cdn.Prefix{{Prefix: netip.MustParsePrefix("104.16.0.0/13"), Provider: "Cloudflare"}})

	body := renderWith(t, s, "domain", domainPageData(nil))
	if strings.Contains(body, "VirusTotal") || strings.Contains(body, "vtjob.js") {
		t.Error("domain page has a VirusTotal section without VirusTotal configured")
	}

	body = renderWith(t, s, "domain", domainPageData(&vtView{Endpoint: vtEndpoint}))
	for _, want := range []string{
		"<h2>VirusTotal</h2>", "not looked up yet", "No VirusTotal resolution cached.",
		`<p class="notice" id="vt-job" data-endpoint="` + vtEndpoint + `" hidden></p>`,
		`<script src="/static/vtjob.js" defer></script>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("empty cache: domain page lacks %q", want)
		}
	}
	if strings.Contains(body, "Enrich with VT") {
		t.Error("Enrich with VT offered without the analyst role")
	}

	v := domainVTView(pg.VTFetch{FetchedAt: t0, Status: "ok", Count: 3}, []ch.VTPair{
		{HostName: "www.x.example", IP: "198.51.100.7", Period: vtPeriod(-48*time.Hour, -time.Hour)},
		{HostName: "www.x.example", IP: "192.0.2.1", Period: vtPeriod(-72*time.Hour, -2*time.Hour)},
		{HostName: "www.x.example", IP: "104.16.0.1", Period: vtPeriod(-96*time.Hour, -3*time.Hour)},
	}, domainPageData(nil)["PDNS"].([]ch.PDNSRecord))
	v.Endpoint = vtEndpoint
	body = renderWith(t, s, "domain", domainPageData(v))
	for _, want := range []string{
		"last looked up 2026-03-01 12:00:00 (ok)",
		`<td><a href="/rdata/198.51.100.7"><code>198.51.100.7</code></a></td>`,
		`<td class="nowrap">2026-02-27 12:00:00</td>`, `<td class="nowrap">2026-03-01 11:00:00</td>`,
		`<td> <span class="badge">also seen by Heimdall</span></td>`,
		`<td> <span class="cdn">CDN Cloudflare</span></td>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("cached resolutions: domain page lacks %q", want)
		}
	}
	if n := strings.Count(body, "also seen by Heimdall"); n != 1 {
		t.Errorf("%d Heimdall badges, want 1", n)
	}
	if strings.Index(body, "198.51.100.7</code>") > strings.Index(body, "104.16.0.1</code>") {
		t.Error("VirusTotal rows not in the store's order, latest first")
	}
}

func TestRenderRdataVT(t *testing.T) {
	if body := renderPage(t, "rdata", rdataFixture(rdataLimit)); strings.Contains(body, "VirusTotal") {
		t.Error("rdata page has a VirusTotal section without VirusTotal configured")
	}

	v := buildRdataView("198.51.100.7", nil, nil, rdataLimit)
	v.VT = rdataVTView(pg.VTFetch{FetchedAt: t0, Status: "ok", Count: 2}, []ch.VTPair{
		{HostName: "z.example", IP: "198.51.100.7", Period: vtPeriod(-48*time.Hour, -time.Hour)},
		{HostName: "a.example", IP: "198.51.100.7", Period: vtPeriod(-72*time.Hour, -2*time.Hour)},
	}, map[string]pg.Domain{"a.example": {FQDN: "a.example"}})
	body := renderPage(t, "rdata", v)
	for _, want := range []string{
		"<h2>VirusTotal</h2>", "last looked up 2026-03-01 12:00:00 (ok)",
		`<td><a href="/domains/z.example">z.example</a></td>`,
		`<td><span class="badge">watched</span></td>`,
		`<td class="nowrap">2026-02-26 12:00:00</td>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("rdata page lacks %q", want)
		}
	}
	if n := strings.Count(body, `<span class="badge">watched</span>`); n != 1 {
		t.Errorf("%d watched badges, want 1", n)
	}
	if strings.Contains(body, "Enrich with VT") {
		t.Error("rdata page offers an enrichment")
	}

	v.VT = rdataVTView(pg.VTFetch{}, nil, nil)
	if body := renderPage(t, "rdata", v); !strings.Contains(body, "not looked up yet") || !strings.Contains(body, "No VirusTotal resolution cached.") {
		t.Error("rdata page: empty cache not shown")
	}
}
