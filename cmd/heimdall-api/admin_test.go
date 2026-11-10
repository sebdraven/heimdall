package main

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/sebdraven/heimdall/internal/store/pg"
)

func TestCDNProviderCounts(t *testing.T) {
	prefixes := []pg.CDNPrefix{
		{ID: 1, Prefix: netip.MustParsePrefix("104.16.0.0/13"), Provider: "Cloudflare", Source: "seed"},
		{ID: 2, Prefix: netip.MustParsePrefix("2606:4700::/32"), Provider: "Cloudflare", Source: "seed"},
		{ID: 3, Prefix: netip.MustParsePrefix("151.101.0.0/16"), Provider: "Fastly", Source: "sync:fastly"},
		{ID: 4, Prefix: netip.MustParsePrefix("199.232.0.0/16"), Provider: "Fastly", Source: "sync:fastly"},
		{ID: 5, Prefix: netip.MustParsePrefix("192.0.2.0/24"), Provider: "Fastly", Source: "manual"},
		{ID: 6, Prefix: netip.MustParsePrefix("2a06:98c0::/29"), Provider: "Cloudflare", Source: "sync:cloudflare"},
	}
	counts := cdnProviderCounts(prefixes)
	if got := encode(t, counts); got != `[{"Provider":"Cloudflare","Count":3,"Sources":[{"Source":"seed","Count":2},{"Source":"sync:cloudflare","Count":1}]},`+
		`{"Provider":"Fastly","Count":3,"Sources":[{"Source":"manual","Count":1},{"Source":"sync:fastly","Count":2}]}]` {
		t.Errorf("counts = %s", got)
	}

	body := renderPage(t, "admin", map[string]any{"CDNPrefixes": prefixes, "CDNProviders": counts})
	for _, want := range []string{
		"<td>Fastly</td>\n      <td>3</td>\n      <td><code>manual</code> 1, <code>sync:fastly</code> 2</td>",
		"<td>sync:fastly</td>",
		"<td>sync:cloudflare</td>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("admin page lacks %q", want)
		}
	}
	if strings.Contains(body, "style=") {
		t.Error("style attribute in the admin page")
	}
}
