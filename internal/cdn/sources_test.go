package cdn

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func parseFixture(t *testing.T, parse func(io.Reader) ([]netip.Prefix, error), name string) string {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ps, err := parse(f)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return fmt.Sprint(SortPrefixes(ps))
}

func TestParseFixtures(t *testing.T) {
	for _, tt := range []struct {
		name  string
		parse func(io.Reader) ([]netip.Prefix, error)
		want  string
	}{
		{"cloudflare-ips-v4", ParseCloudflare, "[103.21.244.0/22 104.16.0.0/13 173.245.48.0/20]"},
		// The v6 list has no final newline.
		{"cloudflare-ips-v6", ParseCloudflare, "[2400:cb00::/32 2606:4700::/32]"},
		{"fastly-public-ip-list.json", ParseFastly, "[23.235.32.0/20 43.249.72.0/22 151.101.0.0/16 2a04:4e40::/32 2a04:4e42::/31]"},
		// AMAZON entries are left out, 13.32.0.0/15 is listed under both services.
		{"aws-ip-ranges.json", ParseCloudFront, "[13.32.0.0/15 52.84.0.0/15 2600:9000::/28]"},
		{"bunny-edgeserverlist.json", ParseBunny, "[89.187.188.227/32 89.187.188.228/32 185.102.217.65/32]"},
		{"bunny-edgeserverlist-ipv6.json", ParseBunny, "[2400:52e0:1500::714:1/128 2400:52e0:1500::715:1/128]"},
		{"ripestat-announced-prefixes.json", ParseRIPEStat, "[104.21.32.0/20 104.23.208.0/24 2a06:98c1:3120::/48]"},
	} {
		if got := parseFixture(t, tt.parse, tt.name); got != tt.want {
			t.Errorf("%s = %s, want %s", tt.name, got, tt.want)
		}
	}
}

func TestParseInvalid(t *testing.T) {
	for _, tt := range []struct {
		name  string
		parse func(io.Reader) ([]netip.Prefix, error)
		body  string
		want  string
	}{
		{"cloudflare host bits", ParseCloudflare, "192.0.2.0/24\n192.0.2.1/24\n", "1 invalid prefix(es)"},
		{"cloudflare html", ParseCloudflare, "<html>error</html>", "invalid prefix"},
		{"fastly not json", ParseFastly, "addresses", "invalid character"},
		{"fastly bad value", ParseFastly, `{"addresses":["x"],"ipv6_addresses":[]}`, `invalid prefix "x"`},
		{"cloudfront bad value", ParseCloudFront, `{"prefixes":[{"ip_prefix":"13.32.0.1/15","service":"CLOUDFRONT"}]}`, "has host bits set"},
		{"bunny prefix", ParseBunny, `["192.0.2.0/24"]`, `1 invalid address(es): "192.0.2.0/24"`},
		{"bunny object", ParseBunny, `{"error":"x"}`, "cannot unmarshal"},
		{"ripestat error", ParseRIPEStat, `{"status":"error","data":{}}`, `RIPEstat status "error"`},
	} {
		_, err := tt.parse(strings.NewReader(tt.body))
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, want %q", tt.name, err, tt.want)
		}
	}
}

func TestFetch(t *testing.T) {
	var agents []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agents = append(agents, r.UserAgent())
		switch r.URL.Path {
		case "/v4":
			fmt.Fprint(w, "192.0.2.0/24\n198.51.100.0/24\n")
		case "/v6":
			fmt.Fprint(w, "2001:db8::/32\n192.0.2.0/24\n")
		case "/empty":
		default:
			http.Error(w, "no", http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()
	ctx := context.Background()

	src := Source{Name: "x", Provider: "X", URLs: []string{srv.URL + "/v4", srv.URL + "/v6"}, Parse: ParseCloudflare}
	got, err := Fetch(ctx, srv.Client(), src)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got) != "[192.0.2.0/24 198.51.100.0/24 2001:db8::/32]" {
		t.Errorf("prefixes = %v, merged and unique", got)
	}
	if strings.Join(agents, " ") != "heimdall heimdall" {
		t.Errorf("user agents = %v, want heimdall", agents)
	}

	src.URLs = []string{srv.URL + "/v4", srv.URL + "/down"}
	if _, err := Fetch(ctx, srv.Client(), src); err == nil || !strings.Contains(err.Error(), "/down: HTTP 503") {
		t.Errorf("one URL down: err = %v", err)
	}
	src.URLs = []string{srv.URL + "/empty"}
	if _, err := Fetch(ctx, srv.Client(), src); err == nil || err.Error() != "no prefix listed" {
		t.Errorf("empty list: err = %v", err)
	}
}

func TestSources(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range Sources {
		if s.Name != strings.ToLower(s.Name) || seen[s.Name] || s.Provider == "" || len(s.URLs) == 0 || s.Parse == nil {
			t.Errorf("source %+v", s)
		}
		seen[s.Name] = true
	}
	a := ASNSource(13335, "Cloudflare")
	if a.Name != "cloudflare" || a.Provider != "Cloudflare" || a.URLs[0] != "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS13335" {
		t.Errorf("asn source = %+v", a)
	}
}
