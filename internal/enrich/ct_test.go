package enrich

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	shaA = "6f1a0e4b5c3d2e1f00112233445566778899aabbccddeeff0123456789abcdef"
	shaB = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
	shaC = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
)

func ctServer(t *testing.T, key string, h http.HandlerFunc) *CTClient {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return NewCTClient(srv.URL+"/", key)
}

func issuanceJSON(id, sha, notBefore string, names ...string) map[string]any {
	return map[string]any{
		"id": id, "tbs_sha256": strings.Repeat("0", 64), "cert_sha256": sha, "dns_names": names,
		"pubkey_sha256": strings.Repeat("1", 64),
		"issuer":        map[string]any{"friendly_name": "Let's Encrypt", "name": "C=US, O=Let's Encrypt, CN=R3"},
		"not_before":    notBefore, "not_after": "2026-12-31T00:00:00Z", "revoked": false,
	}
}

func TestCTLookupPages(t *testing.T) {
	var mu sync.Mutex
	var afters []string
	c := ctServer(t, "", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if r.URL.Path != "/v1/issuances" || q.Get("domain") != "x.example" || q.Get("include_subdomains") != "true" ||
			!slices.Equal(q["expand"], []string{"dns_names", "issuer"}) {
			t.Errorf("query %s", r.URL)
		}
		if ua := r.Header.Get("User-Agent"); ua != "heimdall" {
			t.Errorf("User-Agent %q", ua)
		}
		if auth := r.Header.Get("Authorization"); auth != "" {
			t.Errorf("Authorization %q sent without a key", auth)
		}
		mu.Lock()
		afters = append(afters, q.Get("after"))
		mu.Unlock()
		page := []map[string]any{}
		switch q.Get("after") {
		case "":
			other := issuanceJSON("101", shaB, "2026-03-01T00:00:00Z", "API.x.example.")
			other["issuer"] = map[string]any{"name": "CN=Other CA"}
			other["revoked"] = true
			page = []map[string]any{
				issuanceJSON("100", shaA, "2026-01-01T00:00:00Z", "WWW.X.example.", "*.x.example", "www.x.example"),
				other,
			}
		case "101":
			page = []map[string]any{issuanceJSON("102", shaC, "2026-03-01T00:00:00+01:00", "mail.x.example")}
		}
		_ = json.NewEncoder(w).Encode(page)
	})
	ct, err := c.Lookup(context.Background(), "x.example")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(afters, []string{"", "101", "102"}) {
		t.Errorf("pages after %q, want the first page, then after 101 and 102", afters)
	}
	if ct.Zone != "x.example" || ct.Total != 3 || ct.Truncated || len(ct.Certificates) != 3 {
		t.Fatalf("ct = %+v, want 3 certificates", ct)
	}
	var ids []string
	for _, cert := range ct.Certificates {
		ids = append(ids, cert.ID)
	}
	if got := strings.Join(ids, " "); got != "101 102 100" {
		t.Errorf("order %s, want not_before descending, then id", got)
	}
	old := ct.Certificates[2]
	if old.CertSHA256 != shaA || len(old.CertSHA256) != 64 {
		t.Errorf("sha256 %q, want the full %s", old.CertSHA256, shaA)
	}
	if got := strings.Join(old.Names, " "); got != "*.x.example www.x.example" {
		t.Errorf("names of 100 = %s", got)
	}
	if old.Issuer != "Let's Encrypt" || old.Revoked || !old.NotBefore.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) ||
		!old.NotAfter.Equal(time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("certificate 100 = %+v", old)
	}
	if other := ct.Certificates[0]; other.Issuer != "CN=Other CA" || !other.Revoked || other.CertSHA256 != shaB {
		t.Errorf("certificate 101 = %+v, want the issuer name and revoked", other)
	}
	if loc := ct.Certificates[1].NotBefore.Location(); loc != time.UTC {
		t.Errorf("not_before in %s, want UTC", loc)
	}
	if got := strings.Join(ct.Names, " "); got != "*.x.example api.x.example mail.x.example www.x.example" {
		t.Errorf("names = %s", got)
	}
}

func TestCTCap(t *testing.T) {
	const pageSize = 120
	var mu sync.Mutex
	requests := 0
	c := ctServer(t, "", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		first := 1
		if after := r.URL.Query().Get("after"); after != "" {
			n, _ := strconv.Atoi(after)
			first = n + 1
		}
		page := make([]map[string]any, 0, pageSize)
		for id := first; id < first+pageSize; id++ {
			nb := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(id) * time.Hour).Format(time.RFC3339)
			page = append(page, issuanceJSON(strconv.Itoa(id), shaA, nb, "h"+strconv.Itoa(id)+".x.example"))
		}
		_ = json.NewEncoder(w).Encode(page)
	})
	ct, err := c.Lookup(context.Background(), "x.example")
	if err != nil {
		t.Fatal(err)
	}
	if !ct.Truncated || ct.Total != MaxCertificates || len(ct.Certificates) != MaxCertificates || len(ct.Names) != MaxCertificates {
		t.Errorf("truncated %v total %d kept %d names %d", ct.Truncated, ct.Total, len(ct.Certificates), len(ct.Names))
	}
	if requests != 5 {
		t.Errorf("%d requests, want 5 pages of %d", requests, pageSize)
	}
	if ct.Certificates[0].ID != "500" || ct.Certificates[MaxCertificates-1].ID != "1" {
		t.Errorf("kept %s to %s, want the first %d read, latest first", ct.Certificates[0].ID, ct.Certificates[MaxCertificates-1].ID, MaxCertificates)
	}
}

func TestCTAPIKey(t *testing.T) {
	var got string
	c := ctServer(t, "s3cret", func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		_, _ = w.Write([]byte("[]"))
	})
	if _, err := c.Lookup(context.Background(), "x.example"); err != nil {
		t.Fatal(err)
	}
	if got != "Bearer s3cret" {
		t.Errorf("Authorization %q, want Bearer s3cret", got)
	}
}

func TestCTRateLimited(t *testing.T) {
	c := ctServer(t, "", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("after") == "" {
			_ = json.NewEncoder(w).Encode([]map[string]any{issuanceJSON("1", shaA, "2026-01-01T00:00:00Z", "x.example")})
			return
		}
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	if ct, err := c.Lookup(context.Background(), "x.example"); err == nil || err.Error() != "cert spotter rate limited, retry after 120" || ct != nil {
		t.Errorf("429 on the second page: %+v, %v; want no certificate kept", ct, err)
	}

	c = ctServer(t, "", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTooManyRequests) })
	if _, err := c.Lookup(context.Background(), "x.example"); err == nil || err.Error() != "cert spotter rate limited" {
		t.Errorf("429 without Retry-After: %v", err)
	}
}

func TestCTErrors(t *testing.T) {
	for _, tt := range []struct {
		want string
		h    http.HandlerFunc
	}{
		{"cert spotter: HTTP 502", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) }},
		{"cert spotter: decode:", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) }},
		{"cert spotter: decode:", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"code": "not_allowed"}`)) }},
	} {
		if _, err := ctServer(t, "", tt.h).Lookup(context.Background(), "x.example"); err == nil || !strings.HasPrefix(err.Error(), tt.want) {
			t.Errorf("err = %v, want %s", err, tt.want)
		}
	}
	c := ctServer(t, "", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("[]")) })
	if ct, err := c.Lookup(context.Background(), "x.example"); err != nil || ct.Total != 0 || ct.Truncated || ct.Names == nil || ct.Certificates == nil {
		t.Errorf("no certificate: %+v, %v", ct, err)
	}
}

func TestCertificateJSON(t *testing.T) {
	var legacy Certificate
	if err := json.Unmarshal([]byte(`{"id": 123, "issuer": "C=US, O=Let's Encrypt, CN=R3", "not_before": "2026-01-01T00:00:00Z",
		"not_after": "2026-04-01T00:00:00Z", "names": ["*.x.example"]}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.ID != "123" || legacy.CertSHA256 != "" || legacy.Issuer != "C=US, O=Let's Encrypt, CN=R3" || len(legacy.Names) != 1 ||
		!legacy.NotBefore.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("stored before Cert Spotter: %+v", legacy)
	}

	cert := Certificate{ID: "8812345", CertSHA256: shaA, Issuer: "Let's Encrypt", Revoked: true, Names: []string{"x.example"}}
	b, err := json.Marshal(cert)
	if err != nil {
		t.Fatal(err)
	}
	var back Certificate
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.ID != cert.ID || back.CertSHA256 != shaA || !back.Revoked || back.Issuer != cert.Issuer {
		t.Errorf("round trip %s = %+v", b, back)
	}
}

func TestNormalizeNames(t *testing.T) {
	for _, tt := range []struct {
		in   []string
		want string
	}{
		{[]string{"A.example", "*.A.example", "b.example.", "", " a.example "}, "*.a.example a.example b.example"},
		{nil, ""},
	} {
		got := normalizeNames(tt.in)
		if got == nil || strings.Join(got, " ") != tt.want {
			t.Errorf("normalizeNames(%q) = %#v, want %q", tt.in, got, tt.want)
		}
	}
}
