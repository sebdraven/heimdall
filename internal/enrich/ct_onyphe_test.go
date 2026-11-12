package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func onypheServer(t *testing.T, window string, h http.HandlerFunc) *OnypheClient {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return NewOnypheClient(srv.URL+"/api/v2/", "k3y", window)
}

// onypheResult is a ctl result as ONYPHE returns it.
func onypheResult(sha, notBefore string, altnames ...string) map[string]any {
	return map[string]any{
		"@category": "ctl", "@timestamp": "2026-11-10T11:52:35.000Z", "domain": []string{"x.example"},
		"fingerprint": map[string]any{"md5": strings.Repeat("0", 32), "sha1": strings.Repeat("1", 40), "sha256": sha},
		"hostname":    altnames,
		"issuer":      map[string]any{"commonname": "YR2", "country": "US", "organization": "Let's Encrypt"},
		"subject":     map[string]any{"altname": altnames, "commonname": altnames[0]},
		"tag":         []string{"precert"},
		"validity":    map[string]any{"notbefore": notBefore, "notafter": "2027-02-08T09:42:22.000Z"},
	}
}

func onypheJSON(page, maxPage int, results ...map[string]any) map[string]any {
	return map[string]any{
		"count": len(results), "error": 0, "max_page": maxPage, "page": page, "page_size": 100,
		"results": results, "status": "ok", "text": "Success", "total": len(results),
	}
}

func TestOnypheLookup(t *testing.T) {
	var mu sync.Mutex
	var pages []string
	c := onypheServer(t, "-since:48M", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if r.URL.Path != "/api/v2/search/" || q.Get("q") != "category:ctl domain:x.example -since:48M" {
			t.Errorf("query %s", r.URL)
		}
		if auth := r.Header.Get("Authorization"); auth != "bearer k3y" {
			t.Errorf("Authorization %q", auth)
		}
		if ua := r.Header.Get("User-Agent"); ua != "heimdall" {
			t.Errorf("User-Agent %q", ua)
		}
		mu.Lock()
		pages = append(pages, q.Get("page"))
		mu.Unlock()
		var body map[string]any
		switch q.Get("page") {
		case "1":
			other := onypheResult(shaB, "2026-03-01T00:00:00.000Z", "api.x.example")
			other["issuer"] = map[string]any{"organization": "Other CA"}
			other["hostname"] = "API.x.example."
			noSHA := onypheResult("", "2026-05-01T00:00:00.000Z", "nosha.x.example")
			noSHA["fingerprint"] = map[string]any{"md5": strings.Repeat("0", 32)}
			body = onypheJSON(1, 2,
				onypheResult(strings.ToUpper(shaA), "2026-01-01T00:00:00.000Z", "WWW.x.example.", "*.x.example"),
				other,
				noSHA,
				onypheResult("", "2026-05-01T00:00:00.000Z", "empty.x.example"),
			)
		case "2":
			body = onypheJSON(2, 2,
				onypheResult(shaA, "2026-01-01T00:00:00.000Z", "www.x.example"),
				onypheResult(shaC, "2026-04-01T00:00:00.000Z", "mail.x.example"),
			)
		default:
			t.Errorf("page %s past max_page", q.Get("page"))
		}
		_ = json.NewEncoder(w).Encode(body)
	})
	ct, err := c.Lookup(context.Background(), "x.example")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(pages, []string{"1", "2"}) {
		t.Errorf("pages %v, want 1 to max_page", pages)
	}
	if ct.Zone != "x.example" || ct.Total != 3 || len(ct.Certificates) != 3 || ct.Truncated {
		t.Fatalf("ct %+v", ct)
	}
	var shas []string
	for _, cert := range ct.Certificates {
		shas = append(shas, cert.CertSHA256)
	}
	if want := []string{shaC, shaB, shaA}; !slices.Equal(shas, want) {
		t.Errorf("sha256 %v, want %v: one per full SHA-256, lowercased, latest first", shas, want)
	}
	a := ct.Certificates[2]
	if a.ID != "" || a.Issuer != "YR2" || !a.NotBefore.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) ||
		!a.NotAfter.Equal(time.Date(2027, 2, 8, 9, 42, 22, 0, time.UTC)) || a.NotBefore.Location() != time.UTC {
		t.Errorf("certificate %+v", a)
	}
	if !slices.Equal(a.Names, []string{"*.x.example", "www.x.example"}) {
		t.Errorf("names %v, want the altnames and hostnames, normalized", a.Names)
	}
	if b := ct.Certificates[1]; b.Issuer != "Other CA" || !slices.Equal(b.Names, []string{"api.x.example"}) {
		t.Errorf("issuer %q names %v, want the organization without common name, and a hostname given as a string", b.Issuer, b.Names)
	}
	if want := []string{"*.x.example", "api.x.example", "mail.x.example", "www.x.example"}; !slices.Equal(ct.Names, want) {
		t.Errorf("names %v, want %v", ct.Names, want)
	}
}

func TestOnypheBelowRegistrableDomain(t *testing.T) {
	c := onypheServer(t, "", func(w http.ResponseWriter, r *http.Request) {
		if q := r.URL.Query().Get("q"); q != "category:ctl domain:x.example" {
			t.Errorf("q %q, want the registrable domain and no window", q)
		}
		_ = json.NewEncoder(w).Encode(onypheJSON(1, 1,
			onypheResult(shaA, "2026-01-01T00:00:00.000Z", "www.a.x.example"),
			onypheResult(shaB, "2026-01-01T00:00:00.000Z", "*.a.x.example"),
			onypheResult(shaC, "2026-01-01T00:00:00.000Z", "www.b.x.example", "x.example"),
		))
	})
	ct, err := c.Lookup(context.Background(), "a.x.example")
	if err != nil {
		t.Fatal(err)
	}
	if ct.Zone != "a.x.example" || ct.Total != 2 || slices.ContainsFunc(ct.Certificates, func(c Certificate) bool { return c.CertSHA256 == shaC }) {
		t.Errorf("ct %+v, want only the certificates with a name within a.x.example", ct)
	}
}

func TestOnypheCap(t *testing.T) {
	var mu sync.Mutex
	requests := 0
	c := onypheServer(t, "", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		results := make([]map[string]any, 0, 100)
		for i := range 100 {
			id := (page-1)*100 + i
			nb := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(id) * time.Hour).Format(time.RFC3339)
			results = append(results, onypheResult(fmt.Sprintf("%064x", id+1), nb, "h"+strconv.Itoa(id)+".x.example"))
		}
		_ = json.NewEncoder(w).Encode(onypheJSON(page, 50, results...))
	})
	ct, err := c.Lookup(context.Background(), "x.example")
	if err != nil {
		t.Fatal(err)
	}
	if requests != 5 || !ct.Truncated || ct.Total != MaxCertificates || len(ct.Names) != MaxCertificates {
		t.Errorf("%d requests, truncated %v, total %d, names %d", requests, ct.Truncated, ct.Total, len(ct.Names))
	}
	if sha := ct.Certificates[0].CertSHA256; sha != fmt.Sprintf("%064x", MaxCertificates) || len(sha) != 64 {
		t.Errorf("first %s, want the latest of the first %d, in full", sha, MaxCertificates)
	}
}

func TestOnypheRateLimited(t *testing.T) {
	for _, tt := range []struct{ retryAfter, want string }{
		{"", "onyphe rate limited"},
		{"60", "onyphe rate limited, retry after 60"},
	} {
		c := onypheServer(t, "", func(w http.ResponseWriter, _ *http.Request) {
			if tt.retryAfter != "" {
				w.Header().Set("Retry-After", tt.retryAfter)
			}
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":1,"text":"Too many requests"}`))
		})
		if ct, err := c.Lookup(context.Background(), "x.example"); err == nil || err.Error() != tt.want || ct != nil {
			t.Errorf("first page: %+v, %v; want %q and no certificate", ct, err, tt.want)
		}
	}

	var mu sync.Mutex
	requests := 0
	c := onypheServer(t, "", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		if r.URL.Query().Get("page") == "1" {
			_ = json.NewEncoder(w).Encode(onypheJSON(1, 3,
				onypheResult(shaA, "2026-01-01T00:00:00.000Z", "www.x.example"),
				onypheResult(shaB, "2026-02-01T00:00:00.000Z", "api.x.example"),
			))
			return
		}
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	ct, err := c.Lookup(context.Background(), "x.example")
	if err == nil || err.Error() != "onyphe rate limited, retry after 60" {
		t.Errorf("err = %v", err)
	}
	if ct == nil {
		t.Fatal("429 on the second page: no certificate, want the first page")
	}
	if requests != 2 || !ct.Truncated || ct.Total != 2 || ct.Certificates[0].CertSHA256 != shaB {
		t.Errorf("%d requests, ct %+v", requests, ct)
	}
}

func TestOnypheErrors(t *testing.T) {
	for _, tt := range []struct {
		want string
		h    http.HandlerFunc
	}{
		{"onyphe: HTTP 401: Invalid API key", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":1,"status":"nok","text":"Invalid API key"}`))
		}},
		{"onyphe: HTTP 502", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) }},
		{"onyphe: error 3: syntax error", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"error":3,"status":"nok","text":"syntax error","results":[]}`))
		}},
		{"onyphe: decode:", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) }},
	} {
		if ct, err := onypheServer(t, "", tt.h).Lookup(context.Background(), "x.example"); err == nil || !strings.HasPrefix(err.Error(), tt.want) || ct != nil {
			t.Errorf("%+v, %v; want %s", ct, err, tt.want)
		}
	}
	c := onypheServer(t, "", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(onypheJSON(1, 0))
	})
	if ct, err := c.Lookup(context.Background(), "x.example"); err != nil || ct.Total != 0 || ct.Truncated || ct.Names == nil || ct.Certificates == nil {
		t.Errorf("no certificate: %+v, %v", ct, err)
	}
}
