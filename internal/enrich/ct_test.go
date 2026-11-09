package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func ctServer(t *testing.T, h http.HandlerFunc) *CTClient {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return NewCTClient(srv.URL + "/")
}

func TestCTLookup(t *testing.T) {
	c := ctServer(t, func(w http.ResponseWriter, r *http.Request) {
		if q := r.URL.Query(); q.Get("q") != "%.x.example" || q.Get("output") != "json" || r.URL.Path != "/" {
			t.Errorf("query %s", r.URL)
		}
		if ua := r.Header.Get("User-Agent"); ua != "heimdall" {
			t.Errorf("User-Agent %q", ua)
		}
		_, _ = w.Write([]byte(`[
			{"issuer_ca_id": 1, "issuer_name": "C=US, O=Let's Encrypt, CN=R3", "common_name": "x.example",
			 "name_value": "WWW.x.example\n*.x.example\nwww.x.example\n\nmail.x.example.", "id": 10,
			 "not_before": "2026-01-01T00:00:00", "not_after": "2026-04-01T23:59:59"},
			{"issuer_name": "C=US, O=Let's Encrypt, CN=R3", "name_value": "api.x.example", "id": 12,
			 "not_before": "2026-03-01T00:00:00.123", "not_after": "2026-06-01T00:00:00"},
			{"issuer_name": "C=US, O=Let's Encrypt, CN=R3", "name_value": "api.x.example", "id": 12,
			 "not_before": "2026-03-01T00:00:00", "not_after": "2026-06-01T00:00:00"}
		]`))
	})
	ct, err := c.Lookup(context.Background(), "x.example")
	if err != nil {
		t.Fatal(err)
	}
	if ct.Zone != "x.example" || ct.Total != 2 || ct.Truncated || len(ct.Certificates) != 2 {
		t.Fatalf("ct = %+v, want 2 certificates", ct)
	}
	latest, first := ct.Certificates[0], ct.Certificates[1]
	if latest.ID != 12 || first.ID != 10 {
		t.Errorf("order %d %d, want the latest first", latest.ID, first.ID)
	}
	if got := strings.Join(first.Names, " "); got != "*.x.example mail.x.example www.x.example" {
		t.Errorf("names of 10 = %s", got)
	}
	if first.Issuer != "C=US, O=Let's Encrypt, CN=R3" || !first.NotBefore.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) ||
		!first.NotAfter.Equal(time.Date(2026, 4, 1, 23, 59, 59, 0, time.UTC)) {
		t.Errorf("certificate 10 = %+v", first)
	}
	if got := strings.Join(ct.Names, " "); got != "*.x.example api.x.example mail.x.example www.x.example" {
		t.Errorf("names = %s", got)
	}
}

func TestCTTruncated(t *testing.T) {
	c := ctServer(t, func(w http.ResponseWriter, _ *http.Request) {
		rows := make([]map[string]any, 0, MaxCertificates+1)
		for i := range MaxCertificates + 1 {
			rows = append(rows, map[string]any{
				"id": i + 1, "issuer_name": "CA", "name_value": fmt.Sprintf("h%d.x.example", i),
				"not_before": time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Hour).Format("2006-01-02T15:04:05"),
			})
		}
		_ = json.NewEncoder(w).Encode(rows)
	})
	ct, err := c.Lookup(context.Background(), "x.example")
	if err != nil {
		t.Fatal(err)
	}
	if !ct.Truncated || ct.Total != MaxCertificates+1 || len(ct.Certificates) != MaxCertificates || len(ct.Names) != MaxCertificates+1 {
		t.Errorf("truncated %v total %d kept %d names %d", ct.Truncated, ct.Total, len(ct.Certificates), len(ct.Names))
	}
	if ct.Certificates[0].ID != MaxCertificates+1 || ct.Certificates[MaxCertificates-1].ID != 2 {
		t.Errorf("kept %d to %d, want the latest", ct.Certificates[0].ID, ct.Certificates[MaxCertificates-1].ID)
	}
}

func TestCTErrors(t *testing.T) {
	for _, tt := range []struct {
		want string
		h    http.HandlerFunc
	}{
		{"crt.sh: HTTP 502", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) }},
		{"crt.sh: decode:", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) }},
		{"crt.sh: decode:", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"id": 1}`)) }},
	} {
		if _, err := ctServer(t, tt.h).Lookup(context.Background(), "x.example"); err == nil || !strings.HasPrefix(err.Error(), tt.want) {
			t.Errorf("err = %v, want %s", err, tt.want)
		}
	}
	c := ctServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("[]")) })
	if ct, err := c.Lookup(context.Background(), "x.example"); err != nil || ct.Total != 0 || ct.Names == nil || ct.Certificates == nil {
		t.Errorf("no certificate: %+v, %v", ct, err)
	}
}

func TestSplitNames(t *testing.T) {
	for in, want := range map[string]string{
		"A.example\r\n*.A.example\nb.example.\n\n a.example ": "*.a.example a.example b.example",
		"":                                 "",
		"single.example":                   "single.example",
	} {
		if got := strings.Join(splitNames(in), " "); got != want {
			t.Errorf("splitNames(%q) = %q, want %q", in, got, want)
		}
	}
}
