package vt

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func testClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c := New("secret")
	c.base = srv.URL
	c.lim = rate.NewLimiter(rate.Inf, 1)
	return c
}

func TestDomainResolutions(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/domains/x.example/resolutions" || r.URL.Query().Get("limit") != "40" {
			t.Errorf("request %s", r.URL)
		}
		if got := r.Header.Get("x-apikey"); got != "secret" {
			t.Errorf("x-apikey %q", got)
		}
		_, _ = w.Write([]byte(`{"data": [
			{"type": "resolution", "id": "198.51.100.7x.example", "attributes": {"date": 1599471348, "host_name": "x.example", "ip_address": "198.51.100.7", "resolver": "VirusTotal"}},
			{"type": "resolution", "id": "x", "attributes": {"date": 1599471348, "host_name": "", "ip_address": "198.51.100.8"}}
		], "meta": {"cursor": "abc"}, "links": {"self": "s", "next": "n"}}`))
	})
	got, err := c.DomainResolutions(context.Background(), "x.example")
	if err != nil {
		t.Fatal(err)
	}
	want := Resolution{HostName: "x.example", IP: "198.51.100.7", Date: time.Unix(1599471348, 0).UTC()}
	if len(got) != 1 || got[0] != want {
		t.Errorf("resolutions = %+v, want [%+v]", got, want)
	}
}

func TestIPResolutionsPath(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ip_addresses/2001:db8::1/resolutions" {
			t.Errorf("path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"data": []}`))
	})
	if got, err := c.IPResolutions(context.Background(), "2001:db8::1"); err != nil || len(got) != 0 {
		t.Errorf("resolutions %v, err %v", got, err)
	}
}

func TestResolutionsNotFound(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error": {"code": "NotFoundError", "message": "Domain \"x.example\" not found"}}`))
	})
	if got, err := c.DomainResolutions(context.Background(), "x.example"); err != nil || got != nil {
		t.Errorf("resolutions %v, err %v, want none and no error", got, err)
	}
}

func TestResolutionsErrors(t *testing.T) {
	for _, code := range []string{"QuotaExceededError", "TooManyRequestsError"} {
		c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error": {"code": "` + code + `", "message": "quota"}}`))
		})
		if _, err := c.DomainResolutions(context.Background(), "x.example"); !errors.Is(err, ErrQuota) {
			t.Errorf("%s: err %v, want ErrQuota", code, err)
		}
	}

	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error": {"code": "WrongCredentialsError", "message": "bad key"}}`))
	})
	_, err := c.DomainResolutions(context.Background(), "x.example")
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != http.StatusUnauthorized || ae.Code != "WrongCredentialsError" || errors.Is(err, ErrQuota) {
		t.Errorf("err %v, want an APIError 401 WrongCredentialsError", err)
	}
}
