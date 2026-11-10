package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/sebdraven/heimdall/internal/cdn"
	"github.com/sebdraven/heimdall/internal/store/pg"
)

type syncCall struct {
	provider, source string
	prefixes         []netip.Prefix
	dryRun           bool
}

type fakeSyncStore struct {
	calls  []syncCall
	audits []string
}

func (f *fakeSyncStore) SyncCDNPrefixes(_ context.Context, provider, source string, prefixes []netip.Prefix, dryRun bool) (pg.CDNSync, error) {
	f.calls = append(f.calls, syncCall{provider, source, prefixes, dryRun})
	return pg.CDNSync{Added: len(prefixes), Removed: 1, Unchanged: 2, Skipped: 1}, nil
}

func (f *fakeSyncStore) Audit(_ context.Context, _ *int64, action, target string) error {
	f.audits = append(f.audits, action+" "+target)
	return nil
}

// syncServer serves /a and /asn, and fails /down.
func syncServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a":
			fmt.Fprint(w, "192.0.2.0/24\n2001:db8::/32\n")
		case "/asn":
			fmt.Fprint(w, `{"status":"ok","data":{"prefixes":[{"prefix":"198.51.100.0/24"}]}}`)
		default:
			http.Error(w, "down", http.StatusBadGateway)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func runSync(t *testing.T, srv *httptest.Server, st *fakeSyncStore, args ...string) (string, string, error) {
	t.Helper()
	catalog := []cdn.Source{
		{Name: "alpha", Provider: "Alpha", URLs: []string{srv.URL + "/a"}, Parse: cdn.ParseCloudflare},
		{Name: "broken", Provider: "Broken", URLs: []string{srv.URL + "/down"}, Parse: cdn.ParseCloudflare},
		{Name: "gamma", Provider: "Gamma", URLs: []string{srv.URL + "/a"}, Parse: cdn.ParseCloudflare},
	}
	asn := func(n uint32, provider string) cdn.Source {
		s := cdn.ASNSource(n, provider)
		s.URLs = []string{srv.URL + "/asn"}
		return s
	}
	var out, errOut bytes.Buffer
	fs := flag.NewFlagSet("cdn-sync", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	err := cdnSync(context.Background(), st, srv.Client(), catalog, asn, fs, args, &out, &errOut)
	return out.String(), errOut.String(), err
}

func TestCDNSyncPartialFailure(t *testing.T) {
	srv := syncServer(t)
	st := &fakeSyncStore{}
	out, errOut, err := runSync(t, srv, st)
	if err == nil || err.Error() != "1 of 3 provider(s) failed" {
		t.Fatalf("err = %v, want the failure counted", err)
	}
	if !strings.Contains(errOut, "error: broken: "+srv.URL+"/down: HTTP 502") {
		t.Errorf("stderr = %q", errOut)
	}
	want := "alpha: 2 added, 1 removed, 2 unchanged, 1 already listed by another source\n" +
		"gamma: 2 added, 1 removed, 2 unchanged, 1 already listed by another source\n"
	if out != want {
		t.Errorf("stdout =\n%s\nwant\n%s", out, want)
	}
	if len(st.calls) != 2 || st.calls[0].source != "sync:alpha" || st.calls[0].provider != "Alpha" || st.calls[1].source != "sync:gamma" ||
		fmt.Sprint(st.calls[0].prefixes) != "[192.0.2.0/24 2001:db8::/32]" || st.calls[0].dryRun {
		t.Errorf("calls = %+v", st.calls)
	}
	if strings.Join(st.audits, "|") != "cli:cdnprefix.sync Alpha (2 added, 1 removed)|cli:cdnprefix.sync Gamma (2 added, 1 removed)" {
		t.Errorf("audits = %v", st.audits)
	}
}

func TestCDNSyncDryRun(t *testing.T) {
	srv := syncServer(t)
	st := &fakeSyncStore{}
	out, _, err := runSync(t, srv, st, "-provider", "alpha", "-dry-run")
	if err != nil {
		t.Fatal(err)
	}
	if len(st.calls) != 1 || !st.calls[0].dryRun || st.calls[0].source != "sync:alpha" {
		t.Errorf("calls = %+v, want one dry run of alpha", st.calls)
	}
	if len(st.audits) != 0 {
		t.Errorf("dry run audited: %v", st.audits)
	}
	if !strings.HasSuffix(out, "dry run: nothing written\n") {
		t.Errorf("stdout = %q", out)
	}
}

func TestCDNSyncASN(t *testing.T) {
	srv := syncServer(t)
	st := &fakeSyncStore{}
	_, errOut, err := runSync(t, srv, st, "-provider", "ALPHA", "-provider", "alpha", "-asn", "AS64500", "-as-provider", "Example CDN")
	if err != nil {
		t.Fatal(err)
	}
	if len(st.calls) != 2 || st.calls[0].source != "sync:alpha" || st.calls[1].source != "sync:example cdn" || st.calls[1].provider != "Example CDN" ||
		fmt.Sprint(st.calls[1].prefixes) != "[198.51.100.0/24]" {
		t.Errorf("calls = %+v", st.calls)
	}
	if !strings.Contains(errOut, "warning: example cdn: every prefix announced by the AS is marked CDN") {
		t.Errorf("no ASN warning: %q", errOut)
	}
}

func TestCDNSyncUsage(t *testing.T) {
	srv := syncServer(t)
	for _, args := range [][]string{
		{"-provider", "akamai"},
		{"-asn", "64500"},
		{"-asn", "x", "-as-provider", "X"},
		{"-asn", "0", "-as-provider", "X"},
		{"-asn", "64500", "-as-provider", "Alpha"},
		{"-asn", "64500", "-as-provider", "X", "-asn", "64501", "-as-provider", "x"},
		{"extra"},
	} {
		st := &fakeSyncStore{}
		if _, _, err := runSync(t, srv, st, args...); !errors.Is(err, errUsage) || len(st.calls) != 0 {
			t.Errorf("%v: err = %v, %d calls; want a usage error and nothing synced", args, err, len(st.calls))
		}
	}
	if _, ok := commands["cdn-sync"]; !ok {
		t.Error("cdn-sync is not a command")
	}
}
