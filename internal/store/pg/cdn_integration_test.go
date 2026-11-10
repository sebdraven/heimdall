//go:build integration

package pg

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"
)

func cdnSources(t *testing.T, s *Store) map[string]string {
	t.Helper()
	rows, err := s.CDNPrefixes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, r := range rows {
		out[r.Prefix.String()] = r.Provider + "/" + r.Source
	}
	return out
}

func TestSyncCDNPrefixes(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if _, err := s.CreateCDNPrefix(ctx, netip.MustParsePrefix("203.0.113.0/24"), "Fastly", "manual"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ImportCDNPrefixes(ctx, prefixes("198.18.0.0/15"), "Fastly", "import:fastly.txt"); err != nil {
		t.Fatal(err)
	}
	before := cdnSources(t, s)

	first := prefixes("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "104.16.0.0/13")
	res, err := s.SyncCDNPrefixes(ctx, "Fastly", "sync:fastly", first, true)
	if err != nil {
		t.Fatal(err)
	}
	// 203.0.113.0/24 is manual, 104.16.0.0/13 a Cloudflare seed.
	if res != (CDNSync{Added: 2, Skipped: 2}) {
		t.Errorf("dry run = %+v", res)
	}
	if got := cdnSources(t, s); fmt.Sprint(got) != fmt.Sprint(before) {
		t.Errorf("dry run wrote: %v", got)
	}

	if res, err = s.SyncCDNPrefixes(ctx, "Fastly", "sync:fastly", first, false); err != nil || res != (CDNSync{Added: 2, Skipped: 2}) {
		t.Fatalf("first sync = %+v, %v", res, err)
	}
	got := cdnSources(t, s)
	if got["192.0.2.0/24"] != "Fastly/sync:fastly" || got["198.51.100.0/24"] != "Fastly/sync:fastly" ||
		got["203.0.113.0/24"] != "Fastly/manual" || got["104.16.0.0/13"] != "Cloudflare/seed" {
		t.Errorf("after first sync: %v", got)
	}

	second := prefixes("192.0.2.0/24", "2001:db8::/32")
	if res, err = s.SyncCDNPrefixes(ctx, "Fastly", "sync:fastly", second, false); err != nil || res != (CDNSync{Added: 1, Removed: 1, Unchanged: 1}) {
		t.Fatalf("second sync = %+v, %v", res, err)
	}
	got = cdnSources(t, s)
	if _, ok := got["198.51.100.0/24"]; ok || got["2001:db8::/32"] != "Fastly/sync:fastly" {
		t.Errorf("after second sync: %v", got)
	}
	for _, p := range []string{"203.0.113.0/24", "198.18.0.0/15", "104.16.0.0/13", "2606:4700::/32"} {
		if got[p] != before[p] {
			t.Errorf("%s changed from %q to %q", p, before[p], got[p])
		}
	}

	// Another provider's sync never removes these.
	if _, err := s.SyncCDNPrefixes(ctx, "Bunny", "sync:bunny", prefixes("192.0.2.1/32"), false); err != nil {
		t.Fatal(err)
	}
	got = cdnSources(t, s)
	var fastly []string
	for p, v := range got {
		if v == "Fastly/sync:fastly" {
			fastly = append(fastly, p)
		}
	}
	slices.Sort(fastly)
	if fmt.Sprint(fastly) != "[192.0.2.0/24 2001:db8::/32]" || got["192.0.2.1/32"] != "Bunny/sync:bunny" {
		t.Errorf("after bunny sync: %v", got)
	}

	if _, err := s.SyncCDNPrefixes(ctx, "Fastly", "sync:fastly", nil, false); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty list: err = %v, want ErrInvalid", err)
	}
}
