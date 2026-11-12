//go:build integration

package pg

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sebdraven/heimdall/internal/enrich"
)

// testStore migrates a fresh, uniquely named database so that an existing
// heimdall database is never touched. HEIMDALL_PG_DSN is a postgres:// URL.
func testStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("HEIMDALL_PG_DSN")
	if dsn == "" {
		t.Skip("HEIMDALL_PG_DSN not set")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	db := fmt.Sprintf("heimdall_it_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+db); err != nil {
		t.Fatalf("create database: %v", err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	u.Path = "/" + db
	if err := Migrate(ctx, u.String(), slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	s, err := Open(ctx, u.String())
	if err != nil {
		t.Fatalf("open %s: %v", db, err)
	}
	t.Cleanup(func() {
		s.Close()
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+db+" WITH (FORCE)")
		_ = admin.Close(context.Background())
	})
	return s
}

func TestDomainEnrichRoundTrip(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	at := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

	if _, err := s.DomainEnrich(ctx, "x.example"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("before: err = %v, want ErrNotFound", err)
	}

	partial := enrich.Result{
		FQDN: "x.example", FetchedAt: at, Status: enrich.StatusPartial,
		DNS:  &enrich.DNS{Resolver: "9.9.9.9:53", Records: []enrich.Record{{QType: "A", Rcode: "NOERROR", TTL: 60, Rdata: []string{"192.0.2.1"}}}},
		Zone: &enrich.Zone{Name: "x.example", SOA: []string{"ns1.p.example h.x.example 1 2 3 4 5"}, NS: []string{"ns1.p.example"}},
		RDAP: &enrich.RDAP{Domain: "x.example", Registrar: &enrich.Registrar{Name: "R", IANAID: "1"}, Registration: at.AddDate(-1, 0, 0),
			Status: []string{"active"}, Nameservers: []string{"ns1.p.example"}, Entities: []enrich.Entity{{Roles: []string{"registrar"}, Name: "R"}}},
		Subdomains: &enrich.Subdomains{Zone: "x.example", Names: []enrich.Subdomain{{Name: "www.x.example", FirstSeen: at, LastSeen: at}}},
		Errors:     map[string]string{enrich.SourceCT: "cert spotter: HTTP 502"},
	}
	if err := s.SaveDomainEnrich(ctx, partial); err != nil {
		t.Fatal(err)
	}
	got, err := s.DomainEnrich(ctx, "x.example")
	if err != nil {
		t.Fatal(err)
	}
	if !got.FetchedAt.Equal(at) || got.Status != enrich.StatusPartial || got.CT != nil || got.Errors[enrich.SourceCT] != "cert spotter: HTTP 502" {
		t.Errorf("got %+v", got)
	}
	if got.DNS == nil || got.DNS.Rdata("A")[0] != "192.0.2.1" || got.Zone.NS[0] != "ns1.p.example" ||
		got.RDAP.Registrar.IANAID != "1" || !got.RDAP.Registration.Equal(at.AddDate(-1, 0, 0)) || !got.RDAP.Expiration.IsZero() ||
		got.Subdomains.Names[0].Name != "www.x.example" {
		t.Errorf("sources not kept: dns %+v zone %+v rdap %+v subdomains %+v", got.DNS, got.Zone, got.RDAP, got.Subdomains)
	}

	ok := enrich.Result{FQDN: "x.example", FetchedAt: at.Add(time.Hour), Status: enrich.StatusOK,
		CT: &enrich.CT{Zone: "x.example", Total: 1, Certificates: []enrich.Certificate{{ID: "7", CertSHA256: strings.Repeat("ab", 32), Names: []string{"*.x.example"}}}, Names: []string{"*.x.example"}}}
	if err := s.SaveDomainEnrich(ctx, ok); err != nil {
		t.Fatal(err)
	}
	got, err = s.DomainEnrich(ctx, "x.example")
	if err != nil {
		t.Fatal(err)
	}
	if !got.FetchedAt.Equal(at.Add(time.Hour)) || got.Status != enrich.StatusOK || got.Errors != nil || got.DNS != nil || got.RDAP != nil ||
		got.CT == nil || got.CT.Certificates[0].ID != "7" || got.CT.Certificates[0].CertSHA256 != strings.Repeat("ab", 32) {
		t.Errorf("not replaced: %+v", got)
	}

	if err := s.SaveDomainEnrich(ctx, enrich.Result{FQDN: "y.example", FetchedAt: at, Status: "unknown"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("unknown status: err = %v, want ErrInvalid", err)
	}
}

func TestDomainEnrichments(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	at := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

	if got, err := s.DomainEnrichments(ctx, nil); err != nil || len(got) != 0 {
		t.Fatalf("no name: %v, %v", got, err)
	}
	for _, r := range []enrich.Result{
		{FQDN: "x.example", FetchedAt: at, Status: enrich.StatusOK,
			DNS: &enrich.DNS{Resolver: "9.9.9.9:53"},
			CT: &enrich.CT{Zone: "x.example", Total: 1, Certificates: []enrich.Certificate{{ID: "7", CertSHA256: strings.Repeat("ab", 32), Names: []string{"*.x.example"}}},
				Names: []string{"*.x.example", "mail.x.example"}, Truncated: true},
			Subdomains: &enrich.Subdomains{Zone: "x.example", Names: []enrich.Subdomain{{Name: "www.x.example", FirstSeen: at, LastSeen: at}}}},
		{FQDN: "y.example", FetchedAt: at, Status: enrich.StatusError, Errors: map[string]string{enrich.SourceCT: "cert spotter: HTTP 502"}},
	} {
		if err := s.SaveDomainEnrich(ctx, r); err != nil {
			t.Fatal(err)
		}
	}

	got, err := s.DomainEnrichments(ctx, []string{"x.example", "y.example", "z.example"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d enrichments, want x.example and y.example: %+v", len(got), got)
	}
	x := got["x.example"]
	if x.FQDN != "x.example" || !x.FetchedAt.Equal(at) || x.Status != enrich.StatusOK || x.DNS != nil {
		t.Errorf("x.example %+v", x)
	}
	if x.CT == nil || x.CT.Zone != "x.example" || !x.CT.Truncated || x.CT.Certificates != nil ||
		strings.Join(x.CT.Names, " ") != "*.x.example mail.x.example" {
		t.Errorf("ct %+v, want the names without the certificates", x.CT)
	}
	if x.Subdomains == nil || len(x.Subdomains.Names) != 1 || x.Subdomains.Names[0].Name != "www.x.example" || !x.Subdomains.Names[0].LastSeen.Equal(at) {
		t.Errorf("subdomains %+v", x.Subdomains)
	}
	if y := got["y.example"]; y.CT != nil || y.Subdomains != nil || y.Status != enrich.StatusError {
		t.Errorf("y.example %+v, want no source", y)
	}
}
