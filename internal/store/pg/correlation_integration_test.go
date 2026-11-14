//go:build integration

package pg

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sebdraven/heimdall/internal/enrich"
)

func linkLine(l CorrelationLink) string {
	return fmt.Sprintf("%s %s %s/%d %s/%d %s %s", l.Kind, l.Value, l.DomainA, l.CampaignA, l.DomainB, l.CampaignB,
		l.FirstSeen.UTC().Format(time.RFC3339), l.LastSeen.UTC().Format(time.RFC3339))
}

func TestUpsertCorrelationLinks(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	at := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	sha := strings.Repeat("ab", 32)
	first := []CorrelationLink{
		{Kind: "cert", Value: sha, DomainA: "a.example", CampaignA: 1, DomainB: "b.example", CampaignB: 2},
		{Kind: "ip", Value: "192.0.2.1", DomainA: "a.example", CampaignA: 1, DomainB: "c.example", CampaignB: 3},
	}
	saved, err := s.UpsertCorrelationLinks(ctx, first, at)
	if err != nil {
		t.Fatal(err)
	}
	if len(saved) != 2 || !saved[0].FirstSeen.Equal(at) || !saved[0].LastSeen.Equal(at) {
		t.Fatalf("saved = %+v", saved)
	}

	// An hour later the cert link is found again, c.example moved to campaign
	// 4, and the ip link is gone.
	later := at.Add(time.Hour)
	second := []CorrelationLink{
		{Kind: "cert", Value: sha, DomainA: "a.example", CampaignA: 1, DomainB: "b.example", CampaignB: 2},
		{Kind: "mx", Value: "mx.evil.example", DomainA: "a.example", CampaignA: 1, DomainB: "c.example", CampaignB: 4},
	}
	if _, err := s.UpsertCorrelationLinks(ctx, second, later); err != nil {
		t.Fatal(err)
	}
	all, err := s.CorrelationLinks(ctx, CorrelationFilter{})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, l := range all {
		got = append(got, linkLine(l))
	}
	want := []string{
		"mx mx.evil.example a.example/1 c.example/4 2026-11-09T13:00:00Z 2026-11-09T13:00:00Z",
		"ip 192.0.2.1 a.example/1 c.example/3 2026-11-09T12:00:00Z 2026-11-09T12:00:00Z",
		"cert " + sha + " a.example/1 b.example/2 2026-11-09T12:00:00Z 2026-11-09T13:00:00Z",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("history =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// last_seen never goes back.
	if _, err := s.UpsertCorrelationLinks(ctx, second[:1], at); err != nil {
		t.Fatal(err)
	}
	if l, _ := s.CorrelationLinks(ctx, CorrelationFilter{Kinds: []string{"cert"}}); len(l) != 1 || !l[0].LastSeen.Equal(later) {
		t.Errorf("cert link after an older run: %+v", l)
	}

	if l, err := s.CorrelationLinks(ctx, CorrelationFilter{Since: later}); err != nil || len(l) != 1 || l[0].Kind != "mx" {
		t.Errorf("since: %+v, %v", l, err)
	}
	if l, err := s.CorrelationLinks(ctx, CorrelationFilter{CampaignA: 2, CampaignB: 1}); err != nil || len(l) != 1 || l[0].Kind != "cert" {
		t.Errorf("between 2 and 1: %+v, %v", l, err)
	}
	if l, err := s.CorrelationLinks(ctx, CorrelationFilter{Limit: 1}); err != nil || len(l) != 1 {
		t.Errorf("limit: %+v, %v", l, err)
	}

	bad := []CorrelationLink{{Kind: "ip", Value: "192.0.2.9", DomainA: "z.example", CampaignA: 1, DomainB: "a.example", CampaignB: 2}}
	if _, err := s.UpsertCorrelationLinks(ctx, bad, at); !errors.Is(err, ErrInvalid) {
		t.Errorf("domain_a > domain_b: err = %v, want ErrInvalid", err)
	}
	// A failed run leaves nothing behind.
	if l, _ := s.CorrelationLinks(ctx, CorrelationFilter{}); len(l) != 3 {
		t.Errorf("%d links after a failed run, want 3", len(l))
	}
}

func TestEnrichCertsAndRegistrations(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	at := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	c, err := s.CreateCampaign(ctx, "spynote", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ImportDomains(ctx, []string{"a.example", "b.example"}, &c.ID, 300, "test", nil); err != nil {
		t.Fatal(err)
	}
	sha := strings.Repeat("AB", 32)
	for _, r := range []enrich.Result{
		{FQDN: "a.example", FetchedAt: at, Status: enrich.StatusOK,
			CT: &enrich.CT{Zone: "a.example", Certificates: []enrich.Certificate{
				{ID: "1", CertSHA256: sha, NotBefore: at, NotAfter: at.AddDate(0, 3, 0)},
				{ID: "2"},
			}},
			RDAP: &enrich.RDAP{Domain: "a.example", Registrar: &enrich.Registrar{Name: "NameCheap, Inc.", IANAID: "1068"}, Registration: at.AddDate(0, 0, -3)}},
		{FQDN: "b.example", FetchedAt: at, Status: enrich.StatusPartial,
			RDAP: &enrich.RDAP{Domain: "b.example"}},
		// Not watched.
		{FQDN: "x.example", FetchedAt: at, Status: enrich.StatusOK,
			CT:   &enrich.CT{Zone: "x.example", Certificates: []enrich.Certificate{{ID: "3", CertSHA256: sha}}},
			RDAP: &enrich.RDAP{Domain: "x.example", Registrar: &enrich.Registrar{Name: "R"}, Registration: at}},
	} {
		if err := s.SaveDomainEnrich(ctx, r); err != nil {
			t.Fatal(err)
		}
	}

	certs, err := s.EnrichCerts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 || certs[0].FQDN != "a.example" || certs[0].SHA256 != strings.ToLower(sha) ||
		certs[0].NotBefore == nil || !certs[0].NotBefore.Equal(at) || !certs[0].NotAfter.Equal(at.AddDate(0, 3, 0)) {
		t.Errorf("certs = %+v", certs)
	}
	regs, err := s.EnrichRegistrations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(regs) != 1 || regs[0] != (EnrichRegistration{FQDN: "a.example", Domain: "a.example", RegistrarID: "1068", Registrar: "NameCheap, Inc.", Registered: regs[0].Registered}) ||
		!regs[0].Registered.Equal(at.AddDate(0, 0, -3)) {
		t.Errorf("registrations = %+v", regs)
	}
}

func TestEnrichTrackers(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	at := time.Date(2026, 11, 13, 6, 30, 20, 390000000, time.UTC)
	c, err := s.CreateCampaign(ctx, "spynote", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ImportDomains(ctx, []string{"a.example", "b.example"}, &c.ID, 300, "test", nil); err != nil {
		t.Fatal(err)
	}
	for _, r := range []enrich.Result{
		{FQDN: "a.example", FetchedAt: at, Status: enrich.StatusOK, Lookyloo: &enrich.Lookyloo{Trackers: []enrich.TrackerSeen{
			{Kind: "gads", ID: "AW-11021906314", FirstSeen: at.AddDate(0, -5, 0), LastSeen: at, Captures: 2},
			{Kind: "", ID: "x"},
		}}},
		{FQDN: "b.example", FetchedAt: at, Status: enrich.StatusPartial},
		// Not watched.
		{FQDN: "x.example", FetchedAt: at, Status: enrich.StatusOK, Lookyloo: &enrich.Lookyloo{Trackers: []enrich.TrackerSeen{{Kind: "ua", ID: "UA-1-1"}}}},
	} {
		if err := s.SaveDomainEnrich(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.EnrichTrackers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].FQDN != "a.example" || got[0].Kind != "gads" || got[0].ID != "AW-11021906314" ||
		got[0].FirstSeen == nil || !got[0].FirstSeen.Equal(at.AddDate(0, -5, 0)) || !got[0].LastSeen.Equal(at) {
		t.Errorf("trackers = %+v", got)
	}
}
