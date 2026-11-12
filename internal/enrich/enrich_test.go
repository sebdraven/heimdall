package enrich

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sebdraven/heimdall/internal/resolver"
)

type fakeRegistry struct {
	err   error
	asked string
}

func (f *fakeRegistry) Lookup(_ context.Context, name string) (*RDAP, error) {
	f.asked = name
	if f.err != nil {
		return nil, f.err
	}
	return &RDAP{Domain: "x.example"}, nil
}

type fakeCT struct {
	err     error
	partial *CT
	asked   string
}

func (f *fakeCT) Lookup(_ context.Context, zone string) (*CT, error) {
	f.asked = zone
	if f.err != nil {
		return f.partial, f.err
	}
	return &CT{Zone: zone, Names: []string{"www." + zone}}, nil
}

type fakePDNS struct {
	err   error
	asked string
	n     int
}

func (f *fakePDNS) SubdomainsOf(_ context.Context, zone string, limit int) ([]Subdomain, error) {
	f.asked = zone
	if f.err != nil {
		return nil, f.err
	}
	out := make([]Subdomain, min(f.n, limit))
	for i := range out {
		out[i] = Subdomain{Name: "s.x.example"}
	}
	return out, nil
}

var runTime = time.Date(2026, 11, 9, 12, 0, 0, 0, time.FixedZone("CET", 3600))

func runEnricher(dns Resolver) (*Enricher, *fakeRegistry, *fakeCT, *fakePDNS) {
	r, c, p := &fakeRegistry{}, &fakeCT{}, &fakePDNS{n: 2}
	return &Enricher{DNS: dns, RDAP: r, CT: c, PDNS: p, Now: func() time.Time { return runTime }}, r, c, p
}

func TestRunOK(t *testing.T) {
	f := &fakeResolver{obs: map[string]resolver.Observation{
		"www.a.x.example A":   answer("www.a.x.example", "A", "192.0.2.1"),
		"www.a.x.example SOA": {Rcode: "NOERROR", Authority: []resolver.Answer{{Name: "a.x.example", Type: "SOA", Value: testSOA}}},
	}}
	e, r, c, p := runEnricher(f)
	res := e.Run(context.Background(), "www.a.x.example", "9.9.9.9:53")
	if res.Status != StatusOK || res.Errors != nil {
		t.Fatalf("status %s errors %v", res.Status, res.Errors)
	}
	if res.FQDN != "www.a.x.example" || !res.FetchedAt.Equal(runTime) || res.FetchedAt.Location() != time.UTC {
		t.Errorf("fqdn %s fetched at %s", res.FQDN, res.FetchedAt)
	}
	if res.DNS == nil || res.Zone == nil || res.Zone.Name != "a.x.example" || res.RDAP == nil || res.CT == nil || res.Subdomains == nil {
		t.Fatalf("result %+v", res)
	}
	if r.asked != "www.a.x.example" || c.asked != "a.x.example" || p.asked != "a.x.example" {
		t.Errorf("asked rdap %s ct %s pdns %s, want CT and passive DNS below the zone", r.asked, c.asked, p.asked)
	}
	if res.Subdomains.Zone != "a.x.example" || len(res.Subdomains.Names) != 2 || res.Subdomains.Truncated {
		t.Errorf("subdomains %+v", res.Subdomains)
	}
}

func TestRunPartial(t *testing.T) {
	e, _, c, p := runEnricher(&fakeResolver{down: true})
	e.RDAP.(*fakeRegistry).err = errors.New("rdap example: HTTP 404")
	p.n = MaxSubdomains
	res := e.Run(context.Background(), "www.x.example", "9.9.9.9:53")
	if res.Status != StatusPartial || len(res.Errors) != 2 || res.Errors[SourceDNS] != "no answer from 9.9.9.9:53" || res.Errors[SourceRDAP] != "rdap example: HTTP 404" {
		t.Errorf("status %s errors %v", res.Status, res.Errors)
	}
	if res.DNS != nil || res.Zone != nil || res.RDAP != nil {
		t.Error("a failed source is kept")
	}
	if c.asked != "x.example" || p.asked != "x.example" || res.CT == nil || !res.Subdomains.Truncated {
		t.Errorf("without DNS: ct %s pdns %s, want the registrable domain; subdomains %+v", c.asked, p.asked, res.Subdomains)
	}
}

func TestRunCTRateLimited(t *testing.T) {
	e, _, c, _ := runEnricher(nil)
	c.err = errors.New("cert spotter rate limited, retry after 120")
	c.partial = &CT{Zone: "x.example", Total: 1, Certificates: []Certificate{{ID: "1", CertSHA256: shaA}}, Names: []string{"x.example"}, Truncated: true}
	res := e.Run(context.Background(), "x.example", "")
	if res.Status != StatusPartial || res.Errors[SourceCT] != "cert spotter rate limited, retry after 120" {
		t.Errorf("status %s errors %v", res.Status, res.Errors)
	}
	if res.CT != c.partial {
		t.Errorf("ct %+v, want the certificates read before the rate limit", res.CT)
	}
}

func TestRunNoResolver(t *testing.T) {
	f := &fakeResolver{}
	e, _, _, _ := runEnricher(f)
	res := e.Run(context.Background(), "x.example", "")
	if res.Status != StatusPartial || res.Errors[SourceDNS] != ErrNoResolver.Error() || len(f.questions()) != 0 {
		t.Errorf("status %s errors %v questions %v", res.Status, res.Errors, f.questions())
	}
}

func TestRunError(t *testing.T) {
	e, r, c, p := runEnricher(nil)
	r.err, c.err, p.err = errors.New("r"), errors.New("c"), errors.New("p")
	res := e.Run(context.Background(), "x.example", "")
	if res.Status != StatusError || len(res.Errors) != 4 || res.Errors[SourceSubdomains] != "passive DNS: p" {
		t.Errorf("status %s errors %v", res.Status, res.Errors)
	}

	e, _, c, p = runEnricher(nil)
	res = e.Run(context.Background(), "co.uk", "")
	if res.Errors[SourceCT] != "no registrable domain for co.uk" || c.asked != "" || p.asked != "" {
		t.Errorf("public suffix: errors %v, asked ct %q pdns %q", res.Errors, c.asked, p.asked)
	}
}

func TestSearchScope(t *testing.T) {
	for _, tt := range []struct{ fqdn, zone, want string }{
		{"www.a.x.example.com", "a.x.example.com", "a.x.example.com"},
		{"www.x.example.com", "x.example.com", "x.example.com"},
		{"www.x.example.com", "", "example.com"},
		{"www.x.example.com", "com", "example.com"},
		{"www.x.example.com", "other.example.com", "example.com"},
		{"a.b.co.uk", "b.co.uk", "b.co.uk"},
	} {
		if got, err := searchScope(tt.fqdn, tt.zone); err != nil || got != tt.want {
			t.Errorf("searchScope(%s, %q) = %s, %v, want %s", tt.fqdn, tt.zone, got, err, tt.want)
		}
	}
}
