// Package enrich gathers what can be learnt of a name on demand: its live
// DNS records and zone, its RDAP registration, the names of its
// Certificate Transparency logs, the subdomains in passive DNS and its past
// captures in Lookyloo.
package enrich

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

const (
	StatusOK      = "ok"
	StatusPartial = "partial"
	StatusError   = "error"
)

const (
	SourceDNS        = "dns"
	SourceRDAP       = "rdap"
	SourceCT         = "ct"
	SourceSubdomains = "subdomains"
	SourceLookyloo   = "lookyloo"
)

// Sources lists the sources of an enrichment.
var Sources = []string{SourceDNS, SourceRDAP, SourceCT, SourceSubdomains, SourceLookyloo}

// MaxSubdomains caps the subdomains read from passive DNS.
const MaxSubdomains = 500

// ErrNoResolver fails the DNS source when no resolver is enabled.
var ErrNoResolver = errors.New("no active resolver")

// Result is an enrichment. A source that failed is nil, its message in
// Errors, except CT and Lookyloo, which keep what they read before the
// error.
type Result struct {
	FQDN       string
	FetchedAt  time.Time
	Status     string
	DNS        *DNS
	Zone       *Zone
	RDAP       *RDAP
	CT         *CT
	Subdomains *Subdomains
	Lookyloo   *Lookyloo
	Errors     map[string]string
}

// Subdomain is a name below a zone in passive DNS.
type Subdomain struct {
	Name      string    `json:"name"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Subdomains are the names below Zone, latest first. Truncated is set at
// MaxSubdomains.
type Subdomains struct {
	Zone      string      `json:"zone"`
	Names     []Subdomain `json:"names"`
	Truncated bool        `json:"truncated"`
}

type Registry interface {
	Lookup(ctx context.Context, name string) (*RDAP, error)
}

type CTLog interface {
	Lookup(ctx context.Context, zone string) (*CT, error)
}

type PassiveDNS interface {
	SubdomainsOf(ctx context.Context, zone string, limit int) ([]Subdomain, error)
}

type CaptureArchive interface {
	Captures(ctx context.Context, fqdn string) (*Lookyloo, error)
}

// Enricher queries the sources; Lookyloo is nil when not configured.
type Enricher struct {
	DNS      Resolver
	RDAP     Registry
	CT       CTLog
	PDNS     PassiveDNS
	Lookyloo CaptureArchive
	Now      func() time.Time
}

// Run queries the five sources at once, DNS through server, empty when no
// resolver is enabled. CT and passive DNS search below the zone found by
// DNS, or below the registrable domain of fqdn; Lookyloo searches fqdn. A
// Lookyloo not configured fails without counting in the status.
func (e *Enricher) Run(ctx context.Context, fqdn, server string) Result {
	res := Result{FQDN: fqdn, Errors: map[string]string{}}
	var mu sync.Mutex
	fail := func(source string, err error) {
		mu.Lock()
		defer mu.Unlock()
		res.Errors[source] = err.Error()
	}

	var wg sync.WaitGroup
	var scope string
	var scopeErr error
	zoneKnown := make(chan struct{})
	wg.Go(func() {
		defer close(zoneKnown)
		var zone string
		if server == "" {
			fail(SourceDNS, ErrNoResolver)
		} else if d, z, err := Lookup(ctx, e.DNS, server, fqdn); err != nil {
			fail(SourceDNS, err)
		} else {
			res.DNS, res.Zone = d, z
			if z != nil {
				zone = z.Name
			}
		}
		scope, scopeErr = searchScope(fqdn, zone)
	})
	wg.Go(func() {
		r, err := e.RDAP.Lookup(ctx, fqdn)
		if err != nil {
			fail(SourceRDAP, err)
			return
		}
		res.RDAP = r
	})
	wg.Go(func() {
		<-zoneKnown
		if scopeErr != nil {
			fail(SourceCT, scopeErr)
			return
		}
		c, err := e.CT.Lookup(ctx, scope)
		if err != nil {
			fail(SourceCT, err)
		}
		res.CT = c
	})
	wg.Go(func() {
		<-zoneKnown
		if scopeErr != nil {
			fail(SourceSubdomains, scopeErr)
			return
		}
		names, err := e.PDNS.SubdomainsOf(ctx, scope, MaxSubdomains)
		if err != nil {
			fail(SourceSubdomains, fmt.Errorf("passive DNS: %w", err))
			return
		}
		if names == nil {
			names = []Subdomain{}
		}
		res.Subdomains = &Subdomains{Zone: scope, Names: names, Truncated: len(names) == MaxSubdomains}
	})
	wg.Go(func() {
		if e.Lookyloo == nil {
			fail(SourceLookyloo, ErrLookylooNotConfigured)
			return
		}
		l, err := e.Lookyloo.Captures(ctx, fqdn)
		if err != nil {
			fail(SourceLookyloo, err)
		}
		res.Lookyloo = l
	})
	wg.Wait()

	now := time.Now
	if e.Now != nil {
		now = e.Now
	}
	res.FetchedAt = now().UTC()
	failed, sources := len(res.Errors), len(Sources)
	if e.Lookyloo == nil {
		failed, sources = failed-1, sources-1
	}
	switch {
	case failed == 0:
		res.Status = StatusOK
		if len(res.Errors) == 0 {
			res.Errors = nil
		}
	case failed == sources:
		res.Status = StatusError
	default:
		res.Status = StatusPartial
	}
	return res
}

// searchScope returns zone when it is fqdn or one of its ancestors at or
// below the registrable domain, else the registrable domain.
func searchScope(fqdn, zone string) (string, error) {
	reg, err := publicsuffix.EffectiveTLDPlusOne(fqdn)
	if err != nil {
		return "", fmt.Errorf("no registrable domain for %s", fqdn)
	}
	if zone != "" && within(zone, reg) && within(fqdn, zone) {
		return zone, nil
	}
	return reg, nil
}

// within reports whether name is zone or below it.
func within(name, zone string) bool {
	return name == zone || strings.HasSuffix(name, "."+zone)
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}
