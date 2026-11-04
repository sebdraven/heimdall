package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/sebdraven/heimdall/internal/store/ch"
	"github.com/sebdraven/heimdall/internal/store/pg"
)

const vtPageRows = 500

// vtView is the VirusTotal section of a domain or rdata page, read from the
// cache only. Status is empty when the object was never looked up; Endpoint,
// the enrichment job, is set on a domain page only.
type vtView struct {
	FetchedAt time.Time
	Status    string
	Endpoint  string
	IPs       []vtIPRow
	Names     []vtNameRow
}

// vtIPRow is an address VirusTotal saw for a domain. Heimdall is set when
// the domain's passive DNS has it too.
type vtIPRow struct {
	IP       string
	Period   ch.Period
	Heimdall bool
}

// vtNameRow is a name VirusTotal saw on an address. Domain is nil outside
// the watchlist.
type vtNameRow struct {
	Name   string
	Period ch.Period
	Domain *pg.Domain
}

func domainVTView(f pg.VTFetch, pairs []ch.VTPair, pdns []ch.PDNSRecord) *vtView {
	seen := make(map[string]bool, len(pdns))
	for _, p := range pdns {
		seen[p.RData] = true
	}
	v := &vtView{FetchedAt: f.FetchedAt, Status: f.Status}
	for _, p := range pairs {
		v.IPs = append(v.IPs, vtIPRow{IP: p.IP, Period: p.Period, Heimdall: seen[p.IP]})
	}
	return v
}

func rdataVTView(f pg.VTFetch, pairs []ch.VTPair, watched map[string]pg.Domain) *vtView {
	v := &vtView{FetchedAt: f.FetchedAt, Status: f.Status}
	for _, p := range pairs {
		row := vtNameRow{Name: p.HostName, Period: p.Period}
		if d, ok := watched[p.HostName]; ok {
			row.Domain = &d
		}
		v.Names = append(v.Names, row)
	}
	return v
}

// lastVTFetch returns the last lookup of object, zero if there was none.
func (s *server) lastVTFetch(ctx context.Context, object string) (pg.VTFetch, error) {
	f, err := s.pg.LastVTFetch(ctx, object)
	if errors.Is(err, pg.ErrNotFound) {
		return pg.VTFetch{}, nil
	}
	return f, err
}

// loadDomainVT reads the VirusTotal section of fqdn, nil without VirusTotal.
func (s *server) loadDomainVT(ctx context.Context, fqdn string, pdns []ch.PDNSRecord) (*vtView, error) {
	if s.vt == nil {
		return nil, nil
	}
	f, err := s.lastVTFetch(ctx, "d:"+fqdn)
	if err != nil {
		return nil, err
	}
	pairs, err := s.ch.VTPairsByHost(ctx, fqdn, vtPageRows)
	if err != nil {
		return nil, fmt.Errorf("vt pairs: %w", err)
	}
	v := domainVTView(f, pairs, pdns)
	v.Endpoint = "/graph/domain/" + url.PathEscape(fqdn) + "/vt?depth=1"
	return v, nil
}

type vtDetailJSON struct {
	LookedUpAt  time.Time          `json:"looked_up_at"`
	Status      string             `json:"status"`
	Resolutions []vtResolutionJSON `json:"resolutions"`
}

type vtResolutionJSON struct {
	IP        string    `json:"ip"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// toVTDetailJSON is nil without VirusTotal or when the domain was never
// looked up.
func toVTDetailJSON(v *vtView) *vtDetailJSON {
	if v == nil || v.Status == "" {
		return nil
	}
	out := &vtDetailJSON{LookedUpAt: v.FetchedAt.UTC(), Status: v.Status, Resolutions: make([]vtResolutionJSON, 0, len(v.IPs))}
	for _, r := range v.IPs {
		out.Resolutions = append(out.Resolutions, vtResolutionJSON{IP: r.IP, FirstSeen: r.Period.First.UTC(), LastSeen: r.Period.Last.UTC()})
	}
	return out
}
