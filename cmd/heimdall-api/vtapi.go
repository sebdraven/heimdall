package main

import (
	"context"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"
)

type vtIPJSON struct {
	IP         string       `json:"ip"`
	LookedUpAt *time.Time   `json:"looked_up_at"`
	Status     *string      `json:"status"`
	Names      []vtNameJSON `json:"names"`
}

type vtNameJSON struct {
	HostName  string    `json:"host_name"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Watched   bool      `json:"watched"`
	Campaign  string    `json:"campaign"`
}

func toVTIPJSON(ip string, v *vtView) vtIPJSON {
	out := vtIPJSON{IP: ip, Names: make([]vtNameJSON, 0, len(v.Names))}
	out.LookedUpAt, out.Status = lookedUp(v)
	for _, n := range v.Names {
		nj := vtNameJSON{HostName: n.Name, FirstSeen: n.Period.First.UTC(), LastSeen: n.Period.Last.UTC(), Watched: n.Domain != nil}
		if n.Domain != nil {
			nj.Campaign = n.Domain.Campaign
		}
		out.Names = append(out.Names, nj)
	}
	return out
}

// apiVTIP serves GET /api/vt/ip/{ip}: what the rdata page shows of an
// address, from the cache only.
func (s *server) apiVTIP(w http.ResponseWriter, r *http.Request) {
	if s.vt == nil {
		apiError(w, http.StatusNotFound, "not found")
		return
	}
	a, err := netip.ParseAddr(strings.TrimSpace(r.PathValue("ip")))
	if err != nil {
		apiError(w, http.StatusBadRequest, "not an IP address")
		return
	}
	v, err := s.loadVTIP(r.Context(), a.String())
	if err != nil {
		s.apiStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// loadVTIP reads what VirusTotal saw on ip, from the cache only.
func (s *server) loadVTIP(ctx context.Context, ip string) (vtIPJSON, error) {
	fetch, pairs, err := s.ipVTCache(ctx, ip)
	if err != nil {
		return vtIPJSON{}, err
	}
	names := make([]string, 0, len(pairs))
	for _, p := range pairs {
		names = append(names, p.HostName)
	}
	slices.Sort(names)
	watched, err := s.pg.DomainsByFQDN(ctx, slices.Compact(names))
	if err != nil {
		return vtIPJSON{}, err
	}
	return toVTIPJSON(ip, rdataVTView(fetch, pairs, watched)), nil
}

type vtBudgetJSON struct {
	Budget    int `json:"budget"`
	UsedToday int `json:"used_today"`
	Remaining int `json:"remaining"`
}

// apiVTBudget serves GET /api/vt/budget: the lookups of the UTC day.
func (s *server) apiVTBudget(w http.ResponseWriter, r *http.Request) {
	if s.vt == nil {
		apiError(w, http.StatusNotFound, "not found")
		return
	}
	used, remaining, err := s.vt.Usage(r.Context())
	if err != nil {
		s.apiStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, vtBudgetJSON{Budget: s.vt.Budget, UsedToday: used, Remaining: remaining})
}
