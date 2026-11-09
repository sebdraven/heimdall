package main

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/sebdraven/heimdall/internal/store/ch"
)

// vtIPMaxNames caps the names of a depth 2 enrichment of an address.
const vtIPMaxNames = 100

// parseIP returns the canonical spelling of an address, an IPv4-mapped one
// unmapped as in the VirusTotal cache.
func parseIP(v string) (string, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(v))
	if err != nil {
		return "", false
	}
	return a.Unmap().String(), true
}

// vtIP returns the address of the path, or answers 404 without VirusTotal
// and 400 when it is not an address.
func (s *server) vtIP(w http.ResponseWriter, r *http.Request) (string, bool) {
	if s.vt == nil {
		apiError(w, http.StatusNotFound, "not found")
		return "", false
	}
	ip, ok := parseIP(r.PathValue("ip"))
	if !ok {
		apiError(w, http.StatusBadRequest, "not an IP address")
	}
	return ip, ok
}

// enrichIP serves POST /rdata/{ip}/vt?depth= and POST
// /api/vt/enrich/ip/{ip}?depth=: depth 1 looks up the address with
// VirusTotal, depth 2 also the names seen on it. One job runs per address,
// whatever the depth.
func (s *server) enrichIP(w http.ResponseWriter, r *http.Request) {
	ip, ok := s.vtIP(w, r)
	if !ok {
		return
	}
	objects := []string{"ip:" + ip}
	if intParam(r, "depth", 1, graphMaxDepth) == graphMaxDepth {
		names, err := s.ipNames(r.Context(), ip)
		if err != nil {
			s.apiStoreError(w, r, err)
			return
		}
		for _, n := range names {
			objects = append(objects, "d:"+n)
		}
	}
	s.startEnrich(w, r, objects, ipTarget(ip), "ip "+ip)
}

// vtJobIP serves GET /rdata/{ip}/vt and GET /api/vt/enrich/ip/{ip}.
func (s *server) vtJobIP(w http.ResponseWriter, r *http.Request) {
	if ip, ok := s.vtIP(w, r); ok {
		s.writeVTJob(w, ipTarget(ip))
	}
}

// ipNames returns the names seen on ip by Heimdall's passive DNS and in the
// VirusTotal cache, latest first, at most vtIPMaxNames. A CDN address has
// none: sharing it is not an infrastructure link.
func (s *server) ipNames(ctx context.Context, ip string) ([]string, error) {
	if _, ok := s.cdn.Classify(ip); ok {
		return nil, nil
	}
	records, err := s.graph.PDNSByRdata(ctx, ip, rdataLimit)
	if err != nil {
		return nil, fmt.Errorf("pdns by rdata: %w", err)
	}
	pairs, err := s.graph.VTPairsByIP(ctx, ip, vtPageRows)
	if err != nil {
		return nil, fmt.Errorf("vt pairs: %w", err)
	}
	return latestNames(records, pairs, vtIPMaxNames), nil
}

// latestNames merges the owners of the A/AAAA records and the names of the
// pairs, latest last seen first, at most limit.
func latestNames(records []ch.PDNSRecord, pairs []ch.VTPair, limit int) []string {
	last := map[string]time.Time{}
	see := func(name string, t time.Time) {
		if cur, ok := last[name]; !ok || t.After(cur) {
			last[name] = t
		}
	}
	for _, rec := range records {
		if addrType(rec.RRType) {
			see(rec.RRName, rec.LastSeen)
		}
	}
	for _, p := range pairs {
		see(p.HostName, p.Period.Last)
	}
	names := slices.SortedFunc(maps.Keys(last), func(a, b string) int {
		return cmp.Or(last[b].Compare(last[a]), cmp.Compare(a, b))
	})
	return names[:min(limit, len(names))]
}

func addrType(rrtype string) bool { return rrtype == "A" || rrtype == "AAAA" }

// loadIPGraph reads the graph of /graph/ip/{ip}: the address, the names
// Heimdall's passive DNS saw resolve to it and, withVT, those VirusTotal
// saw. Nothing is read for a CDN address.
func (s *server) loadIPGraph(ctx context.Context, ip string, withVT bool) (graphJSON, error) {
	in := graphInput{Addr: ip}
	if _, isCDN := s.cdn.Classify(ip); !isCDN {
		records, err := s.graph.PDNSByRdata(ctx, ip, rdataLimit)
		if err != nil {
			return graphJSON{}, fmt.Errorf("pdns by rdata: %w", err)
		}
		for _, rec := range records {
			if addrType(rec.RRType) {
				in.IPPeers = append(in.IPPeers, ch.Pivot{Domain: rec.RRName, RRType: rec.RRType, RData: ip})
			}
		}
		in.Partial = len(records) == rdataLimit
		if withVT {
			if in.VT, err = s.graph.VTPairsByIP(ctx, ip, graphMaxVT); err != nil {
				return graphJSON{}, fmt.Errorf("vt pairs: %w", err)
			}
			in.Partial = in.Partial || len(in.VT) == graphMaxVT
		}
	}
	return s.watchGraph(ctx, buildGraph(in, s.cdn, graphMaxNodes))
}

// apiGraphIP serves /api/graph/ip/{ip} and /graph/ip/{ip}/data.
func (s *server) apiGraphIP(w http.ResponseWriter, r *http.Request) {
	ip, ok := parseIP(r.PathValue("ip"))
	if !ok {
		apiError(w, http.StatusBadRequest, "not an IP address")
		return
	}
	g, err := s.loadIPGraph(r.Context(), ip, s.wantVT(r))
	if err != nil {
		s.apiStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, g)
}

// graphIPPage serves /graph/ip/{ip}. Its "Enrich with VT" enriches the
// address at depth 2, the nodes of the graph.
func (s *server) graphIPPage(w http.ResponseWriter, r *http.Request) {
	ip, ok := parseIP(r.PathValue("ip"))
	if !ok {
		s.fail(w, r, http.StatusBadRequest, "Not an IP address.", nil)
		return
	}
	rdata := "/rdata/" + url.PathEscape(ip)
	v := graphView{Title: ip, Back: rdata, Source: "/graph/ip/" + url.PathEscape(ip) + "/data", MaxNodes: graphMaxNodes}
	if p, ok := s.cdn.Classify(ip); ok {
		v.CDN = p
	} else {
		s.setVT(r, &v, rdata+"/vt?depth=2")
	}
	if err := s.setLink(r, &v, 0, ""); err != nil {
		s.storeFail(w, r, err)
		return
	}
	s.render(w, r, "graph", http.StatusOK, v)
}
