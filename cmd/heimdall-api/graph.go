package main

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/sebdraven/heimdall/internal/cdn"
	"github.com/sebdraven/heimdall/internal/resolver"
	"github.com/sebdraven/heimdall/internal/store/ch"
	"github.com/sebdraven/heimdall/internal/store/pg"
)

const (
	graphMaxNodes = 500
	graphMaxDepth = 2
)

const (
	nodeDomain = "domain"
	nodeIP     = "ip"
	nodeNSSet  = "nsset"
	edgeCNAME  = "CNAME"
	edgeNSSet  = "NS_SET"
)

// pdnsStore and watchStore are what the graph endpoints read from ClickHouse
// and Postgres.
type pdnsStore interface {
	PivotValues(ctx context.Context, fqdn string) ([]ch.PivotValue, error)
	CurrentState(ctx context.Context, domain string) ([]ch.Current, error)
	NSSet(ctx context.Context, fqdn string) (*ch.NSSet, error)
	Pivots(ctx context.Context, fqdn string, values []ch.PivotValue, limit int) ([]ch.Pivot, error)
	NSPairPivots(ctx context.Context, zone string, set []string, limit int) ([]ch.NSPairPivot, error)
}

type watchStore interface {
	Campaign(ctx context.Context, id int64) (pg.Campaign, error)
	Domains(ctx context.Context, campaignID *int64) ([]pg.Domain, error)
	DomainsByFQDN(ctx context.Context, fqdns []string) (map[string]pg.Domain, error)
}

type graphStores struct {
	pdnsStore
	watchStore
}

type graphNode struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Label    string `json:"label"`
	Watched  bool   `json:"watched"`
	Campaign string `json:"campaign"`
	Href     string `json:"href"`
}

type graphEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

type graphJSON struct {
	Nodes       []graphNode `json:"nodes"`
	Edges       []graphEdge `json:"edges"`
	Truncated   bool        `json:"truncated"`
	ExcludedCDN int         `json:"excluded_cdn"`
}

// graphDomain is what the store says about one domain of the graph.
type graphDomain struct {
	FQDN   string
	Values []ch.PivotValue
	CNAMEs []string
	NS     *ch.NSSet
}

// graphInput holds the domains of a graph and the other names sharing an
// address (IPPeers) or an NS set (NSPeers, by nsset node id) with them.
// Partial is set when a store call hit its limit.
type graphInput struct {
	Domains   []graphDomain
	IPPeers   []ch.Pivot
	NSPeers   map[string][]ch.NSPairPivot
	MinShared int
	Partial   bool
}

func domainNode(fqdn string) graphNode {
	return graphNode{ID: "d:" + fqdn, Kind: nodeDomain, Label: fqdn, Href: "/domains/" + url.PathEscape(fqdn)}
}

func ipNode(value string) graphNode {
	return graphNode{ID: "ip:" + value, Kind: nodeIP, Label: value, Href: "/rdata/" + url.PathEscape(value)}
}

func nssetID(ns []string) string {
	return "ns:" + strings.Join(slices.Compact(slices.Sorted(slices.Values(ns))), ",")
}

func nssetNode(z *ch.NSSet) graphNode {
	ns := slices.Compact(slices.Sorted(slices.Values(z.NS)))
	return graphNode{ID: nssetID(ns), Kind: nodeNSSet, Label: strings.Join(ns, ", "), Href: "/domains/" + url.PathEscape(z.Zone)}
}

type graphBuilder struct {
	g     graphJSON
	limit int
	nodes map[string]bool
	edges map[graphEdge]bool
}

// node adds n unless the graph is full, and reports whether n is in it.
func (b *graphBuilder) node(n graphNode) bool {
	if b.nodes[n.ID] {
		return true
	}
	if len(b.g.Nodes) >= b.limit {
		b.g.Truncated = true
		return false
	}
	b.nodes[n.ID] = true
	b.g.Nodes = append(b.g.Nodes, n)
	return true
}

// edge adds to before from: a peer whose target was cut is not added.
func (b *graphBuilder) edge(from, to graphNode, kind string) {
	if !b.node(to) || !b.node(from) {
		return
	}
	e := graphEdge{From: from.ID, To: to.ID, Kind: kind}
	if !b.edges[e] {
		b.edges[e] = true
		b.g.Edges = append(b.g.Edges, e)
	}
}

type peerLink struct {
	peer string
	to   graphNode
	kind string
}

// buildGraph turns in into a graph of at most limit nodes, the domains of in
// first. A peer outside them is kept if it shares an address or an NS set
// with at least in.MinShared of them.
func buildGraph(in graphInput, cl *cdn.Classifier, limit int) graphJSON {
	b := &graphBuilder{
		g:     graphJSON{Nodes: []graphNode{}, Edges: []graphEdge{}, Truncated: in.Partial},
		limit: limit,
		nodes: map[string]bool{},
		edges: map[graphEdge]bool{},
	}
	members := map[string]bool{}
	for _, d := range in.Domains {
		members[d.FQDN] = true
		b.node(domainNode(d.FQDN))
	}
	ipHolders := map[string]map[string]bool{}
	nsHolders := map[string]map[string]bool{}
	nsNodes := map[string]graphNode{}
	excluded := map[string]bool{}
	for _, d := range in.Domains {
		from := domainNode(d.FQDN)
		kept, cdns := splitCDN(d.Values, cl)
		for _, c := range cdns {
			excluded[c.Value] = true
		}
		for _, v := range kept {
			b.edge(from, ipNode(v.RData), v.RRType)
			addHolder(ipHolders, v.RData, d.FQDN)
		}
		for _, t := range d.CNAMEs {
			b.edge(from, domainNode(t), edgeCNAME)
		}
		if pairable(d.NS) {
			n := nssetNode(d.NS)
			b.edge(from, n, edgeNSSet)
			addHolder(nsHolders, n.ID, d.FQDN)
			nsNodes[n.ID] = n
		}
	}
	b.g.ExcludedCDN = len(excluded)

	shared := map[string]map[string]bool{}
	var links []peerLink
	for _, p := range in.IPPeers {
		holders, ok := ipHolders[p.RData]
		if !ok {
			continue
		}
		links = append(links, peerLink{peer: p.Domain, to: ipNode(p.RData), kind: p.RRType})
		for h := range holders {
			addHolder(shared, p.Domain, h)
		}
	}
	for _, id := range slices.Sorted(maps.Keys(in.NSPeers)) {
		holders, ok := nsHolders[id]
		if !ok {
			continue
		}
		for _, m := range in.NSPeers[id] {
			links = append(links, peerLink{peer: m.Domain, to: nsNodes[id], kind: edgeNSSet})
			for h := range holders {
				addHolder(shared, m.Domain, h)
			}
		}
	}
	slices.SortStableFunc(links, func(x, y peerLink) int { return cmp.Compare(x.peer, y.peer) })
	for _, l := range links {
		if members[l.peer] || len(shared[l.peer]) >= in.MinShared {
			b.edge(domainNode(l.peer), l.to, l.kind)
		}
	}
	return b.g
}

func addHolder(m map[string]map[string]bool, key, fqdn string) {
	if m[key] == nil {
		m[key] = map[string]bool{}
	}
	m[key][fqdn] = true
}

// cnameTargets returns the CNAME targets of the current state.
func cnameTargets(current []ch.Current) []string {
	var out []string
	for _, c := range current {
		if c.QType == "CNAME" {
			for _, v := range c.Rdata {
				out = append(out, resolver.Name(v))
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func graphFQDNs(g graphJSON) []string {
	var out []string
	for _, n := range g.Nodes {
		if fqdn, ok := strings.CutPrefix(n.ID, "d:"); ok && n.Kind == nodeDomain {
			out = append(out, fqdn)
		}
	}
	return out
}

func markWatched(g *graphJSON, watched map[string]pg.Domain) {
	for i := range g.Nodes {
		n := &g.Nodes[i]
		fqdn, ok := strings.CutPrefix(n.ID, "d:")
		if !ok || n.Kind != nodeDomain {
			continue
		}
		if d, ok := watched[fqdn]; ok {
			n.Watched, n.Campaign = true, d.Campaign
		}
	}
}

func (s *server) loadGraphDomain(ctx context.Context, fqdn string) (graphDomain, error) {
	d := graphDomain{FQDN: fqdn}
	var err error
	if d.Values, err = s.graph.PivotValues(ctx, fqdn); err != nil {
		return d, fmt.Errorf("pivot values: %w", err)
	}
	current, err := s.graph.CurrentState(ctx, fqdn)
	if err != nil {
		return d, fmt.Errorf("current state: %w", err)
	}
	d.CNAMEs = cnameTargets(current)
	if d.NS, err = s.graph.NSSet(ctx, fqdn); err != nil {
		return d, fmt.Errorf("ns set: %w", err)
	}
	return d, nil
}

// loadGraphInput reads the domains and, with peers, the names sharing their
// addresses or NS sets. Past graphMaxNodes domains the rest is not read.
func (s *server) loadGraphInput(ctx context.Context, fqdns []string, peers bool) (graphInput, error) {
	in := graphInput{NSPeers: map[string][]ch.NSPairPivot{}}
	if len(fqdns) > graphMaxNodes {
		fqdns, in.Partial = fqdns[:graphMaxNodes], true
	}
	for _, fqdn := range fqdns {
		d, err := s.loadGraphDomain(ctx, fqdn)
		if err != nil {
			return in, err
		}
		in.Domains = append(in.Domains, d)
		if !peers {
			continue
		}
		kept, _ := splitCDN(d.Values, s.cdn)
		pivots, err := s.graph.Pivots(ctx, fqdn, kept, graphMaxNodes)
		if err != nil {
			return in, fmt.Errorf("pivots: %w", err)
		}
		in.IPPeers = append(in.IPPeers, pivots...)
		in.Partial = in.Partial || len(pivots) == graphMaxNodes
		if !pairable(d.NS) {
			continue
		}
		id := nssetID(d.NS.NS)
		if _, done := in.NSPeers[id]; done {
			continue
		}
		matches, err := s.graph.NSPairPivots(ctx, d.NS.Zone, d.NS.NS, graphMaxNodes)
		if err != nil {
			return in, fmt.Errorf("ns pair pivots: %w", err)
		}
		in.NSPeers[id] = matches
		in.Partial = in.Partial || len(matches) == graphMaxNodes
	}
	return in, nil
}

func (s *server) loadGraph(ctx context.Context, fqdns []string, peers bool, minShared int) (graphJSON, error) {
	in, err := s.loadGraphInput(ctx, fqdns, peers)
	if err != nil {
		return graphJSON{}, err
	}
	in.MinShared = minShared
	g := buildGraph(in, s.cdn, graphMaxNodes)
	watched, err := s.graph.DomainsByFQDN(ctx, graphFQDNs(g))
	if err != nil {
		return graphJSON{}, err
	}
	markWatched(&g, watched)
	return g, nil
}

// apiGraphDomain serves /api/graph/domain/{fqdn}: depth 1 is the domain,
// its addresses, CNAME targets and NS set, depth 2 adds the names sharing
// them.
func (s *server) apiGraphDomain(w http.ResponseWriter, r *http.Request) {
	fqdn := resolver.Name(r.PathValue("fqdn"))
	depth := intParam(r, "depth", 1, graphMaxDepth)
	g, err := s.loadGraph(r.Context(), []string{fqdn}, depth == graphMaxDepth, 1)
	if err != nil {
		s.apiStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, g)
}

// apiGraphCampaign serves /api/graph/campaign/{id}: the campaign's domains
// at depth 1, and the names sharing an address or an NS set with at least
// two of them.
func (s *server) apiGraphCampaign(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		apiError(w, http.StatusNotFound, "not found")
		return
	}
	if _, err := s.graph.Campaign(r.Context(), id); err != nil {
		s.apiStoreError(w, r, err)
		return
	}
	domains, err := s.graph.Domains(r.Context(), &id)
	if err != nil {
		s.apiStoreError(w, r, err)
		return
	}
	fqdns := make([]string, 0, len(domains))
	for _, d := range domains {
		fqdns = append(fqdns, d.FQDN)
	}
	g, err := s.loadGraph(r.Context(), fqdns, true, 2)
	if err != nil {
		s.apiStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, g)
}

// graphView is what graph.html shows. Path is set for a domain graph, which
// offers both depths.
type graphView struct {
	Title    string
	Back     string
	Source   string
	Path     string
	Depth    int
	MaxNodes int
}

func (s *server) graphDomainPage(w http.ResponseWriter, r *http.Request) {
	fqdn := resolver.Name(r.PathValue("fqdn"))
	depth := intParam(r, "depth", 1, graphMaxDepth)
	path := "/graph/domain/" + url.PathEscape(fqdn)
	s.render(w, r, "graph", http.StatusOK, graphView{
		Title: fqdn, Back: "/domains/" + url.PathEscape(fqdn),
		Source: path + "/data?depth=" + strconv.Itoa(depth), Path: path, Depth: depth, MaxNodes: graphMaxNodes,
	})
}

func (s *server) graphCampaignPage(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		s.fail(w, r, http.StatusNotFound, "Not found.", nil)
		return
	}
	c, err := s.graph.Campaign(r.Context(), id)
	if err != nil {
		s.storeFail(w, r, err)
		return
	}
	s.render(w, r, "graph", http.StatusOK, graphView{
		Title: c.Name, Back: fmt.Sprintf("/campaigns/%d", id),
		Source: fmt.Sprintf("/graph/campaign/%d/data", id), MaxNodes: graphMaxNodes,
	})
}
