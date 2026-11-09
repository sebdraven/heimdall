package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sebdraven/heimdall/internal/cdn"
	"github.com/sebdraven/heimdall/internal/resolver"
	"github.com/sebdraven/heimdall/internal/store/ch"
	"github.com/sebdraven/heimdall/internal/store/pg"
)

const (
	graphMaxNodes = 500
	graphMaxDepth = 2
	graphMaxVT    = 2000
)

const (
	nodeDomain = "domain"
	nodeIP     = "ip"
	nodeNSSet  = "nsset"
	edgeCNAME  = "CNAME"
	edgeNSSet  = "NS_SET"
	edgeVT     = "VT"

	sourceHeimdall = "heimdall"
	sourceVT       = "vt"
)

// pdnsStore and watchStore are what the graph endpoints read from ClickHouse
// and Postgres.
type pdnsStore interface {
	PivotValues(ctx context.Context, fqdn string) ([]ch.PivotValue, error)
	CurrentState(ctx context.Context, domain string) ([]ch.Current, error)
	NSSet(ctx context.Context, fqdn string) (*ch.NSSet, error)
	Pivots(ctx context.Context, fqdn string, values []ch.PivotValue, limit int) ([]ch.Pivot, error)
	NSPairPivots(ctx context.Context, zone string, set []string, limit int) ([]ch.NSPairPivot, error)
	VTPairs(ctx context.Context, hosts, ips []string, limit int) ([]ch.VTPair, error)
	PDNSByRdata(ctx context.Context, rdata string, limit int) ([]ch.PDNSRecord, error)
	VTPairsByIP(ctx context.Context, ip string, limit int) ([]ch.VTPair, error)
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
	Source   string `json:"source"`
}

// graphEdge has first_seen and last_seen for a VT edge only.
type graphEdge struct {
	From      string     `json:"from"`
	To        string     `json:"to"`
	Kind      string     `json:"kind"`
	FirstSeen *time.Time `json:"first_seen,omitempty"`
	LastSeen  *time.Time `json:"last_seen,omitempty"`
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
// address (IPPeers) or an NS set (NSPeers, by nsset node id) with them, and
// the cached VirusTotal pairs (VT). Partial is set when a store call hit its
// limit. Addr, set for the graph of an address, is its first node, and
// IPPeers are then the names that resolved to it. NS, set for the graph of
// an NS set, is its first node, and NSPeers then hold the names whose set
// equals it.
type graphInput struct {
	Addr      string
	NS        []string
	Domains   []graphDomain
	IPPeers   []ch.Pivot
	NSPeers   map[string][]ch.NSPairPivot
	VT        []ch.VTPair
	MinShared int
	Partial   bool
}

func domainNode(fqdn string) graphNode {
	return graphNode{ID: "d:" + fqdn, Kind: nodeDomain, Label: fqdn, Href: "/domains/" + url.PathEscape(fqdn), Source: sourceHeimdall}
}

func ipNode(value string) graphNode {
	return graphNode{ID: "ip:" + value, Kind: nodeIP, Label: value, Href: "/rdata/" + url.PathEscape(value), Source: sourceHeimdall}
}

func vtNode(n graphNode) graphNode {
	n.Source = sourceVT
	return n
}

func nssetID(ns []string) string {
	return "ns:" + strings.Join(slices.Compact(slices.Sorted(slices.Values(ns))), ",")
}

func nssetNode(z *ch.NSSet) graphNode {
	ns := slices.Compact(slices.Sorted(slices.Values(z.NS)))
	return graphNode{ID: nssetID(ns), Kind: nodeNSSet, Label: strings.Join(ns, ", "), Href: "/domains/" + url.PathEscape(z.Zone), Source: sourceHeimdall}
}

type edgeKey struct{ from, to, kind string }

type graphBuilder struct {
	g     graphJSON
	limit int
	nodes map[string]bool
	edges map[edgeKey]bool
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

func (b *graphBuilder) edge(from, to graphNode, kind string) {
	b.addEdge(from, to, graphEdge{From: from.ID, To: to.ID, Kind: kind})
}

// addEdge adds to before from: a peer whose target was cut is not added.
func (b *graphBuilder) addEdge(from, to graphNode, e graphEdge) {
	if !b.node(to) || !b.node(from) {
		return
	}
	k := edgeKey{e.From, e.To, e.Kind}
	if !b.edges[k] {
		b.edges[k] = true
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
// with at least in.MinShared of them. VirusTotal pairs come last, and only
// those touching a node already in the graph. A CDN Addr gives an empty
// graph.
func buildGraph(in graphInput, cl *cdn.Classifier, limit int) graphJSON {
	b := &graphBuilder{
		g:     graphJSON{Nodes: []graphNode{}, Edges: []graphEdge{}, Truncated: in.Partial},
		limit: limit,
		nodes: map[string]bool{},
		edges: map[edgeKey]bool{},
	}
	ipHolders := map[string]map[string]bool{}
	if in.Addr != "" {
		if _, ok := cl.Classify(in.Addr); ok {
			b.g.ExcludedCDN = 1
			return b.g
		}
		b.node(ipNode(in.Addr))
		ipHolders[in.Addr] = map[string]bool{}
	}
	nsHolders := map[string]map[string]bool{}
	nsNodes := map[string]graphNode{}
	if len(in.NS) > 0 {
		n := nssetRootNode(in.NS)
		b.node(n)
		nsHolders[n.ID] = map[string]bool{}
		nsNodes[n.ID] = n
	}
	members := map[string]bool{}
	for _, d := range in.Domains {
		members[d.FQDN] = true
		b.node(domainNode(d.FQDN))
	}
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

	for _, p := range in.VT {
		from, to := vtNode(domainNode(p.HostName)), vtNode(ipNode(p.IP))
		if !b.nodes[from.ID] && !b.nodes[to.ID] {
			continue
		}
		if _, ok := cl.Classify(p.IP); ok {
			excluded[p.IP] = true
			continue
		}
		first, last := p.Period.First.UTC(), p.Period.Last.UTC()
		b.addEdge(from, to, graphEdge{From: from.ID, To: to.ID, Kind: edgeVT, FirstSeen: &first, LastSeen: &last})
	}
	b.g.ExcludedCDN = len(excluded)
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
// addresses or NS sets, and withVT the cached VirusTotal pairs of all of
// them. Past graphMaxNodes domains the rest is not read.
func (s *server) loadGraphInput(ctx context.Context, fqdns []string, peers, withVT bool) (graphInput, error) {
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
	if !withVT {
		return in, nil
	}
	hosts, ips := vtCandidates(in, s.cdn)
	pairs, err := s.graph.VTPairs(ctx, hosts, ips, graphMaxVT)
	if err != nil {
		return in, fmt.Errorf("vt pairs: %w", err)
	}
	in.VT = pairs
	in.Partial = in.Partial || len(pairs) == graphMaxVT
	return in, nil
}

// vtCandidates returns the names and the non-CDN addresses that may become
// nodes of the graph of in.
func vtCandidates(in graphInput, cl *cdn.Classifier) (hosts, ips []string) {
	for _, d := range in.Domains {
		hosts = append(hosts, d.FQDN)
		hosts = append(hosts, d.CNAMEs...)
		kept, _ := splitCDN(d.Values, cl)
		for _, v := range kept {
			ips = append(ips, v.RData)
		}
	}
	for _, p := range in.IPPeers {
		hosts = append(hosts, p.Domain)
	}
	for _, ms := range in.NSPeers {
		for _, m := range ms {
			hosts = append(hosts, m.Domain)
		}
	}
	return slices.Compact(slices.Sorted(slices.Values(hosts))), slices.Compact(slices.Sorted(slices.Values(ips)))
}

func (s *server) loadGraph(ctx context.Context, fqdns []string, peers bool, minShared int, withVT bool) (graphJSON, error) {
	in, err := s.loadGraphInput(ctx, fqdns, peers, withVT)
	if err != nil {
		return graphJSON{}, err
	}
	in.MinShared = minShared
	return s.watchGraph(ctx, buildGraph(in, s.cdn, graphMaxNodes))
}

// watchGraph marks the watched domains of g.
func (s *server) watchGraph(ctx context.Context, g graphJSON) (graphJSON, error) {
	watched, err := s.graph.DomainsByFQDN(ctx, graphFQDNs(g))
	if err != nil {
		return graphJSON{}, err
	}
	markWatched(&g, watched)
	return g, nil
}

// wantVT reports whether the request asks for the cached VirusTotal pairs,
// which are ignored when VirusTotal is not configured.
func (s *server) wantVT(r *http.Request) bool {
	return s.vt != nil && r.URL.Query().Get("vt") == "1"
}

// loadDomainGraph reads the graph of /graph/domain/{fqdn}?depth=.
func (s *server) loadDomainGraph(r *http.Request, withVT bool) (graphJSON, string, error) {
	fqdn := resolver.Name(r.PathValue("fqdn"))
	depth := intParam(r, "depth", 1, graphMaxDepth)
	g, err := s.loadGraph(r.Context(), []string{fqdn}, depth == graphMaxDepth, 1, withVT)
	return g, fqdn, err
}

// loadCampaignGraph reads the graph of /graph/campaign/{id}.
func (s *server) loadCampaignGraph(ctx context.Context, id int64, withVT bool) (graphJSON, string, error) {
	c, err := s.graph.Campaign(ctx, id)
	if err != nil {
		return graphJSON{}, "", err
	}
	domains, err := s.graph.Domains(ctx, &id)
	if err != nil {
		return graphJSON{}, "", err
	}
	fqdns := make([]string, 0, len(domains))
	for _, d := range domains {
		fqdns = append(fqdns, d.FQDN)
	}
	g, err := s.loadGraph(ctx, fqdns, true, 2, withVT)
	return g, c.Name, err
}

// apiGraphDomain serves /api/graph/domain/{fqdn}: depth 1 is the domain,
// its addresses, CNAME targets and NS set, depth 2 adds the names sharing
// them.
func (s *server) apiGraphDomain(w http.ResponseWriter, r *http.Request) {
	g, _, err := s.loadDomainGraph(r, s.wantVT(r))
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
	g, _, err := s.loadCampaignGraph(r.Context(), id, s.wantVT(r))
	if err != nil {
		s.apiStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, g)
}

// graphView is what graph.html shows. Path is set for a domain graph, which
// offers both depths. VT is nil when VirusTotal is not configured. CDN, the
// provider, is set for the graph of a CDN address, which is not drawn.
type graphView struct {
	Title    string
	Back     string
	Source   string
	Path     string
	Depth    int
	MaxNodes int
	VT       *graphVTView
	CDN      string
}

// graphVTView drives the VirusTotal controls. Remaining is -1 when unknown.
type graphVTView struct {
	On        bool
	Endpoint  string
	Budget    int
	Remaining int
}

// setVT adds the VirusTotal controls to v and, when asked, the cached pairs
// to its source.
func (s *server) setVT(r *http.Request, v *graphView, endpoint string) {
	if s.vt == nil {
		return
	}
	vv := &graphVTView{On: s.wantVT(r), Endpoint: endpoint, Budget: s.vt.Budget, Remaining: -1}
	if vv.On {
		sep := "?"
		if strings.Contains(v.Source, "?") {
			sep = "&"
		}
		v.Source += sep + "vt=1"
	}
	if n, err := s.vt.Remaining(r.Context()); err != nil {
		s.log.Warn("vt usage", "err", err)
	} else {
		vv.Remaining = n
	}
	v.VT = vv
}

func (s *server) graphDomainPage(w http.ResponseWriter, r *http.Request) {
	fqdn := resolver.Name(r.PathValue("fqdn"))
	depth := intParam(r, "depth", 1, graphMaxDepth)
	path := "/graph/domain/" + url.PathEscape(fqdn)
	v := graphView{
		Title: fqdn, Back: "/domains/" + url.PathEscape(fqdn),
		Source: path + "/data?depth=" + strconv.Itoa(depth), Path: path, Depth: depth, MaxNodes: graphMaxNodes,
	}
	s.setVT(r, &v, path+"/vt?depth="+strconv.Itoa(depth))
	s.render(w, r, "graph", http.StatusOK, v)
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
	v := graphView{
		Title: c.Name, Back: fmt.Sprintf("/campaigns/%d", id),
		Source: fmt.Sprintf("/graph/campaign/%d/data", id), MaxNodes: graphMaxNodes,
	}
	s.setVT(r, &v, fmt.Sprintf("/graph/campaign/%d/vt", id))
	s.render(w, r, "graph", http.StatusOK, v)
}

// enrichGraphDomain serves POST /graph/domain/{fqdn}/vt?depth= and POST
// /api/vt/enrich/domain/{fqdn}?depth=: starts looking up with VirusTotal the
// domain and IP nodes of the graph without VirusTotal.
func (s *server) enrichGraphDomain(w http.ResponseWriter, r *http.Request) {
	if s.vt == nil {
		apiError(w, http.StatusNotFound, "not found")
		return
	}
	g, fqdn, err := s.loadDomainGraph(r, false)
	if err != nil {
		s.apiStoreError(w, r, err)
		return
	}
	s.startEnrich(w, r, graphObjects(g), domainTarget(fqdn), "domain "+fqdn)
}

// enrichGraphCampaign serves POST /graph/campaign/{id}/vt and POST
// /api/vt/enrich/campaign/{id}.
func (s *server) enrichGraphCampaign(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if s.vt == nil || !ok {
		apiError(w, http.StatusNotFound, "not found")
		return
	}
	g, name, err := s.loadCampaignGraph(r.Context(), id, false)
	if err != nil {
		s.apiStoreError(w, r, err)
		return
	}
	s.startEnrich(w, r, graphObjects(g), campaignTarget(id), "campaign "+name)
}

// graphObjects returns the domain and IP nodes of g as VirusTotal objects.
func graphObjects(g graphJSON) []string {
	var objects []string
	for _, n := range g.Nodes {
		if n.Kind == nodeDomain || n.Kind == nodeIP {
			objects = append(objects, n.ID)
		}
	}
	return objects
}

// startEnrich looks up objects in the background unless an enrichment of
// target is running, and answers 202 with the state of the target's job.
func (s *server) startEnrich(w http.ResponseWriter, r *http.Request, objects []string, target, label string) {
	job, started := s.vtJobs.begin(target)
	if started {
		// The job outlives the request, which a proxy may cut.
		go s.runEnrich(context.WithoutCancel(r.Context()), target, label, objects)
	}
	writeJSON(w, http.StatusAccepted, job)
}

func (s *server) runEnrich(base context.Context, target, label string, objects []string) {
	ctx, cancel := context.WithTimeout(base, vtJobTimeout)
	defer cancel()
	sum, err := s.vt.Enrich(ctx, objects)
	note, errMsg := stopNote(sum.StoppedReason), ""
	if err != nil {
		s.log.Error("vt enrich", "target", label, "err", err)
		note, errMsg = ", failed", "internal error"
		if errors.Is(err, context.DeadlineExceeded) {
			errMsg = "timed out after " + vtJobTimeout.String()
		}
	}
	s.auditCtx(base, "vt.enrich", fmt.Sprintf("%s (looked up %d, cached %d, skipped for budget %d%s)",
		label, sum.LookedUp, sum.Cached, sum.SkippedBudget, note))
	s.vtJobs.finish(target, sum, errMsg)
}

func stopNote(reason string) string {
	if reason == "" {
		return ""
	}
	return ", stopped: " + reason
}

// vtJobDomain serves GET /graph/domain/{fqdn}/vt and GET
// /api/vt/enrich/domain/{fqdn}: the state of the enrichment of the domain,
// or {"state": "none"}.
func (s *server) vtJobDomain(w http.ResponseWriter, r *http.Request) {
	if s.vt == nil {
		apiError(w, http.StatusNotFound, "not found")
		return
	}
	s.writeVTJob(w, domainTarget(resolver.Name(r.PathValue("fqdn"))))
}

// vtJobCampaign serves GET /graph/campaign/{id}/vt and GET
// /api/vt/enrich/campaign/{id}.
func (s *server) vtJobCampaign(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if s.vt == nil || !ok {
		apiError(w, http.StatusNotFound, "not found")
		return
	}
	s.writeVTJob(w, campaignTarget(id))
}

func (s *server) writeVTJob(w http.ResponseWriter, target string) {
	job, ok := s.vtJobs.get(target)
	if !ok {
		job = vtJob{State: vtNone}
	}
	writeJSON(w, http.StatusOK, job)
}
