package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sebdraven/heimdall/internal/correlate"
	"github.com/sebdraven/heimdall/internal/resolver"
	"github.com/sebdraven/heimdall/internal/store/ch"
	"github.com/sebdraven/heimdall/internal/store/pg"
)

const (
	correlateDelay   = time.Minute
	correlateEvery   = time.Hour
	correlateTimeout = 2 * time.Minute
	// correlateChunk bounds the domains of one zone query.
	correlateChunk    = 500
	correlateVTPairs  = 100000
	correlateHops     = 4
	correlateNewLinks = 500
	correlatePast     = 1000
	correlateLinked   = 5
	newLinksWindow    = 7 * 24 * time.Hour

	nodeCampaign = "campaign"
	edgeMember   = "member"
)

// correlationCH and correlationPG are what the correlation reads and writes;
// it never calls an external service.
type correlationCH interface {
	OwnedRecords(ctx context.Context, names, rrtypes []string) ([]ch.Owned, error)
	ZoneNSSets(ctx context.Context, domains []string) (map[string]*ch.NSSet, error)
	ZoneSOAs(ctx context.Context, domains []string) (map[string]*ch.SOA, error)
	VTPairs(ctx context.Context, hosts, ips []string, limit int) ([]ch.VTPair, error)
}

type correlationPG interface {
	Campaign(ctx context.Context, id int64) (pg.Campaign, error)
	Campaigns(ctx context.Context) ([]pg.Campaign, error)
	Domains(ctx context.Context, campaignID *int64) ([]pg.Domain, error)
	EnrichCerts(ctx context.Context) ([]pg.EnrichCert, error)
	EnrichRegistrations(ctx context.Context) ([]pg.EnrichRegistration, error)
	UpsertCorrelationLinks(ctx context.Context, links []pg.CorrelationLink, at time.Time) ([]pg.CorrelationLink, error)
	CorrelationLinks(ctx context.Context, f pg.CorrelationFilter) ([]pg.CorrelationLink, error)
}

type correlationStores struct {
	correlationCH
	correlationPG
}

// correlationSnapshot is the last computation, its links dated from the
// history.
type correlationSnapshot struct {
	ComputedAt time.Time
	Evidence   []correlate.Evidence
}

// correlateLoop computes the links correlateDelay after start-up, then
// every correlateEvery.
func (s *server) correlateLoop(ctx context.Context) {
	t := time.NewTimer(correlateDelay)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.runCorrelation(ctx, correlateTimeout)
			t.Reset(correlateEvery)
		}
	}
}

// runCorrelation computes and records the links, or abandons the run past
// timeout, leaving the history and the last snapshot as they were.
func (s *server) runCorrelation(ctx context.Context, timeout time.Duration) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	snap, res, err := s.correlate(ctx, s.now().UTC())
	switch {
	case err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded):
		s.log.Warn("correlation abandoned", "timeout", timeout.String(), "duration_ms", time.Since(start).Milliseconds(), "err", err)
		return
	case err != nil && errors.Is(err, context.Canceled):
		return
	case err != nil:
		s.log.Error("correlation", "err", err)
		return
	}
	s.corrSnap.Store(snap)
	s.log.Info("correlation", "links", len(snap.Evidence), "duration_ms", time.Since(start).Milliseconds(),
		"skipped_cdn", res.Skipped[correlate.SkipCDN], "skipped_shared", res.Skipped[correlate.SkipShared],
		"skipped_provider", res.Skipped[correlate.SkipProvider])
}

func (s *server) correlate(ctx context.Context, at time.Time) (*correlationSnapshot, correlate.Result, error) {
	in, err := s.loadCorrelationInput(ctx)
	if err != nil {
		return nil, correlate.Result{}, err
	}
	res := correlate.Compute(in)
	if err := ctx.Err(); err != nil {
		return nil, res, err
	}
	links := make([]pg.CorrelationLink, 0, len(res.Evidence))
	for _, e := range res.Evidence {
		links = append(links, pg.CorrelationLink{
			Kind: e.Kind, Value: e.Value, DomainA: e.DomainA, CampaignA: e.CampaignA, DomainB: e.DomainB, CampaignB: e.CampaignB,
		})
	}
	saved, err := s.corr.UpsertCorrelationLinks(ctx, links, at)
	if err != nil {
		return nil, res, fmt.Errorf("upsert links: %w", err)
	}
	stored := make(map[correlate.Key]pg.CorrelationLink, len(saved))
	for _, l := range saved {
		stored[correlate.Key{Kind: l.Kind, Value: l.Value, DomainA: l.DomainA, DomainB: l.DomainB}] = l
	}
	for i := range res.Evidence {
		if l, ok := stored[res.Evidence[i].Key()]; ok {
			res.Evidence[i].FirstSeen, res.Evidence[i].LastSeen = l.FirstSeen.UTC(), l.LastSeen.UTC()
		}
	}
	return &correlationSnapshot{ComputedAt: at, Evidence: res.Evidence}, res, nil
}

// loadCorrelationInput reads what Postgres and ClickHouse hold of the
// watched domains.
func (s *server) loadCorrelationInput(ctx context.Context) (correlate.Input, error) {
	in := correlate.Input{CDN: s.cdn}
	domains, err := s.corr.Domains(ctx, nil)
	if err != nil {
		return in, fmt.Errorf("domains: %w", err)
	}
	fqdns := make([]string, 0, len(domains))
	for _, d := range domains {
		var campaign int64
		if d.CampaignID != nil {
			campaign = *d.CampaignID
		}
		in.Domains = append(in.Domains, correlate.Domain{FQDN: d.FQDN, Campaign: campaign})
		fqdns = append(fqdns, d.FQDN)
	}

	owned, err := s.corr.OwnedRecords(ctx, fqdns, []string{"A", "AAAA", "CNAME", "MX"})
	if err != nil {
		return in, fmt.Errorf("owned records: %w", err)
	}
	var targets []string
	for _, o := range owned {
		r := correlate.Record{Domain: o.RRName, Value: o.RData, Period: o.Period}
		switch o.RRType {
		case "A", "AAAA":
			in.IPs = append(in.IPs, r)
		case "CNAME":
			r.Value = resolver.Name(o.RData)
			in.CNAMEs = append(in.CNAMEs, r)
			targets = append(targets, r.Value)
		case "MX":
			if r.Value = mxHost(o.RData); r.Value != "" {
				in.MXs = append(in.MXs, r)
			}
		}
	}
	if in.Chains, err = s.loadChains(ctx, targets); err != nil {
		return in, err
	}

	for chunk := range slices.Chunk(fqdns, correlateChunk) {
		zones, err := s.corr.ZoneNSSets(ctx, chunk)
		if err != nil {
			return in, fmt.Errorf("ns sets: %w", err)
		}
		for _, d := range chunk {
			if z := zones[d]; z != nil {
				in.NSSets = append(in.NSSets, correlate.NSSet{Domain: d, Zone: z.Zone, NS: z.NS, Period: z.Period})
			}
		}
		soas, err := s.corr.ZoneSOAs(ctx, chunk)
		if err != nil {
			return in, fmt.Errorf("soas: %w", err)
		}
		for _, d := range chunk {
			if z := soas[d]; z != nil {
				in.SOAs = append(in.SOAs, correlate.SOA{Domain: d, Zone: z.Zone, MName: z.MName, RName: z.RName, Period: z.Period})
			}
		}
		pairs, err := s.corr.VTPairs(ctx, chunk, nil, correlateVTPairs)
		if err != nil {
			return in, fmt.Errorf("vt pairs: %w", err)
		}
		if len(pairs) == correlateVTPairs {
			s.log.Warn("correlation: vt pairs truncated", "limit", correlateVTPairs)
		}
		for _, p := range pairs {
			in.VT = append(in.VT, correlate.Record{Domain: p.HostName, Value: p.IP, Period: p.Period})
		}
	}

	certs, err := s.corr.EnrichCerts(ctx)
	if err != nil {
		return in, fmt.Errorf("certificates: %w", err)
	}
	for _, c := range certs {
		cert := correlate.Cert{Domain: c.FQDN, SHA256: c.SHA256}
		if c.NotBefore != nil && c.NotAfter != nil {
			cert.NotBefore, cert.NotAfter = c.NotBefore.UTC(), c.NotAfter.UTC()
		}
		in.Certs = append(in.Certs, cert)
	}
	regs, err := s.corr.EnrichRegistrations(ctx)
	if err != nil {
		return in, fmt.Errorf("registrations: %w", err)
	}
	for _, r := range regs {
		in.Registrations = append(in.Registrations, correlate.Registration{
			Domain: r.FQDN, Registrable: r.Domain, RegistrarID: r.RegistrarID, Registrar: r.Registrar, Registered: r.Registered.UTC(),
		})
	}
	return in, nil
}

// loadChains follows the CNAME targets in passive DNS, correlateHops hops
// at most.
func (s *server) loadChains(ctx context.Context, targets []string) (map[string]correlate.Chain, error) {
	chains := map[string]correlate.Chain{}
	next := slices.Compact(slices.Sorted(slices.Values(targets)))
	for hop := 0; hop < correlateHops && len(next) > 0; hop++ {
		owned, err := s.corr.OwnedRecords(ctx, next, []string{"A", "AAAA", "CNAME"})
		if err != nil {
			return nil, fmt.Errorf("cname chains: %w", err)
		}
		for _, n := range next {
			chains[n] = correlate.Chain{}
		}
		var found []string
		for _, o := range owned {
			c := chains[o.RRName]
			if o.RRType == "CNAME" {
				t := resolver.Name(o.RData)
				c.CNAMEs = append(c.CNAMEs, t)
				if _, seen := chains[t]; !seen {
					found = append(found, t)
				}
			} else {
				c.IPs = append(c.IPs, o.RData)
			}
			chains[o.RRName] = c
		}
		next = slices.Compact(slices.Sorted(slices.Values(found)))
	}
	return chains, nil
}

type correlationCampaignJSON struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

type correlationPairJSON struct {
	A         int64          `json:"a"`
	B         int64          `json:"b"`
	Score     float64        `json:"score"`
	Counts    map[string]int `json:"counts"`
	FirstSeen *time.Time     `json:"first_seen"`
	LastSeen  *time.Time     `json:"last_seen"`
}

type correlationLinkJSON struct {
	Kind      string    `json:"kind"`
	Value     string    `json:"value"`
	DomainA   string    `json:"domain_a"`
	CampaignA int64     `json:"campaign_a"`
	DomainB   string    `json:"domain_b"`
	CampaignB int64     `json:"campaign_b"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type correlationsJSON struct {
	Campaigns  []correlationCampaignJSON `json:"campaigns"`
	Pairs      []correlationPairJSON     `json:"pairs"`
	NewLinks   []correlationLinkJSON     `json:"new_links"`
	ComputedAt *time.Time                `json:"computed_at"`
}

// correlationEvidenceJSON is a current link. Weight is that of the last
// computation; Period is when both domains held the value, the validity of
// a certificate or the two registration dates.
type correlationEvidenceJSON struct {
	Kind      string      `json:"kind"`
	Value     string      `json:"value"`
	DomainA   string      `json:"domain_a"`
	CampaignA int64       `json:"campaign_a"`
	DomainB   string      `json:"domain_b"`
	CampaignB int64       `json:"campaign_b"`
	Weight    float64     `json:"weight"`
	Period    *periodJSON `json:"period"`
	FirstSeen *time.Time  `json:"first_seen"`
	LastSeen  *time.Time  `json:"last_seen"`
}

// correlationPairDetailJSON holds the current links of a pair and, in Past,
// those of the history no longer found.
type correlationPairDetailJSON struct {
	A          correlationCampaignJSON   `json:"a"`
	B          correlationCampaignJSON   `json:"b"`
	Score      float64                   `json:"score"`
	Counts     map[string]int            `json:"counts"`
	Evidence   []correlationEvidenceJSON `json:"evidence"`
	Past       []correlationLinkJSON     `json:"past"`
	ComputedAt *time.Time                `json:"computed_at"`
}

func timeOrNil(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	t = t.UTC()
	return &t
}

func toCorrelationLinkJSON(l pg.CorrelationLink) correlationLinkJSON {
	return correlationLinkJSON{
		Kind: l.Kind, Value: l.Value, DomainA: l.DomainA, CampaignA: l.CampaignA, DomainB: l.DomainB, CampaignB: l.CampaignB,
		FirstSeen: l.FirstSeen.UTC(), LastSeen: l.LastSeen.UTC(),
	}
}

type correlationParams struct {
	minScore float64
	kinds    []string
	since    time.Time
}

// correlationParams reads ?min_score= (0 to 1), ?kinds= (comma-separated)
// and ?since= (7 days ago by default).
func (s *server) correlationParams(r *http.Request) (correlationParams, error) {
	q := r.URL.Query()
	p := correlationParams{since: s.now().Add(-newLinksWindow)}
	if v := strings.TrimSpace(q.Get("min_score")); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil || math.IsNaN(f) || f < 0 || f > 1 {
			return p, errors.New("min_score must be between 0 and 1")
		}
		p.minScore = f
	}
	if v := q.Get("kinds"); v != "" {
		for _, k := range strings.Split(v, ",") {
			k = strings.TrimSpace(k)
			if !slices.Contains(correlate.Kinds, k) {
				return p, fmt.Errorf("unknown kind %q (known: %s)", k, strings.Join(correlate.Kinds, ", "))
			}
			if !slices.Contains(p.kinds, k) {
				p.kinds = append(p.kinds, k)
			}
		}
	}
	if v := q.Get("since"); v != "" {
		t, err := parseTime(v, s.now())
		if err != nil {
			return p, err
		}
		p.since = t
	}
	return p, nil
}

// apiCorrelations serves GET /api/correlations and GET /correlations/data.
func (s *server) apiCorrelations(w http.ResponseWriter, r *http.Request) {
	p, err := s.correlationParams(r)
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := s.loadCorrelations(r.Context(), p)
	if err != nil {
		s.apiStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) loadCorrelations(ctx context.Context, p correlationParams) (correlationsJSON, error) {
	out := correlationsJSON{Campaigns: []correlationCampaignJSON{}, Pairs: []correlationPairJSON{}, NewLinks: []correlationLinkJSON{}}
	campaigns, err := s.corr.Campaigns(ctx)
	if err != nil {
		return out, err
	}
	for _, c := range campaigns {
		out.Campaigns = append(out.Campaigns, correlationCampaignJSON{ID: c.ID, Name: c.Name})
	}
	if snap := s.corrSnap.Load(); snap != nil {
		out.ComputedAt = timeOrNil(snap.ComputedAt)
		for _, pr := range correlate.Pairs(correlate.OfKinds(snap.Evidence, p.kinds)) {
			if pr.Score >= p.minScore {
				out.Pairs = append(out.Pairs, correlationPairJSON{
					A: pr.A, B: pr.B, Score: pr.Score, Counts: pr.Counts, FirstSeen: timeOrNil(pr.FirstSeen), LastSeen: timeOrNil(pr.LastSeen),
				})
			}
		}
	}
	links, err := s.corr.CorrelationLinks(ctx, pg.CorrelationFilter{Since: p.since, Kinds: p.kinds, Limit: correlateNewLinks})
	if err != nil {
		return out, err
	}
	for _, l := range links {
		out.NewLinks = append(out.NewLinks, toCorrelationLinkJSON(l))
	}
	return out, nil
}

// pairIDs reads {a} and {b}, two different campaign ids.
func pairIDs(r *http.Request) (a, b int64, ok bool) {
	a, errA := strconv.ParseInt(r.PathValue("a"), 10, 64)
	b, errB := strconv.ParseInt(r.PathValue("b"), 10, 64)
	return a, b, errA == nil && errB == nil && a > 0 && b > 0 && a != b
}

// apiCorrelationPair serves GET /api/correlations/{a}/{b} and GET
// /correlations/{a}/{b}/data: the links of the pair, highest weight then
// latest first seen first.
func (s *server) apiCorrelationPair(w http.ResponseWriter, r *http.Request) {
	a, b, ok := pairIDs(r)
	if !ok {
		apiError(w, http.StatusNotFound, "not found")
		return
	}
	p, err := s.correlationParams(r)
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := s.loadCorrelationPair(r.Context(), a, b, p.kinds)
	if err != nil {
		s.apiStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) loadCorrelationPair(ctx context.Context, a, b int64, kinds []string) (correlationPairDetailJSON, error) {
	ca, err := s.corr.Campaign(ctx, a)
	if err != nil {
		return correlationPairDetailJSON{}, err
	}
	cb, err := s.corr.Campaign(ctx, b)
	if err != nil {
		return correlationPairDetailJSON{}, err
	}
	out := correlationPairDetailJSON{
		A: correlationCampaignJSON{ID: ca.ID, Name: ca.Name}, B: correlationCampaignJSON{ID: cb.ID, Name: cb.Name},
		Counts: map[string]int{}, Evidence: []correlationEvidenceJSON{}, Past: []correlationLinkJSON{},
	}
	current := map[correlate.Key]bool{}
	if snap := s.corrSnap.Load(); snap != nil {
		out.ComputedAt = timeOrNil(snap.ComputedAt)
		ev := slices.Clone(correlate.OfKinds(correlate.Between(snap.Evidence, a, b), kinds))
		correlate.SortByWeight(ev)
		if pairs := correlate.Pairs(ev); len(pairs) > 0 {
			out.Score, out.Counts = pairs[0].Score, pairs[0].Counts
		}
		for _, e := range ev {
			current[e.Key()] = true
			ej := correlationEvidenceJSON{
				Kind: e.Kind, Value: e.Value, DomainA: e.DomainA, CampaignA: e.CampaignA, DomainB: e.DomainB, CampaignB: e.CampaignB,
				Weight: e.Weight, FirstSeen: timeOrNil(e.FirstSeen), LastSeen: timeOrNil(e.LastSeen),
			}
			if e.Period != nil {
				ej.Period = &periodJSON{First: e.Period.First.UTC(), Last: e.Period.Last.UTC()}
			}
			out.Evidence = append(out.Evidence, ej)
		}
	}
	history, err := s.corr.CorrelationLinks(ctx, pg.CorrelationFilter{Kinds: kinds, CampaignA: a, CampaignB: b, Limit: correlatePast})
	if err != nil {
		return out, err
	}
	for _, l := range history {
		if !current[correlate.Key{Kind: l.Kind, Value: l.Value, DomainA: l.DomainA, DomainB: l.DomainB}] {
			out.Past = append(out.Past, toCorrelationLinkJSON(l))
		}
	}
	slices.SortStableFunc(out.Past, func(x, y correlationLinkJSON) int { return y.LastSeen.Compare(x.LastSeen) })
	return out, nil
}

func campaignNode(c pg.Campaign) graphNode {
	return graphNode{
		ID: fmt.Sprintf("c:%d", c.ID), Kind: nodeCampaign, Label: c.Name,
		Href: fmt.Sprintf("/campaigns/%d/analytics", c.ID), Source: sourceHeimdall,
	}
}

func memberNode(fqdn string, c pg.Campaign) graphNode {
	n := domainNode(fqdn)
	n.Watched, n.Campaign = true, c.Name
	return n
}

// valueNode is the node of what a link shares; a certificate shows its whole
// SHA-256.
func valueNode(kind, value string) graphNode {
	switch kind {
	case correlate.KindIP, correlate.KindVT:
		return ipNode(value)
	case correlate.KindNSSet:
		return nssetRootNode(strings.Split(value, ","))
	case correlate.KindCNAME, correlate.KindMX:
		return domainNode(value)
	case correlate.KindCert:
		return graphNode{ID: "cert:" + value, Kind: "cert", Label: value, Source: sourceHeimdall}
	case correlate.KindSOA:
		return graphNode{ID: "soa:" + value, Kind: "soa", Label: value, Source: sourceHeimdall}
	}
	return graphNode{ID: "rdap:" + value, Kind: "registrar", Label: value, Source: sourceHeimdall}
}

// parseExpand reads ?expand=a,b, zero when absent.
func parseExpand(v string) (a, b int64, err error) {
	if v == "" {
		return 0, 0, nil
	}
	sa, sb, ok := strings.Cut(v, ",")
	a, errA := strconv.ParseInt(strings.TrimSpace(sa), 10, 64)
	b, errB := strconv.ParseInt(strings.TrimSpace(sb), 10, 64)
	if !ok || errA != nil || errB != nil || a <= 0 || b <= 0 || a == b {
		return 0, 0, errors.New("expand must be two campaign ids, a,b")
	}
	return a, b, nil
}

// apiCorrelationGraph serves GET /api/correlations/graph and GET
// /correlations/graph/data: a node per linked campaign and an edge per kind
// of link, and with ?expand=a,b the domains of a and b and what they share.
func (s *server) apiCorrelationGraph(w http.ResponseWriter, r *http.Request) {
	p, err := s.correlationParams(r)
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	a, b, err := parseExpand(r.URL.Query().Get("expand"))
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	g, err := s.loadCorrelationGraph(r.Context(), p, a, b)
	if err != nil {
		s.apiStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, g)
}

func (s *server) loadCorrelationGraph(ctx context.Context, p correlationParams, a, b int64) (graphJSON, error) {
	bld := newGraphBuilder(graphMaxNodes, false)
	campaigns := map[int64]pg.Campaign{}
	list, err := s.corr.Campaigns(ctx)
	if err != nil {
		return graphJSON{}, err
	}
	for _, c := range list {
		campaigns[c.ID] = c
	}
	if a != 0 {
		for _, id := range []int64{a, b} {
			if _, ok := campaigns[id]; !ok {
				return graphJSON{}, pg.ErrNotFound
			}
		}
	}
	snap := s.corrSnap.Load()
	if snap == nil {
		return bld.g, nil
	}
	ev := correlate.OfKinds(snap.Evidence, p.kinds)
	for _, pr := range correlate.Pairs(ev) {
		ca, okA := campaigns[pr.A]
		cb, okB := campaigns[pr.B]
		if pr.Score < p.minScore || !okA || !okB {
			continue
		}
		for _, kind := range correlate.Kinds {
			if pr.Counts[kind] > 0 {
				bld.edge(campaignNode(ca), campaignNode(cb), kind)
			}
		}
	}
	if a == 0 {
		return bld.g, nil
	}
	for _, e := range correlate.Between(ev, a, b) {
		ca, cb := campaigns[e.CampaignA], campaigns[e.CampaignB]
		da, db, v := memberNode(e.DomainA, ca), memberNode(e.DomainB, cb), valueNode(e.Kind, e.Value)
		bld.edge(campaignNode(ca), da, edgeMember)
		bld.edge(campaignNode(cb), db, edgeMember)
		bld.edge(da, v, e.Kind)
		bld.edge(db, v, e.Kind)
	}
	return bld.g, nil
}

type correlationKindView struct {
	Kind   string
	Weight string
}

type correlationsView struct {
	Kinds    []correlationKindView
	MaxNodes int
}

func correlationKinds() []correlationKindView {
	out := make([]correlationKindView, 0, len(correlate.Kinds))
	for _, k := range correlate.Kinds {
		w := strconv.FormatFloat(correlate.Weight(k), 'f', 1, 64)
		if k == correlate.KindIP {
			w += "/n"
		}
		out = append(out, correlationKindView{Kind: k, Weight: w})
	}
	return out
}

func (s *server) correlationsPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "correlations", http.StatusOK, correlationsView{Kinds: correlationKinds(), MaxNodes: graphMaxNodes})
}

// linkedCampaign is a campaign linked to the one of an analytics page.
// Kinds lists the distinct values shared, by kind.
type linkedCampaign struct {
	ID    int64
	Name  string
	Score float64
	Kinds string
}

// linkedCampaigns returns the correlateLinked campaigns of highest score
// linked to id, and whether the links were computed.
func (s *server) linkedCampaigns(ctx context.Context, id int64) ([]linkedCampaign, bool, error) {
	snap := s.corrSnap.Load()
	if snap == nil {
		return nil, false, nil
	}
	var pairs []correlate.Pair
	for _, pr := range correlate.Pairs(snap.Evidence) {
		if pr.A == id || pr.B == id {
			pairs = append(pairs, pr)
		}
		if len(pairs) == correlateLinked {
			break
		}
	}
	if len(pairs) == 0 {
		return nil, true, nil
	}
	campaigns, err := s.corr.Campaigns(ctx)
	if err != nil {
		return nil, true, err
	}
	names := map[int64]string{}
	for _, c := range campaigns {
		names[c.ID] = c.Name
	}
	out := make([]linkedCampaign, 0, len(pairs))
	for _, pr := range pairs {
		other := pr.A
		if other == id {
			other = pr.B
		}
		var kinds []string
		for _, k := range correlate.Kinds {
			if n := pr.Counts[k]; n > 0 {
				kinds = append(kinds, fmt.Sprintf("%s %d", k, n))
			}
		}
		out = append(out, linkedCampaign{ID: other, Name: cmp.Or(names[other], fmt.Sprintf("#%d", other)), Score: pr.Score, Kinds: strings.Join(kinds, ", ")})
	}
	return out, true, nil
}
