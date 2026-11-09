package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sebdraven/heimdall/internal/cdn"
	"github.com/sebdraven/heimdall/internal/enrich"
	"github.com/sebdraven/heimdall/internal/resolver"
	"github.com/sebdraven/heimdall/internal/store/ch"
	"github.com/sebdraven/heimdall/internal/store/pg"
)

const (
	enrichJobTimeout = 2 * time.Minute
	enrichSaveTime   = 10 * time.Second
)

// enrichStore keeps the enrichments and lists the resolvers.
type enrichStore interface {
	Resolvers(ctx context.Context) ([]pg.Resolver, error)
	SaveDomainEnrich(ctx context.Context, r enrich.Result) error
	DomainEnrich(ctx context.Context, fqdn string) (enrich.Result, error)
}

type enrichCounts struct {
	DNS        int `json:"dns"`
	RDAP       int `json:"rdap"`
	CT         int `json:"ct"`
	Subdomains int `json:"subdomains"`
}

// enrichSummary ends an enrichment job; vtjob.js shows Summary.
type enrichSummary struct {
	Status  string            `json:"status"`
	Counts  enrichCounts      `json:"counts"`
	Errors  map[string]string `json:"errors,omitempty"`
	Summary string            `json:"summary"`
}

// summarize counts the values of each source: DNS values, 1 for a
// registration, the certificates and the subdomains.
func summarize(r enrich.Result) enrichSummary {
	var c enrichCounts
	if r.DNS != nil {
		for _, rec := range r.DNS.Records {
			c.DNS += len(rec.Rdata)
		}
	}
	if r.RDAP != nil {
		c.RDAP = 1
	}
	if r.CT != nil {
		c.CT = r.CT.Total
	}
	if r.Subdomains != nil {
		c.Subdomains = len(r.Subdomains.Names)
	}
	counts := map[string]int{enrich.SourceDNS: c.DNS, enrich.SourceRDAP: c.RDAP, enrich.SourceCT: c.CT, enrich.SourceSubdomains: c.Subdomains}
	parts := make([]string, 0, len(enrich.Sources))
	for _, src := range enrich.Sources {
		if _, failed := r.Errors[src]; failed {
			parts = append(parts, src+" failed")
		} else {
			parts = append(parts, fmt.Sprintf("%s %d", src, counts[src]))
		}
	}
	return enrichSummary{Status: r.Status, Counts: c, Errors: r.Errors, Summary: r.Status + ": " + strings.Join(parts, ", ")}
}

// enrichFQDN returns the name of the path, or answers 400.
func enrichFQDN(w http.ResponseWriter, r *http.Request) (string, bool) {
	fqdn, err := resolver.NormalizeFQDN(r.PathValue("fqdn"))
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid fqdn")
		return "", false
	}
	return fqdn, true
}

// enrichDomain serves POST /domains/{fqdn}/enrich and POST
// /api/enrich/domain/{fqdn}: one enrichment runs at a time per name.
func (s *server) enrichDomain(w http.ResponseWriter, r *http.Request) {
	fqdn, ok := enrichFQDN(w, r)
	if !ok {
		return
	}
	job := s.enrichJobs.start(r.Context(), domainTarget(fqdn), enrichJobTimeout, func(ctx context.Context) (enrichSummary, string) {
		return s.runDomainEnrich(ctx, fqdn)
	})
	writeJSON(w, http.StatusAccepted, job)
}

// enrichJobDomain serves GET /domains/{fqdn}/enrich and GET
// /api/enrich/domain/{fqdn}: the state of the enrichment, or
// {"state": "none"}.
func (s *server) enrichJobDomain(w http.ResponseWriter, r *http.Request) {
	fqdn, ok := enrichFQDN(w, r)
	if !ok {
		return
	}
	cur, found := s.enrichJobs.get(domainTarget(fqdn))
	if !found {
		cur = job[enrichSummary]{State: jobNone}
	}
	writeJSON(w, http.StatusOK, cur)
}

func (s *server) runDomainEnrich(ctx context.Context, fqdn string) (enrichSummary, string) {
	res := s.enrich.Run(ctx, fqdn, s.activeResolver(ctx))
	sum := summarize(res)
	// The result is kept even when the job ran out of time.
	save, cancel := context.WithTimeout(context.WithoutCancel(ctx), enrichSaveTime)
	defer cancel()
	errMsg := ""
	if err := s.enrichDB.SaveDomainEnrich(save, res); err != nil {
		s.log.Error("save enrichment", "fqdn", fqdn, "err", err)
		errMsg = "internal error"
	}
	s.auditCtx(save, "domain.enrich", fmt.Sprintf("%s (%s)", fqdn, sum.Summary))
	return sum, errMsg
}

// activeResolver returns the address of the first enabled resolver, "" if
// there is none.
func (s *server) activeResolver(ctx context.Context) string {
	rs, err := s.enrichDB.Resolvers(ctx)
	if err != nil {
		s.log.Warn("resolvers", "err", err)
		return ""
	}
	for _, r := range rs {
		if r.Enabled {
			return r.Address
		}
	}
	return ""
}

type enrichJSON struct {
	FQDN       string             `json:"fqdn"`
	FetchedAt  time.Time          `json:"fetched_at"`
	Status     string             `json:"status"`
	DNS        *enrich.DNS        `json:"dns"`
	Zone       *enrich.Zone       `json:"zone"`
	RDAP       *enrich.RDAP       `json:"rdap"`
	CT         *enrich.CT         `json:"ct"`
	Subdomains *enrich.Subdomains `json:"subdomains"`
	Errors     map[string]string  `json:"errors"`
	Graph      graphJSON          `json:"graph"`
}

func toEnrichJSON(r enrich.Result, g graphJSON) enrichJSON {
	errs := r.Errors
	if errs == nil {
		errs = map[string]string{}
	}
	return enrichJSON{
		FQDN: r.FQDN, FetchedAt: r.FetchedAt.UTC(), Status: r.Status, DNS: r.DNS, Zone: r.Zone, RDAP: r.RDAP,
		CT: r.CT, Subdomains: r.Subdomains, Errors: errs, Graph: g,
	}
}

// apiDomainEnrich serves GET /domains/{fqdn}/enrich/data and GET
// /api/domains/{fqdn}/enrich: the last enrichment and its graph, 404
// before the first one.
func (s *server) apiDomainEnrich(w http.ResponseWriter, r *http.Request) {
	fqdn, ok := enrichFQDN(w, r)
	if !ok {
		return
	}
	res, err := s.enrichDB.DomainEnrich(r.Context(), fqdn)
	if err != nil {
		s.apiStoreError(w, r, err)
		return
	}
	g, err := s.watchGraph(r.Context(), enrichGraph(res, s.cdn, graphMaxNodes))
	if err != nil {
		s.apiStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toEnrichJSON(res, g))
}

// enrichGraph draws an enrichment around its name: the addresses, CDN ones
// aside, the CNAME and MX targets, the NS set of the zone, the subdomains
// and the names of the certificates, wildcards as their base name.
func enrichGraph(r enrich.Result, cl *cdn.Classifier, limit int) graphJSON {
	b := newGraphBuilder(limit, false)
	from := domainNode(r.FQDN)
	b.node(from)
	excluded := map[string]bool{}
	if r.DNS != nil {
		for _, rec := range r.DNS.Records {
			for _, v := range rec.Rdata {
				switch rec.QType {
				case "A", "AAAA":
					if _, isCDN := cl.Classify(v); isCDN {
						excluded[v] = true
						continue
					}
					b.edge(from, ipNode(v), rec.QType)
				case "CNAME":
					b.edge(from, domainNode(resolver.Name(v)), edgeCNAME)
				case "MX":
					if mx := mxHost(v); mx != "" {
						b.edge(from, domainNode(mx), edgeMX)
					}
				}
			}
		}
	}
	if r.Zone != nil {
		if z := (&ch.NSSet{Zone: r.Zone.Name, NS: r.Zone.NS}); pairable(z) {
			b.edge(from, nssetNode(z), edgeNSSet)
		}
	}
	if r.Subdomains != nil {
		for _, d := range r.Subdomains.Names {
			if d.Name != r.FQDN {
				b.edge(from, domainNode(d.Name), edgeSub)
			}
		}
	}
	if r.CT != nil {
		for _, n := range r.CT.Names {
			if name, err := resolver.NormalizeFQDN(strings.TrimPrefix(n, "*.")); err == nil && name != r.FQDN {
				b.edge(from, domainNode(name), edgeCert)
			}
		}
	}
	b.g.ExcludedCDN = len(excluded)
	return b.g
}

// mxHost returns the exchange of an MX value, "" for a null MX.
func mxHost(v string) string {
	f := strings.Fields(v)
	if len(f) != 2 {
		return ""
	}
	return resolver.Name(f[1])
}

// enrichView is the Enrichment section of a domain page. Result is nil
// before the first enrichment.
type enrichView struct {
	Endpoint string
	Result   *enrich.Result
}

func (s *server) loadDomainEnrich(ctx context.Context, fqdn string) (*enrichView, error) {
	v := &enrichView{Endpoint: "/domains/" + url.PathEscape(fqdn) + "/enrich"}
	res, err := s.enrichDB.DomainEnrich(ctx, fqdn)
	switch {
	case err == nil:
		v.Result = &res
	case !errors.Is(err, pg.ErrNotFound):
		return nil, err
	}
	return v, nil
}
