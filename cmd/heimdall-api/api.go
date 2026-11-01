package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/sebdraven/heimdall/internal/auth"
	"github.com/sebdraven/heimdall/internal/cdn"
	gjallarhorn "github.com/sebdraven/heimdall/internal/changes"
	"github.com/sebdraven/heimdall/internal/cof"
	"github.com/sebdraven/heimdall/internal/resolver"
	"github.com/sebdraven/heimdall/internal/store/ch"
	"github.com/sebdraven/heimdall/internal/store/pg"
)

const (
	pdnsLimit   = 10000
	eventsLimit = 10000
)

type domainJSON struct {
	FQDN            string    `json:"fqdn"`
	Campaign        string    `json:"campaign"`
	IntervalSeconds int       `json:"interval_seconds"`
	Enabled         bool      `json:"enabled"`
	Source          string    `json:"source"`
	AddedAt         time.Time `json:"added_at"`
}

func toDomainJSON(d pg.Domain) domainJSON {
	return domainJSON{
		FQDN: d.FQDN, Campaign: d.Campaign, IntervalSeconds: d.IntervalSeconds,
		Enabled: d.Enabled, Source: d.Source, AddedAt: d.AddedAt.UTC(),
	}
}

func toDomainsJSON(ds []pg.Domain) []domainJSON {
	out := make([]domainJSON, 0, len(ds))
	for _, d := range ds {
		out = append(out, toDomainJSON(d))
	}
	return out
}

type currentJSON struct {
	QType    string            `json:"qtype"`
	Resolver string            `json:"resolver"`
	TS       time.Time         `json:"ts"`
	Rcode    string            `json:"rcode"`
	TTL      uint32            `json:"ttl"`
	Rdata    []string          `json:"rdata"`
	CDN      map[string]string `json:"cdn,omitempty"`
}

type changeJSON struct {
	TS        time.Time `json:"ts"`
	Scope     string    `json:"scope"`
	QType     string    `json:"qtype"`
	Resolver  string    `json:"resolver"`
	PrevRcode string    `json:"prev_rcode"`
	NewRcode  string    `json:"new_rcode"`
	Added     []string  `json:"added"`
	Removed   []string  `json:"removed"`
	PrevTTL   uint32    `json:"prev_ttl"`
	NewTTL    uint32    `json:"new_ttl"`
}

type pdnsJSON struct {
	RRName    string    `json:"rrname"`
	RRType    string    `json:"rrtype"`
	RData     string    `json:"rdata"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     uint64    `json:"count"`
}

type domainDetailJSON struct {
	Domain  *domainJSON   `json:"domain"`
	Current []currentJSON `json:"current"`
	Changes []changeJSON  `json:"changes"`
	PDNS    []pdnsJSON    `json:"pdns"`
}

// strs encodes a nil slice as [] rather than null.
func strs(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// cdnValues maps the CDN addresses among values to their provider, nil if
// there are none.
func cdnValues(values []string, cl *cdn.Classifier) map[string]string {
	var out map[string]string
	for _, v := range values {
		if p, ok := cl.Classify(v); ok {
			if out == nil {
				out = map[string]string{}
			}
			out[v] = p
		}
	}
	return out
}

// changeScope tells a change of the name from one of its zone.
func changeScope(domain string) string {
	if strings.HasPrefix(domain, gjallarhorn.ZonePrefix) {
		return "zone"
	}
	return "name"
}

func toDomainDetailJSON(dd domainDetail, cl *cdn.Classifier) domainDetailJSON {
	out := domainDetailJSON{
		Current: make([]currentJSON, 0, len(dd.Current)),
		Changes: make([]changeJSON, 0, len(dd.Changes)),
		PDNS:    make([]pdnsJSON, 0, len(dd.PDNS)),
	}
	if dd.Domain != nil {
		d := toDomainJSON(*dd.Domain)
		out.Domain = &d
	}
	for _, c := range dd.Current {
		out.Current = append(out.Current, currentJSON{
			QType: c.QType, Resolver: c.Resolver, TS: c.TS.UTC(), Rcode: c.Rcode, TTL: c.TTL, Rdata: strs(c.Rdata),
			CDN: cdnValues(c.Rdata, cl),
		})
	}
	for _, c := range dd.Changes {
		out.Changes = append(out.Changes, changeJSON{
			TS: c.TS.UTC(), Scope: changeScope(c.Domain), QType: c.QType, Resolver: c.Resolver, PrevRcode: c.PrevRcode, NewRcode: c.NewRcode,
			Added: strs(c.Added), Removed: strs(c.Removed), PrevTTL: c.PrevTTL, NewTTL: c.NewTTL,
		})
	}
	for _, p := range dd.PDNS {
		out.PDNS = append(out.PDNS, pdnsJSON{
			RRName: p.RRName, RRType: p.RRType, RData: p.RData,
			FirstSeen: p.FirstSeen.UTC(), LastSeen: p.LastSeen.UTC(), Count: p.Count,
		})
	}
	return out
}

type campaignJSON struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Family      string    `json:"family"`
	Description string    `json:"description"`
	Domains     int       `json:"domains"`
	CreatedAt   time.Time `json:"created_at"`
}

func toCampaignJSON(c pg.Campaign) campaignJSON {
	return campaignJSON{ID: c.ID, Name: c.Name, Family: c.Family, Description: c.Description, Domains: c.Domains, CreatedAt: c.CreatedAt}
}

type eventJSON struct {
	TS       time.Time       `json:"ts"`
	Domain   string          `json:"domain"`
	Campaign string          `json:"campaign"`
	Kind     string          `json:"kind"`
	QType    string          `json:"qtype"`
	Resolver string          `json:"resolver"`
	Detail   json.RawMessage `json:"detail"`
}

type periodJSON struct {
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
}

type pivotJSON struct {
	Domain  string      `json:"domain"`
	RRType  string      `json:"rrtype"`
	RData   string      `json:"rdata"`
	Target  periodJSON  `json:"target"`
	Other   periodJSON  `json:"other"`
	Overlap *periodJSON `json:"overlap"`
}

type excludedCDNJSON struct {
	Value    string `json:"value"`
	Provider string `json:"provider"`
}

type pivotsJSON struct {
	Pivots      []pivotJSON       `json:"pivots"`
	ExcludedCDN []excludedCDNJSON `json:"excluded_cdn"`
}

// splitCDN sets aside the A and AAAA values that are CDN addresses, which
// unrelated names share.
func splitCDN(values []ch.PivotValue, cl *cdn.Classifier) (kept []ch.PivotValue, excluded []excludedCDNJSON) {
	excluded = []excludedCDNJSON{}
	for _, v := range values {
		if v.RRType == "A" || v.RRType == "AAAA" {
			if p, ok := cl.Classify(v.RData); ok {
				excluded = append(excluded, excludedCDNJSON{Value: v.RData, Provider: p})
				continue
			}
		}
		kept = append(kept, v)
	}
	return kept, excluded
}

type searchNameJSON struct {
	RRName    string    `json:"rrname"`
	RRTypes   []string  `json:"rrtypes"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     uint64    `json:"count"`
	Watched   bool      `json:"watched"`
	Campaign  string    `json:"campaign"`
}

type searchValueJSON struct {
	RData     string    `json:"rdata"`
	RRType    string    `json:"rrtype"`
	Names     uint64    `json:"names"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type searchJSON struct {
	Query     string            `json:"query"`
	Kind      string            `json:"kind"`
	Domains   []domainJSON      `json:"domains"`
	Names     []searchNameJSON  `json:"names"`
	Values    []searchValueJSON `json:"values"`
	Truncated struct {
		Domains bool `json:"domains"`
		Names   bool `json:"names"`
		Values  bool `json:"values"`
	} `json:"truncated"`
}

func toSearchJSON(v searchView) searchJSON {
	out := searchJSON{
		Query: v.Query, Kind: v.Kind,
		Domains: toDomainsJSON(v.Domains),
		Names:   make([]searchNameJSON, 0, len(v.Names)),
		Values:  make([]searchValueJSON, 0, len(v.Values)),
	}
	for _, n := range v.Names {
		nj := searchNameJSON{
			RRName: n.RRName, RRTypes: strs(n.RRTypes), FirstSeen: n.FirstSeen.UTC(), LastSeen: n.LastSeen.UTC(), Count: n.Count,
			Watched: n.Domain != nil,
		}
		if n.Domain != nil {
			nj.Campaign = n.Domain.Campaign
		}
		out.Names = append(out.Names, nj)
	}
	for _, val := range v.Values {
		out.Values = append(out.Values, searchValueJSON{
			RData: val.RData, RRType: val.RRType, Names: val.Names, FirstSeen: val.FirstSeen.UTC(), LastSeen: val.LastSeen.UTC(),
		})
	}
	out.Truncated.Domains, out.Truncated.Names, out.Truncated.Values = v.Truncated.Domains, v.Truncated.Names, v.Truncated.Values
	return out
}

func apiError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *server) apiStoreError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, pg.ErrNotFound):
		apiError(w, http.StatusNotFound, "not found")
	case errors.Is(err, pg.ErrConflict):
		apiError(w, http.StatusConflict, "already exists")
	case errors.Is(err, pg.ErrInvalid):
		apiError(w, http.StatusBadRequest, "invalid value")
	default:
		s.log.Error("api", "path", r.URL.Path, "err", err)
		apiError(w, http.StatusInternalServerError, "internal error")
	}
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func (s *server) apiPDNSQuery(w http.ResponseWriter, r *http.Request) {
	s.streamPDNS(w, r, func() ([]ch.PDNSRecord, error) {
		return s.ch.PDNSByName(r.Context(), resolver.Name(r.PathValue("rrname")), intParam(r, "limit", pdnsLimit, pdnsLimit))
	})
}

func (s *server) apiPDNSRdata(w http.ResponseWriter, r *http.Request) {
	s.streamPDNS(w, r, func() ([]ch.PDNSRecord, error) {
		return s.ch.PDNSByRdata(r.Context(), normalizeRdataQuery(r.PathValue("value")), intParam(r, "limit", pdnsLimit, pdnsLimit))
	})
}

// normalizeRdataQuery maps user input to the stored rdata form: canonical IP
// text, or lower-case names without the trailing dot. Values containing
// spaces or quotes (MX, SOA, TXT) are matched as given.
func normalizeRdataQuery(v string) string {
	v = strings.TrimSpace(v)
	if a, err := netip.ParseAddr(v); err == nil {
		return a.String()
	}
	if strings.ContainsAny(v, " \"") {
		return v
	}
	return resolver.Name(v)
}

func (s *server) streamPDNS(w http.ResponseWriter, r *http.Request, query func() ([]ch.PDNSRecord, error)) {
	records, err := query()
	if err != nil {
		s.log.Error("pdns", "path", r.URL.Path, "err", err)
		apiError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.Header().Set("Content-Type", cof.ContentType)
	w.WriteHeader(http.StatusOK)
	cw := cof.NewWriter(w)
	rc := http.NewResponseController(w)
	for i, rec := range records {
		if err := cw.Write(cof.New(rec.RRName, rec.RRType, rec.RData, rec.FirstSeen, rec.LastSeen, rec.Count)); err != nil {
			return
		}
		if i%500 == 499 {
			_ = rc.Flush()
		}
	}
}

func (s *server) apiDomains(w http.ResponseWriter, r *http.Request) {
	var campaignID *int64
	if name := r.URL.Query().Get("campaign"); name != "" {
		c, err := s.pg.CampaignByName(r.Context(), name)
		if err != nil {
			s.apiStoreError(w, r, err)
			return
		}
		campaignID = &c.ID
	}
	domains, err := s.pg.Domains(r.Context(), campaignID)
	if err != nil {
		s.apiStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toDomainsJSON(domains))
}

func (s *server) apiDomainDetail(w http.ResponseWriter, r *http.Request) {
	fqdn := resolver.Name(r.PathValue("fqdn"))
	dd, err := s.loadDomain(r.Context(), fqdn, intParam(r, "limit", domainChanges, domainChangesMax))
	if err != nil {
		s.apiStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toDomainDetailJSON(dd, s.cdn))
}

func (s *server) apiCampaignDomains(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		apiError(w, http.StatusNotFound, "not found")
		return
	}
	if _, err := s.pg.Campaign(r.Context(), id); err != nil {
		s.apiStoreError(w, r, err)
		return
	}
	domains, err := s.pg.Domains(r.Context(), &id)
	if err != nil {
		s.apiStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toDomainsJSON(domains))
}

func (s *server) campaignID(r *http.Request, name string) (*int64, error) {
	if name == "" {
		return nil, nil
	}
	c, err := s.pg.CampaignByName(r.Context(), name)
	if err != nil {
		return nil, err
	}
	return &c.ID, nil
}

func (s *server) apiCreateDomain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FQDN            string `json:"fqdn"`
		Campaign        string `json:"campaign"`
		IntervalSeconds int    `json:"interval_seconds"`
		Enabled         *bool  `json:"enabled"`
		Source          string `json:"source"`
	}
	if err := decodeJSON(r, &req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	fqdn, err := resolver.NormalizeFQDN(req.FQDN)
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.IntervalSeconds == 0 {
		req.IntervalSeconds = 300
	}
	if req.IntervalSeconds < 10 {
		apiError(w, http.StatusBadRequest, "interval_seconds must be at least 10")
		return
	}
	cid, err := s.campaignID(r, req.Campaign)
	if err != nil {
		if errors.Is(err, pg.ErrNotFound) {
			apiError(w, http.StatusBadRequest, "unknown campaign")
			return
		}
		s.apiStoreError(w, r, err)
		return
	}
	u := auth.UserFrom(r.Context())
	if req.Source == "" {
		req.Source = "api:" + u.Username
	}
	d, err := s.pg.CreateDomain(r.Context(), pg.NewDomain{
		FQDN: fqdn, CampaignID: cid, IntervalSeconds: req.IntervalSeconds,
		Enabled: req.Enabled == nil || *req.Enabled, Source: req.Source, AddedBy: &u.ID,
	})
	if err != nil {
		s.apiStoreError(w, r, err)
		return
	}
	s.audit(r, "domain.create", fqdn)
	writeJSON(w, http.StatusCreated, toDomainJSON(d))
}

func (s *server) apiPatchDomain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Campaign        *string `json:"campaign"`
		IntervalSeconds *int    `json:"interval_seconds"`
		Enabled         *bool   `json:"enabled"`
		Source          *string `json:"source"`
	}
	if err := decodeJSON(r, &req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.IntervalSeconds != nil && *req.IntervalSeconds < 10 {
		apiError(w, http.StatusBadRequest, "interval_seconds must be at least 10")
		return
	}
	p := pg.DomainPatch{IntervalSeconds: req.IntervalSeconds, Enabled: req.Enabled, Source: req.Source}
	if req.Campaign != nil {
		cid, err := s.campaignID(r, *req.Campaign)
		if err != nil {
			if errors.Is(err, pg.ErrNotFound) {
				apiError(w, http.StatusBadRequest, "unknown campaign")
				return
			}
			s.apiStoreError(w, r, err)
			return
		}
		p.SetCampaign, p.CampaignID = true, cid
	}
	fqdn := resolver.Name(r.PathValue("fqdn"))
	d, err := s.pg.UpdateDomain(r.Context(), fqdn, p)
	if err != nil {
		s.apiStoreError(w, r, err)
		return
	}
	s.audit(r, "domain.update", fqdn)
	writeJSON(w, http.StatusOK, toDomainJSON(d))
}

func (s *server) apiDeleteDomain(w http.ResponseWriter, r *http.Request) {
	fqdn := resolver.Name(r.PathValue("fqdn"))
	if err := s.pg.DeleteDomain(r.Context(), fqdn); err != nil {
		s.apiStoreError(w, r, err)
		return
	}
	s.audit(r, "domain.delete", fqdn)
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) apiCampaigns(w http.ResponseWriter, r *http.Request) {
	cs, err := s.pg.Campaigns(r.Context())
	if err != nil {
		s.apiStoreError(w, r, err)
		return
	}
	out := make([]campaignJSON, 0, len(cs))
	for _, c := range cs {
		out = append(out, toCampaignJSON(c))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) apiCreateCampaign(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Family      string `json:"family"`
		Description string `json:"description"`
	}
	if err := decodeJSON(r, &req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		apiError(w, http.StatusBadRequest, "name is required")
		return
	}
	c, err := s.pg.CreateCampaign(r.Context(), req.Name, strings.TrimSpace(req.Family), strings.TrimSpace(req.Description))
	if err != nil {
		s.apiStoreError(w, r, err)
		return
	}
	s.audit(r, "campaign.create", c.Name)
	writeJSON(w, http.StatusCreated, toCampaignJSON(c))
}

func (s *server) apiEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	now := time.Now().UTC()
	f := ch.EventFilter{
		Since:    now.Add(-24 * time.Hour),
		Kind:     q.Get("kind"),
		Campaign: q.Get("campaign"),
		Domain:   resolver.Name(q.Get("domain")),
		Limit:    intParam(r, "limit", 1000, eventsLimit),
	}
	var err error
	if v := q.Get("since"); v != "" {
		if f.Since, err = parseTime(v, now); err != nil {
			apiError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if v := q.Get("until"); v != "" {
		if f.Until, err = parseTime(v, now); err != nil {
			apiError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if f.Kind != "" && !slices.Contains(gjallarhorn.Kinds, f.Kind) {
		apiError(w, http.StatusBadRequest, "unknown kind")
		return
	}
	events, err := s.ch.Events(r.Context(), f)
	if err != nil {
		s.log.Error("events", "err", err)
		apiError(w, http.StatusInternalServerError, "internal error")
		return
	}
	out := make([]eventJSON, 0, len(events))
	for _, e := range events {
		detail := json.RawMessage(e.Detail)
		if !json.Valid(detail) {
			detail = json.RawMessage("null")
		}
		out = append(out, eventJSON{TS: e.TS, Domain: e.Domain, Campaign: e.Campaign, Kind: e.Kind, QType: e.QType, Resolver: e.Resolver, Detail: detail})
	}
	writeJSON(w, http.StatusOK, out)
}

// apiSearch follows the rules of /search without redirecting: an IP lists
// the names that held it, a known name is matched exactly.
func (s *server) apiSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		apiError(w, http.StatusBadRequest, "q is required")
		return
	}
	v := searchView{Query: q, Limit: intParam(r, "limit", searchLimit, searchLimit)}
	var err error
	if a, perr := netip.ParseAddr(q); perr == nil {
		v.Kind = "ip"
		err = s.searchIP(r.Context(), &v, a.String())
	} else {
		name := resolver.Name(q)
		pattern, ok := likePattern(name)
		if !ok {
			apiError(w, http.StatusBadRequest, fmt.Sprintf("q needs at least %d characters besides *", searchMinChars))
			return
		}
		v.Kind = "pattern"
		if !strings.Contains(name, "*") {
			known, kerr := s.knownName(r.Context(), name)
			if kerr != nil {
				s.apiStoreError(w, r, kerr)
				return
			}
			if known {
				v.Kind, pattern = "exact", escapeLike(name)
			}
		}
		err = s.searchPattern(r.Context(), &v, pattern)
	}
	if err != nil {
		s.apiStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toSearchJSON(v))
}

func (s *server) apiPivots(w http.ResponseWriter, r *http.Request) {
	fqdn := resolver.Name(r.PathValue("fqdn"))
	values, err := s.ch.PivotValues(r.Context(), fqdn)
	if err != nil {
		s.log.Error("pivot values", "err", err)
		apiError(w, http.StatusInternalServerError, "internal error")
		return
	}
	kept, excluded := splitCDN(values, s.cdn)
	pivots, err := s.ch.Pivots(r.Context(), fqdn, kept, intParam(r, "limit", 1000, 10000))
	if err != nil {
		s.log.Error("pivots", "err", err)
		apiError(w, http.StatusInternalServerError, "internal error")
		return
	}
	out := pivotsJSON{Pivots: make([]pivotJSON, 0, len(pivots)), ExcludedCDN: excluded}
	for _, p := range pivots {
		pj := pivotJSON{
			Domain: p.Domain, RRType: p.RRType, RData: p.RData,
			Target: periodJSON(p.Target), Other: periodJSON(p.Other),
		}
		if p.Overlap != nil {
			o := periodJSON(*p.Overlap)
			pj.Overlap = &o
		}
		out.Pivots = append(out.Pivots, pj)
	}
	writeJSON(w, http.StatusOK, out)
}
