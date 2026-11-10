// Package correlate links domains of different campaigns that share a piece
// of infrastructure, and scores each pair of campaigns from these links.
package correlate

import (
	"cmp"
	"maps"
	"math"
	"path"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/sebdraven/heimdall/internal/store/ch"
)

// The lists below match a name by suffix ("example.com" is the name or one
// below it) or, ending in ".*", by the first label of its registrable domain
// as a shell pattern ("zoho.*" matches mx.zoho.eu, "awsdns-*.*" matches
// ns-1.awsdns-12.org).

// CNAMEProviders are the CDN and edge targets that unrelated names share.
var CNAMEProviders = []string{
	"cloudfront.net", "fastly.net", "fastlylb.net", "akamaiedge.net", "akamai.net", "akamaized.net",
	"edgekey.net", "edgesuite.net", "b-cdn.net", "azureedge.net", "azurefd.net", "trafficmanager.net",
	"cdn77.org", "cloudflare.net", "incapdns.net", "impervadns.net", "stackpathdns.com", "kxcdn.com",
	"edgecastcdn.net", "llnwd.net", "sucuridns.com", "gcdn.co",
}

// MXProviders are the mail providers whose exchanges serve unrelated
// domains.
var MXProviders = []string{
	"google.com", "googlemail.com", "outlook.com", "protection.outlook.com", "hotmail.com", "zoho.*", "yandex.*",
	"mail.ru", "icloud.com", "me.com", "yahoodns.net", "protonmail.ch", "mimecast.com", "pphosted.com",
	"messagelabs.com", "messagingengine.com", "secureserver.net", "registrar-servers.com", "privateemail.com",
	"ovh.net", "gandi.net", "mailgun.org", "sendgrid.net", "amazonaws.com", "mx.cloudflare.net", "titan.email",
	"migadu.com", "hostinger.com",
}

// SOADefaults are the SOA mname or rname that a DNS provider writes in every
// zone it hosts.
var SOADefaults = []string{
	"ns.cloudflare.com", "dns.cloudflare.com", "awsdns-*.*", "amazon.com", "azure-dns.*", "microsoft.com",
	"domaincontrol.com", "registrar-servers.com", "googledomains.com", "google.com", "nsone.net", "ultradns.*",
	"dnsmadeeasy.com", "digitalocean.com", "linode.com", "hetzner.com", "ovh.net", "gandi.net", "name.com",
	"dynect.net", "akam.net", "porkbun.com", "dnspod.net", "hichina.com", "dns-parking.com", "vercel-dns.com",
	"netlify.com",
}

const (
	KindCert  = "cert"
	KindNSSet = "ns_set"
	KindIP    = "ip"
	KindCNAME = "cname"
	KindMX    = "mx"
	KindSOA   = "soa"
	KindRDAP  = "rdap"
	KindVT    = "vt"
)

// Kinds lists the kinds of evidence, strongest first.
var Kinds = []string{KindCert, KindNSSet, KindIP, KindCNAME, KindMX, KindSOA, KindRDAP, KindVT}

const (
	WeightCert  = 1.0
	WeightNSSet = 0.9
	// WeightIP is divided by the number of watched domains on the address.
	WeightIP    = 0.8
	WeightCNAME = 0.7
	WeightMX    = 0.5
	WeightSOA   = 0.4
	WeightRDAP  = 0.3
	WeightVT    = 0.3
)

const (
	// MaxIPHolders: an address of more watched domains over a period is
	// shared hosting.
	MaxIPHolders = 20
	// RegistrationWindow bounds the gap between two registrations by the
	// same registrar.
	RegistrationWindow = 48 * time.Hour
	// MaxHolders: a value held by more watched domains says little and would
	// give a link per pair of them.
	MaxHolders = 100
	// maxChain bounds the CNAME hops followed to the addresses of a target.
	maxChain = 8
)

// Weight returns the weight of kind, WeightIP for an address.
func Weight(kind string) float64 {
	return map[string]float64{
		KindCert: WeightCert, KindNSSet: WeightNSSet, KindIP: WeightIP, KindCNAME: WeightCNAME,
		KindMX: WeightMX, KindSOA: WeightSOA, KindRDAP: WeightRDAP, KindVT: WeightVT,
	}[kind]
}

// Reasons a value is left out.
const (
	SkipCDN      = "cdn"
	SkipShared   = "shared"
	SkipProvider = "provider"
)

// Domain is a watched domain; Campaign is 0 outside any campaign.
type Domain struct {
	FQDN     string
	Campaign int64
}

// Record is a value a domain held over Period, in passive DNS or the
// VirusTotal cache.
type Record struct {
	Domain string
	Value  string
	Period ch.Period
}

// NSSet is the current NS set of the zone of a domain.
type NSSet struct {
	Domain string
	Zone   string
	NS     []string
	Period ch.Period
}

// SOA is the current SOA of the zone of a domain.
type SOA struct {
	Domain string
	Zone   string
	MName  string
	RName  string
	Period ch.Period
}

// Cert is a certificate of the stored enrichment of a domain.
type Cert struct {
	Domain    string
	SHA256    string
	NotBefore time.Time
	NotAfter  time.Time
}

// Registration is the RDAP registration of the registrable domain of a
// domain.
type Registration struct {
	Domain      string
	Registrable string
	RegistrarID string
	Registrar   string
	Registered  time.Time
}

// Chain is what a name points to in passive DNS.
type Chain struct {
	CNAMEs []string
	IPs    []string
}

// Classifier tells CDN addresses; *cdn.Classifier is one.
type Classifier interface {
	Classify(addr string) (string, bool)
}

// Input is what is known of the watched domains. IPs are their A and AAAA
// values, CNAMEs and MXs the targets and exchanges they own, VT the
// addresses VirusTotal saw them on. Chains follow the CNAME targets.
type Input struct {
	Domains       []Domain
	IPs           []Record
	CNAMEs        []Record
	MXs           []Record
	NSSets        []NSSet
	SOAs          []SOA
	Certs         []Cert
	Registrations []Registration
	VT            []Record
	Chains        map[string]Chain
	CDN           Classifier
}

// Evidence links DomainA to DomainB, DomainA < DomainB, through Value.
// Period is when both held it, the validity of a certificate or the two
// registration dates, nil if none. FirstSeen and LastSeen come from the
// history of links.
type Evidence struct {
	Kind      string
	Value     string
	DomainA   string
	CampaignA int64
	DomainB   string
	CampaignB int64
	Weight    float64
	Period    *ch.Period
	FirstSeen time.Time
	LastSeen  time.Time
}

// Key identifies a link in the history.
type Key struct {
	Kind, Value, DomainA, DomainB string
}

func (e Evidence) Key() Key { return Key{e.Kind, e.Value, e.DomainA, e.DomainB} }

// Result holds the links found and, by reason, the number of values left
// out.
type Result struct {
	Evidence []Evidence
	Skipped  map[string]int
}

type holder struct {
	domain string
	zone   string
	period *ch.Period
}

type computer struct {
	in       Input
	campaign map[string]int64
	ev       map[Key]Evidence
	skipped  map[string]map[string]bool
}

// Compute finds the links between domains of different campaigns.
func Compute(in Input) Result {
	c := &computer{in: in, campaign: map[string]int64{}, ev: map[Key]Evidence{}, skipped: map[string]map[string]bool{}}
	for _, d := range in.Domains {
		c.campaign[d.FQDN] = d.Campaign
	}
	c.certs()
	c.nssets()
	ipHolders := c.ips()
	c.cnames()
	c.mxs()
	c.soas()
	c.registrations()
	c.vt(ipHolders)

	res := Result{Evidence: make([]Evidence, 0, len(c.ev)), Skipped: map[string]int{}}
	for _, e := range c.ev {
		res.Evidence = append(res.Evidence, e)
	}
	slices.SortFunc(res.Evidence, compareKey)
	for reason, values := range c.skipped {
		res.Skipped[reason] = len(values)
	}
	return res
}

func compareKey(a, b Evidence) int {
	return cmp.Or(
		cmp.Compare(slices.Index(Kinds, a.Kind), slices.Index(Kinds, b.Kind)),
		cmp.Compare(a.Value, b.Value), cmp.Compare(a.DomainA, b.DomainA), cmp.Compare(a.DomainB, b.DomainB),
	)
}

func (c *computer) skip(reason, kind, value string) {
	if c.skipped[reason] == nil {
		c.skipped[reason] = map[string]bool{}
	}
	c.skipped[reason][kind+"\x00"+value] = true
}

// add records a link unless both domains are in the same campaign or one is
// in none, keeping the higher weight of a link found twice.
func (c *computer) add(kind, value string, a, b string, w float64, p *ch.Period) {
	ca, cb := c.campaign[a], c.campaign[b]
	if a == b || ca == 0 || cb == 0 || ca == cb {
		return
	}
	if a > b {
		a, b, ca, cb = b, a, cb, ca
	}
	e := Evidence{Kind: kind, Value: value, DomainA: a, CampaignA: ca, DomainB: b, CampaignB: cb, Weight: round(w), Period: p}
	if old, ok := c.ev[e.Key()]; ok && old.Weight >= e.Weight {
		return
	}
	c.ev[e.Key()] = e
}

func round(v float64) float64 { return math.Round(v*1e4) / 1e4 }

// group merges the holders of each value by domain, their periods joined.
func group(hs map[string][]holder) map[string][]holder {
	out := make(map[string][]holder, len(hs))
	for v, list := range hs {
		byDomain := map[string]int{}
		for _, h := range list {
			i, ok := byDomain[h.domain]
			if !ok {
				byDomain[h.domain] = len(out[v])
				out[v] = append(out[v], h)
				continue
			}
			out[v][i].period = join(out[v][i].period, h.period)
		}
		slices.SortFunc(out[v], func(x, y holder) int { return cmp.Compare(x.domain, y.domain) })
	}
	return out
}

func join(a, b *ch.Period) *ch.Period {
	if a == nil || b == nil {
		return cmp.Or(a, b)
	}
	return &ch.Period{First: earlier(a.First, b.First), Last: later(a.Last, b.Last)}
}

func overlap(a, b *ch.Period) *ch.Period {
	if a == nil || b == nil {
		return nil
	}
	first, last := later(a.First, b.First), earlier(a.Last, b.Last)
	if first.After(last) {
		return nil
	}
	return &ch.Period{First: first, Last: last}
}

func period(p ch.Period) *ch.Period { return &p }

// pairAll links every two holders of value from different zones when
// distinctZones, the period being when both held it.
func (c *computer) pairAll(kind, value string, hs []holder, w float64, distinctZones bool) {
	if len(hs) > MaxHolders {
		c.skip(SkipShared, kind, value)
		return
	}
	for i := range hs {
		for j := i + 1; j < len(hs); j++ {
			if distinctZones && hs[i].zone == hs[j].zone {
				continue
			}
			c.add(kind, value, hs[i].domain, hs[j].domain, w, overlap(hs[i].period, hs[j].period))
		}
	}
}

func (c *computer) pairValues(kind string, hs map[string][]holder, w float64, distinctZones bool) {
	for _, v := range slices.Sorted(maps.Keys(hs)) {
		c.pairAll(kind, v, hs[v], w, distinctZones)
	}
}

func (c *computer) certs() {
	hs := map[string][]holder{}
	for _, cert := range c.in.Certs {
		sha := strings.ToLower(strings.TrimSpace(cert.SHA256))
		if sha == "" {
			continue
		}
		var p *ch.Period
		if !cert.NotBefore.IsZero() && !cert.NotAfter.IsZero() {
			p = period(ch.Period{First: cert.NotBefore, Last: cert.NotAfter})
		}
		hs[sha] = append(hs[sha], holder{domain: cert.Domain, period: p})
	}
	c.pairValues(KindCert, group(hs), WeightCert, false)
}

func (c *computer) nssets() {
	hs := map[string][]holder{}
	for _, z := range c.in.NSSets {
		ns := slices.Compact(slices.Sorted(slices.Values(z.NS)))
		if len(ns) < ch.MinNSSet {
			continue
		}
		v := strings.Join(ns, ",")
		hs[v] = append(hs[v], holder{domain: z.Domain, zone: z.Zone, period: period(z.Period)})
	}
	c.pairValues(KindNSSet, group(hs), WeightNSSet, true)
}

// ips links the holders of a non-CDN address whose periods overlap, the
// weight shared by the watched domains holding it during that overlap.
// It returns the holders of each address, for vt.
func (c *computer) ips() map[string][]holder {
	hs := map[string][]holder{}
	for _, r := range c.in.IPs {
		if c.isCDN(r.Value) {
			c.skip(SkipCDN, KindIP, r.Value)
			continue
		}
		hs[r.Value] = append(hs[r.Value], holder{domain: r.Domain, period: period(r.Period)})
	}
	hs = group(hs)
	for _, ip := range slices.Sorted(maps.Keys(hs)) {
		list := hs[ip]
		if len(list) > MaxHolders {
			c.skip(SkipShared, KindIP, ip)
			continue
		}
		for i := range list {
			for j := i + 1; j < len(list); j++ {
				ov := overlap(list[i].period, list[j].period)
				if ov == nil || !c.crossCampaign(list[i].domain, list[j].domain) {
					continue
				}
				n := 0
				for _, h := range list {
					if overlap(h.period, ov) != nil {
						n++
					}
				}
				if n > MaxIPHolders {
					c.skip(SkipShared, KindIP, ip)
					continue
				}
				c.add(KindIP, ip, list[i].domain, list[j].domain, WeightIP/float64(n), ov)
			}
		}
	}
	return hs
}

func (c *computer) crossCampaign(a, b string) bool {
	ca, cb := c.campaign[a], c.campaign[b]
	return ca != 0 && cb != 0 && ca != cb
}

func (c *computer) isCDN(ip string) bool {
	if c.in.CDN == nil {
		return false
	}
	_, ok := c.in.CDN.Classify(ip)
	return ok
}

func (c *computer) cnames() {
	hs := map[string][]holder{}
	for _, r := range c.in.CNAMEs {
		t := strings.TrimSuffix(strings.ToLower(r.Value), ".")
		switch {
		case t == "":
			continue
		case Matches(t, CNAMEProviders):
			c.skip(SkipProvider, KindCNAME, t)
			continue
		case c.endsOnCDN(t):
			c.skip(SkipCDN, KindCNAME, t)
			continue
		}
		hs[t] = append(hs[t], holder{domain: r.Domain, period: period(r.Period)})
	}
	c.pairValues(KindCNAME, group(hs), WeightCNAME, false)
}

// endsOnCDN reports whether a CNAME chain from target reaches a CDN address.
func (c *computer) endsOnCDN(target string) bool {
	seen := map[string]bool{}
	next := []string{target}
	for hop := 0; hop < maxChain && len(next) > 0; hop++ {
		var found []string
		for _, n := range next {
			if seen[n] {
				continue
			}
			seen[n] = true
			link := c.in.Chains[n]
			if slices.ContainsFunc(link.IPs, c.isCDN) {
				return true
			}
			found = append(found, link.CNAMEs...)
		}
		next = found
	}
	return false
}

func (c *computer) mxs() {
	hs := map[string][]holder{}
	for _, r := range c.in.MXs {
		h := strings.TrimSuffix(strings.ToLower(r.Value), ".")
		if h == "" {
			continue
		}
		if Matches(h, MXProviders) {
			c.skip(SkipProvider, KindMX, h)
			continue
		}
		hs[h] = append(hs[h], holder{domain: r.Domain, period: period(r.Period)})
	}
	c.pairValues(KindMX, group(hs), WeightMX, false)
}

func (c *computer) soas() {
	hs := map[string][]holder{}
	for _, s := range c.in.SOAs {
		if s.MName == "" || s.RName == "" {
			continue
		}
		v := s.MName + " " + s.RName
		if Matches(s.MName, SOADefaults) || Matches(s.RName, SOADefaults) {
			c.skip(SkipProvider, KindSOA, v)
			continue
		}
		hs[v] = append(hs[v], holder{domain: s.Domain, zone: s.Zone, period: period(s.Period)})
	}
	c.pairValues(KindSOA, group(hs), WeightSOA, true)
}

// registrations links the registrable domains registered less than
// RegistrationWindow apart by the same registrar, known by its IANA id or
// else its name.
func (c *computer) registrations() {
	byRegistrar := map[string][]Registration{}
	for _, r := range c.in.Registrations {
		if r.Registered.IsZero() || r.Registrable == "" {
			continue
		}
		key := "iana:" + strings.TrimSpace(r.RegistrarID)
		if strings.TrimSpace(r.RegistrarID) == "" {
			key = "name:" + strings.ToLower(strings.TrimSpace(r.Registrar))
		}
		if key == "name:" {
			continue
		}
		byRegistrar[key] = append(byRegistrar[key], r)
	}
	for _, key := range slices.Sorted(maps.Keys(byRegistrar)) {
		rs := byRegistrar[key]
		slices.SortFunc(rs, func(a, b Registration) int {
			return cmp.Or(a.Registered.Compare(b.Registered), cmp.Compare(a.Domain, b.Domain))
		})
		value := registrarLabel(rs[0])
		for i := range rs {
			for j := i + 1; j < len(rs) && rs[j].Registered.Sub(rs[i].Registered) < RegistrationWindow; j++ {
				if rs[i].Registrable == rs[j].Registrable {
					continue
				}
				c.add(KindRDAP, value, rs[i].Domain, rs[j].Domain, WeightRDAP,
					period(ch.Period{First: rs[i].Registered.UTC(), Last: rs[j].Registered.UTC()}))
			}
		}
	}
}

func registrarLabel(r Registration) string {
	name, id := strings.TrimSpace(r.Registrar), strings.TrimSpace(r.RegistrarID)
	switch {
	case id == "":
		return name
	case name == "":
		return "IANA " + id
	}
	return name + " (IANA " + id + ")"
}

// vt links a domain VirusTotal saw on a non-CDN address to the domains that
// held it in passive DNS, unless shared hosting holds it.
func (c *computer) vt(ipHolders map[string][]holder) {
	for _, r := range c.in.VT {
		if c.isCDN(r.Value) {
			c.skip(SkipCDN, KindVT, r.Value)
			continue
		}
		holders := ipHolders[r.Value]
		if len(holders) > MaxIPHolders {
			c.skip(SkipShared, KindVT, r.Value)
			continue
		}
		for _, h := range holders {
			c.add(KindVT, r.Value, r.Domain, h.domain, WeightVT, overlap(period(r.Period), h.period))
		}
	}
}

// Matches reports whether name matches one of patterns.
func Matches(name string, patterns []string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	for _, p := range patterns {
		if base, ok := strings.CutSuffix(p, ".*"); ok {
			reg, err := publicsuffix.EffectiveTLDPlusOne(name)
			if err != nil {
				continue
			}
			label, _, _ := strings.Cut(reg, ".")
			if ok, _ := path.Match(base, label); ok {
				return true
			}
			continue
		}
		if name == p || strings.HasSuffix(name, "."+p) {
			return true
		}
	}
	return false
}

func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
