package correlate

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sebdraven/heimdall/internal/cdn"
	"github.com/sebdraven/heimdall/internal/store/ch"
)

var t0 = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

func day(n int) time.Time { return t0.AddDate(0, 0, n) }

func span(from, to int) ch.Period { return ch.Period{First: day(from), Last: day(to)} }

// Campaign 1 holds a1 and a2, 2 holds b1 and b2, 3 holds c1; free.example
// is watched outside any campaign.
var testDomains = []Domain{
	{"a1.example", 1}, {"a2.example", 1}, {"b1.example", 2}, {"b2.example", 2}, {"c1.example", 3}, {"free.example", 0},
}

func testCDN() *cdn.Classifier {
	return cdn.New([]cdn.Prefix{{Prefix: netip.MustParsePrefix("104.16.0.0/13"), Provider: "Cloudflare"}})
}

func compute(in Input) Result {
	in.Domains = append(in.Domains, testDomains...)
	in.CDN = testCDN()
	return Compute(in)
}

func links(r Result) string {
	var out []string
	for _, e := range r.Evidence {
		s := fmt.Sprintf("%s %s %s/%d %s/%d %g", e.Kind, e.Value, e.DomainA, e.CampaignA, e.DomainB, e.CampaignB, e.Weight)
		if e.Period != nil {
			s += " " + e.Period.First.Format(time.DateOnly) + ".." + e.Period.Last.Format(time.DateOnly)
		}
		out = append(out, s)
	}
	return strings.Join(out, "\n")
}

func check(t *testing.T, name string, r Result, want ...string) {
	t.Helper()
	if got := links(r); got != strings.Join(want, "\n") {
		t.Errorf("%s:\n%s\nwant\n%s", name, got, strings.Join(want, "\n"))
	}
}

func TestCert(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	r := compute(Input{Certs: []Cert{
		{Domain: "b1.example", SHA256: strings.ToUpper(sha), NotBefore: day(0), NotAfter: day(90)},
		{Domain: "a1.example", SHA256: sha, NotBefore: day(0), NotAfter: day(90)},
		{Domain: "a2.example", SHA256: sha, NotBefore: day(0), NotAfter: day(90)},
		{Domain: "free.example", SHA256: sha},
		{Domain: "c1.example", SHA256: ""},
		{Domain: "b2.example", SHA256: ""},
	}})
	// The full SHA-256, the pair in name order; a1/a2 share a campaign and
	// free.example has none.
	check(t, "cert", r,
		"cert "+sha+" a1.example/1 b1.example/2 1 2026-03-01..2026-05-30",
		"cert "+sha+" a2.example/1 b1.example/2 1 2026-03-01..2026-05-30")
	if len(sha) != 64 {
		t.Fatal("fixture")
	}
}

func TestNSSet(t *testing.T) {
	pair := []string{"ns2.p.example", "ns1.p.example"}
	r := compute(Input{NSSets: []NSSet{
		{Domain: "a1.example", Zone: "a1.example", NS: pair, Period: span(0, 10)},
		{Domain: "b1.example", Zone: "b1.example", NS: []string{"ns1.p.example", "ns2.p.example", "ns1.p.example"}, Period: span(5, 10)},
		// Same zone: not a link between zones.
		{Domain: "c1.example", Zone: "a1.example", NS: pair, Period: span(0, 10)},
		// A single nameserver says nothing.
		{Domain: "a2.example", Zone: "a2.example", NS: []string{"ns1.q.example"}, Period: span(0, 10)},
		{Domain: "b2.example", Zone: "b2.example", NS: []string{"ns1.q.example"}, Period: span(0, 10)},
		// A superset is another set.
		{Domain: "b2.example", Zone: "b2.example", NS: append([]string{"ns3.p.example"}, pair...), Period: span(0, 10)},
	}})
	check(t, "ns_set", r,
		"ns_set ns1.p.example,ns2.p.example a1.example/1 b1.example/2 0.9 2026-03-06..2026-03-11",
		"ns_set ns1.p.example,ns2.p.example b1.example/2 c1.example/3 0.9 2026-03-06..2026-03-11")
}

func TestIP(t *testing.T) {
	in := Input{IPs: []Record{
		{"a1.example", "192.0.2.1", span(0, 10)},
		{"b1.example", "192.0.2.1", span(5, 20)},
		{"free.example", "192.0.2.1", span(8, 30)},
		{"c1.example", "192.0.2.1", span(40, 50)},
		{"a1.example", "104.16.0.1", span(0, 10)},
		{"b1.example", "104.16.0.1", span(0, 10)},
	}}
	r := compute(in)
	// Three watched domains held 192.0.2.1 during the overlap of a1 and b1,
	// free.example included; c1 came later.
	check(t, "ip", r, "ip 192.0.2.1 a1.example/1 b1.example/2 0.2667 2026-03-06..2026-03-11")
	if r.Skipped[SkipCDN] != 1 {
		t.Errorf("skipped = %v, want the CDN address", r.Skipped)
	}

	// 21 watched domains on the address during the overlap: shared hosting.
	in.IPs = in.IPs[:2]
	for i := range 19 {
		d := fmt.Sprintf("host%02d.example", i)
		in.Domains = append(in.Domains, Domain{d, 0})
		in.IPs = append(in.IPs, Record{d, "192.0.2.1", span(0, 30)})
	}
	r = compute(in)
	check(t, "21 holders", r)
	if r.Skipped[SkipShared] != 1 {
		t.Errorf("skipped = %v, want the shared address", r.Skipped)
	}

	in.IPs = in.IPs[:20]
	check(t, "20 holders", compute(in), "ip 192.0.2.1 a1.example/1 b1.example/2 0.04 2026-03-06..2026-03-11")
}

func TestCNAME(t *testing.T) {
	r := compute(Input{
		CNAMEs: []Record{
			{"a1.example", "T.Shared.example.", span(0, 10)},
			{"b1.example", "t.shared.example", span(20, 30)},
			{"a1.example", "d111.cloudfront.net", span(0, 10)},
			{"b1.example", "d111.cloudfront.net", span(0, 10)},
			{"a2.example", "front.example", span(0, 10)},
			{"b2.example", "front.example", span(0, 10)},
		},
		Chains: map[string]Chain{
			"front.example": {CNAMEs: []string{"edge.example"}},
			"edge.example":  {IPs: []string{"192.0.2.9", "104.16.0.7"}},
		},
	})
	// No overlap required, none reported.
	check(t, "cname", r, "cname t.shared.example a1.example/1 b1.example/2 0.7")
	if r.Skipped[SkipProvider] != 1 || r.Skipped[SkipCDN] != 1 {
		t.Errorf("skipped = %v, want cloudfront.net as a provider and front.example ending on a CDN", r.Skipped)
	}
}

func TestMX(t *testing.T) {
	var mx []Record
	for _, host := range []string{"mx.evil.example", "aspmx.l.google.com", "mx.zoho.eu", "mx.yandex.net", "eu-smtp-inbound-1.mimecast.com", "x.mail.protection.outlook.com"} {
		mx = append(mx, Record{"a1.example", host, span(0, 10)}, Record{"c1.example", host, span(0, 10)})
	}
	r := compute(Input{MXs: mx})
	check(t, "mx", r, "mx mx.evil.example a1.example/1 c1.example/3 0.5 2026-03-01..2026-03-11")
	if r.Skipped[SkipProvider] != 5 {
		t.Errorf("skipped = %v, want 5 known providers", r.Skipped)
	}
}

func TestSOA(t *testing.T) {
	soa := func(d, zone, m, rn string) SOA {
		return SOA{Domain: d, Zone: zone, MName: m, RName: rn, Period: span(0, 10)}
	}
	r := compute(Input{SOAs: []SOA{
		soa("a1.example", "a1.example", "ns1.evil.example", "admin.evil.example"),
		soa("b1.example", "b1.example", "ns1.evil.example", "admin.evil.example"),
		soa("a2.example", "a2.example", "kate.ns.cloudflare.com", "dns.cloudflare.com"),
		soa("b2.example", "b2.example", "kate.ns.cloudflare.com", "dns.cloudflare.com"),
		soa("a2.example", "a2.example", "ns-1.awsdns-12.org", "awsdns-hostmaster.amazon.com"),
		soa("c1.example", "c1.example", "ns-1.awsdns-12.org", "awsdns-hostmaster.amazon.com"),
		soa("c1.example", "c1.example", "pdns1.registrar-servers.com", "hostmaster.registrar-servers.com"),
		soa("b2.example", "b2.example", "pdns1.registrar-servers.com", "hostmaster.registrar-servers.com"),
	}})
	check(t, "soa", r, "soa ns1.evil.example admin.evil.example a1.example/1 b1.example/2 0.4 2026-03-01..2026-03-11")
	if r.Skipped[SkipProvider] != 3 {
		t.Errorf("skipped = %v, want 3 default SOAs", r.Skipped)
	}
}

func TestRDAP(t *testing.T) {
	reg := func(d, registrable, id, name string, at time.Time) Registration {
		return Registration{Domain: d, Registrable: registrable, RegistrarID: id, Registrar: name, Registered: at}
	}
	r := compute(Input{Registrations: []Registration{
		reg("a1.example", "a1.example", "1068", "NameCheap, Inc.", t0),
		reg("b1.example", "b1.example", "1068", "Namecheap", t0.Add(47*time.Hour)),
		reg("c1.example", "c1.example", "1068", "NameCheap, Inc.", t0.Add(49*time.Hour)),
		// Another registrar, same day.
		reg("b2.example", "b2.example", "146", "GoDaddy.com, LLC", t0.Add(time.Hour)),
		// The same registrable domain is one registration.
		reg("a2.example", "b2.example", "146", "GoDaddy.com, LLC", t0.Add(time.Hour)),
		// By name when the IANA id is unknown.
		reg("free.example", "free.example", "", "", t0),
	}})
	check(t, "rdap", r,
		"rdap NameCheap, Inc. (IANA 1068) a1.example/1 b1.example/2 0.3 2026-03-01..2026-03-02",
		"rdap NameCheap, Inc. (IANA 1068) b1.example/2 c1.example/3 0.3 2026-03-02..2026-03-03")
}

func TestVT(t *testing.T) {
	r := compute(Input{
		IPs: []Record{
			{"b1.example", "198.51.100.7", span(5, 20)},
			{"a2.example", "198.51.100.7", span(0, 2)},
			{"b2.example", "104.16.0.1", span(0, 10)},
		},
		VT: []Record{
			{"a1.example", "198.51.100.7", span(0, 10)},
			{"a1.example", "104.16.0.1", span(0, 10)},
			{"free.example", "198.51.100.7", span(0, 10)},
		},
	})
	// a2 is in a1's campaign; the pdns pair a2/b1 does not overlap.
	check(t, "vt", r, "vt 198.51.100.7 a1.example/1 b1.example/2 0.3 2026-03-06..2026-03-11")
}

func TestScore(t *testing.T) {
	ev := func(kind, value string, w float64) Evidence { return Evidence{Kind: kind, Value: value, Weight: w} }
	for _, tt := range []struct {
		ev   []Evidence
		want float64
	}{
		{nil, 0},
		{[]Evidence{ev(KindCert, "x", 1)}, 1},
		{[]Evidence{ev(KindCert, "x", 1), ev(KindMX, "m", 0.5)}, 1},
		{[]Evidence{ev(KindMX, "m", 0.5), ev(KindMX, "n", 0.5)}, 0.75},
		{[]Evidence{ev(KindNSSet, "s", 0.9), ev(KindRDAP, "r", 0.3)}, 0.93},
		// A value counts once, at its highest weight.
		{[]Evidence{ev(KindIP, "192.0.2.1", 0.4), ev(KindIP, "192.0.2.1", 0.2), ev(KindIP, "192.0.2.1", 0.4)}, 0.4},
		// The same value under another kind is another piece of evidence.
		{[]Evidence{ev(KindIP, "192.0.2.1", 0.4), ev(KindVT, "192.0.2.1", 0.3)}, 0.58},
	} {
		if got := Score(tt.ev); got != tt.want {
			t.Errorf("Score(%v) = %v, want %v", tt.ev, got, tt.want)
		}
	}
}

func TestPairs(t *testing.T) {
	ev := []Evidence{
		{Kind: KindMX, Value: "m", DomainA: "a1.example", CampaignA: 9, DomainB: "b1.example", CampaignB: 2, Weight: 0.5, FirstSeen: day(3), LastSeen: day(10)},
		{Kind: KindMX, Value: "m", DomainA: "a2.example", CampaignA: 9, DomainB: "b1.example", CampaignB: 2, Weight: 0.5, FirstSeen: day(1), LastSeen: day(10)},
		{Kind: KindIP, Value: "192.0.2.1", DomainA: "b1.example", CampaignA: 2, DomainB: "c1.example", CampaignB: 9, Weight: 0.4, FirstSeen: day(5), LastSeen: day(10)},
		{Kind: KindCert, Value: "x", DomainA: "a1.example", CampaignA: 1, DomainB: "b1.example", CampaignB: 2, Weight: 1, FirstSeen: day(2), LastSeen: day(9)},
	}
	var got []string
	for _, p := range Pairs(ev) {
		got = append(got, fmt.Sprintf("%d-%d %g %v %s %s", p.A, p.B, p.Score, p.Counts, p.FirstSeen.Format(time.DateOnly), p.LastSeen.Format(time.DateOnly)))
	}
	want := "1-2 1 map[cert:1] 2026-03-03 2026-03-10 | 2-9 0.7 map[ip:1 mx:1] 2026-03-02 2026-03-11"
	if strings.Join(got, " | ") != want {
		t.Errorf("pairs = %s\nwant %s", strings.Join(got, " | "), want)
	}
	if n := len(Between(ev, 9, 2)); n != 3 {
		t.Errorf("between 9 and 2: %d links, want 3", n)
	}
	if n := len(OfKinds(ev, []string{KindMX, KindCert})); n != 3 {
		t.Errorf("mx and cert: %d links, want 3", n)
	}

	SortByWeight(ev)
	var order []string
	for _, e := range ev {
		order = append(order, e.Kind+"/"+e.DomainA)
	}
	if got := strings.Join(order, " "); got != "cert/a1.example mx/a1.example mx/a2.example ip/b1.example" {
		t.Errorf("by weight then latest first seen: %s", got)
	}
}

func TestCanonicalOrder(t *testing.T) {
	r := compute(Input{MXs: []Record{{"c1.example", "mx.evil.example", span(0, 1)}, {"a1.example", "mx.evil.example", span(0, 1)}}})
	if len(r.Evidence) != 1 {
		t.Fatalf("links = %s", links(r))
	}
	e := r.Evidence[0]
	if e.DomainA != "a1.example" || e.CampaignA != 1 || e.DomainB != "c1.example" || e.CampaignB != 3 {
		t.Errorf("link = %+v, want a1.example (1) first", e)
	}
	if e.Key() != (Key{KindMX, "mx.evil.example", "a1.example", "c1.example"}) {
		t.Errorf("key = %+v", e.Key())
	}
}

func TestMaxHolders(t *testing.T) {
	in := Input{MXs: []Record{{"a1.example", "mx.common.example", span(0, 1)}, {"b1.example", "mx.common.example", span(0, 1)}}}
	for i := range MaxHolders - 2 {
		d := fmt.Sprintf("d%03d.example", i)
		in.Domains = append(in.Domains, Domain{d, 7})
		in.MXs = append(in.MXs, Record{d, "mx.common.example", span(0, 1)})
	}
	if r := compute(in); len(r.Evidence) == 0 {
		t.Error("no link at MaxHolders domains")
	}
	in.Domains = append(in.Domains, Domain{"one-more.example", 7})
	in.MXs = append(in.MXs, Record{"one-more.example", "mx.common.example", span(0, 1)})
	if r := compute(in); len(r.Evidence) != 0 || r.Skipped[SkipShared] != 1 {
		t.Errorf("past MaxHolders: %d links, skipped %v", len(r.Evidence), r.Skipped)
	}
}

func TestMatches(t *testing.T) {
	for _, tt := range []struct {
		name     string
		patterns []string
		want     bool
	}{
		{"google.com", MXProviders, true},
		{"aspmx.l.google.com.", MXProviders, true},
		{"notgoogle.com", MXProviders, false},
		{"mx.zoho.com.au", MXProviders, true},
		{"mx.zohomail.example", MXProviders, false},
		{"mx.yandex.ru", MXProviders, true},
		{"ns-1.awsdns-12.co.uk", SOADefaults, true},
		{"ns1-01.azure-dns.com", SOADefaults, true},
		{"kate.ns.cloudflare.com", SOADefaults, true},
		{"ns1.cloudflare.example", SOADefaults, false},
		{"x.edgekey.net", CNAMEProviders, true},
		{"x.github.io", CNAMEProviders, false},
	} {
		if got := Matches(tt.name, tt.patterns); got != tt.want {
			t.Errorf("Matches(%s) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestWeight(t *testing.T) {
	for _, k := range Kinds {
		if Weight(k) <= 0 || Weight(k) > 1 {
			t.Errorf("Weight(%s) = %v", k, Weight(k))
		}
	}
}
