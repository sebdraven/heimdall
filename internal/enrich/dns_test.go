package enrich

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/sebdraven/heimdall/internal/resolver"
)

// fakeResolver answers from obs, keyed by "name qtype", NOERROR without
// data otherwise, or a timeout when down.
type fakeResolver struct {
	obs  map[string]resolver.Observation
	down bool

	mu    sync.Mutex
	asked []string
}

func (f *fakeResolver) Resolve(_ context.Context, server, fqdn, qtype string) resolver.Observation {
	f.mu.Lock()
	f.asked = append(f.asked, fqdn+" "+qtype)
	f.mu.Unlock()
	if f.down {
		return resolver.Observation{Domain: fqdn, QType: qtype, Resolver: server, Rcode: resolver.RcodeTimeout}
	}
	o, ok := f.obs[fqdn+" "+qtype]
	if !ok {
		o = resolver.Observation{Rcode: "NOERROR"}
	}
	o.Domain, o.QType, o.Resolver = fqdn, qtype, server
	return o
}

func (f *fakeResolver) questions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Sorted(slices.Values(f.asked))
}

func answer(name, qtype string, values ...string) resolver.Observation {
	o := resolver.Observation{Rcode: "NOERROR", TTL: 300, Rdata: values}
	for _, v := range values {
		o.Answers = append(o.Answers, resolver.Answer{Name: name, Type: qtype, Value: v})
	}
	return o
}

const testSOA = "ns1.p.example hostmaster.x.example 1 7200 3600 1209600 300"

func TestLookupApex(t *testing.T) {
	f := &fakeResolver{obs: map[string]resolver.Observation{
		"x.example A":   answer("x.example", "A", "192.0.2.1"),
		"x.example NS":  answer("x.example", "NS", "ns1.p.example", "ns2.p.example"),
		"x.example SOA": answer("x.example", "SOA", testSOA),
	}}
	d, z, err := Lookup(context.Background(), f, "9.9.9.9:53", "x.example")
	if err != nil {
		t.Fatal(err)
	}
	if d.Resolver != "9.9.9.9:53" || len(d.Records) != len(resolver.QTypes) {
		t.Errorf("dns = %+v, want one record per qtype from 9.9.9.9:53", d)
	}
	if got := strings.Join(d.Rdata("A"), " "); got != "192.0.2.1" {
		t.Errorf("A = %s", got)
	}
	if mx := d.Rdata("MX"); mx == nil || len(mx) != 0 {
		t.Errorf("MX = %#v, want an empty list", mx)
	}
	if z == nil || z.Name != "x.example" || strings.Join(z.SOA, "") != testSOA || strings.Join(z.NS, " ") != "ns1.p.example ns2.p.example" {
		t.Errorf("zone = %+v, want x.example with its own SOA and NS", z)
	}
	if n := len(f.questions()); n != len(resolver.QTypes) {
		t.Errorf("%d questions, want %d: the apex is not asked again", n, len(resolver.QTypes))
	}
}

func TestLookupBelowZone(t *testing.T) {
	soaAuthority := resolver.Observation{Rcode: "NOERROR", Authority: []resolver.Answer{{Name: "x.example", Type: "SOA", Value: testSOA}}}
	f := &fakeResolver{obs: map[string]resolver.Observation{
		"www.x.example A":     answer("www.x.example", "A", "192.0.2.1"),
		"www.x.example MX":    answer("www.x.example", "MX", "10 mail.x.example"),
		"www.x.example SOA":   soaAuthority,
		"www.x.example CNAME": {Rcode: "NOERROR"},
		"x.example SOA":       answer("x.example", "SOA", testSOA),
		"x.example NS":        answer("x.example", "NS", "ns2.p.example", "ns1.p.example"),
	}}
	d, z, err := Lookup(context.Background(), f, "9.9.9.9:53", "www.x.example")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(d.Rdata("MX"), " "); got != "10 mail.x.example" {
		t.Errorf("MX = %s", got)
	}
	if z == nil || z.Name != "x.example" || strings.Join(z.SOA, "") != testSOA || strings.Join(z.NS, " ") != "ns2.p.example ns1.p.example" {
		t.Errorf("zone = %+v, want x.example asked for its SOA and NS", z)
	}
	q := f.questions()
	if !slices.Contains(q, "x.example SOA") || !slices.Contains(q, "x.example NS") || len(q) != len(resolver.QTypes)+2 {
		t.Errorf("questions = %v", q)
	}
}

func TestLookupNoZone(t *testing.T) {
	f := &fakeResolver{obs: map[string]resolver.Observation{"a.example A": answer("a.example", "A", "192.0.2.1")}}
	d, z, err := Lookup(context.Background(), f, "9.9.9.9:53", "a.example")
	if err != nil || d == nil || z != nil {
		t.Errorf("dns %+v zone %+v err %v, want records and no zone", d, z, err)
	}
}

func TestLookupDown(t *testing.T) {
	f := &fakeResolver{down: true}
	if _, _, err := Lookup(context.Background(), f, "9.9.9.9:53", "x.example"); err == nil || err.Error() != "no answer from 9.9.9.9:53" {
		t.Errorf("err = %v, want no answer", err)
	}
}

func TestLookupTimeout(t *testing.T) {
	var got []bool
	var mu sync.Mutex
	c := resolverFunc(func(ctx context.Context, _, _, _ string) resolver.Observation {
		_, ok := ctx.Deadline()
		mu.Lock()
		got = append(got, ok)
		mu.Unlock()
		return resolver.Observation{Rcode: "NOERROR"}
	})
	if _, _, err := Lookup(context.Background(), c, "9.9.9.9:53", "x.example"); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(got, false) || len(got) != len(resolver.QTypes) {
		t.Errorf("deadlines %v, want one per query", got)
	}
}

type resolverFunc func(ctx context.Context, server, fqdn, qtype string) resolver.Observation

func (f resolverFunc) Resolve(ctx context.Context, server, fqdn, qtype string) resolver.Observation {
	return f(ctx, server, fqdn, qtype)
}
