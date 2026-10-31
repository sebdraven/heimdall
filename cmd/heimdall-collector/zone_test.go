package main

import (
	"context"
	"slices"
	"testing"
	"time"

	gjallarhorn "github.com/sebdraven/heimdall/internal/changes"
	"github.com/sebdraven/heimdall/internal/resolver"
	"github.com/sebdraven/heimdall/internal/store/ch"
)

func soaValue(serial string) string {
	return "ns1.syamcloud.com hostmaster.syamcloud.com " + serial + " 7200 3600 1209600 300"
}

// nodata is a query on a subdomain answered NOERROR without answer, the zone
// SOA in authority.
func nodata(at time.Duration, domain, qtype, serial string) resolver.Observation {
	return resolver.Observation{
		TS: t0.Add(at), Domain: domain, QType: qtype, Resolver: "9.9.9.9:53", Rcode: "NOERROR",
		Rdata: []string{}, Answers: []resolver.Answer{},
		Authority: []resolver.Answer{{Name: "syamcloud.com", Type: "SOA", Value: soaValue(serial)}},
		Zone:      "syamcloud.com",
	}
}

var (
	zoneSOAKey = gjallarhorn.Key{Domain: "zone:syamcloud.com", QType: "SOA", Resolver: "9.9.9.9:53"}
	zoneNSKey  = gjallarhorn.Key{Domain: "zone:syamcloud.com", QType: "NS", Resolver: "9.9.9.9:53"}
)

// fakeDNS answers every query with ns as NS records, at the time set by the
// test.
type fakeDNS struct {
	ts    time.Time
	ns    []string
	calls []string
}

func (f *fakeDNS) Resolve(_ context.Context, server, fqdn, qtype string) resolver.Observation {
	f.calls = append(f.calls, fqdn+"/"+qtype)
	o := resolver.Observation{TS: f.ts, Domain: fqdn, QType: qtype, Resolver: server, Rcode: "NOERROR", Rdata: f.ns}
	for _, v := range f.ns {
		o.Answers = append(o.Answers, resolver.Answer{Name: fqdn, Type: qtype, Value: v})
	}
	return o
}

func newMeasurer(dns *fakeDNS, watched ...string) *measurer {
	return &measurer{
		tr: newTracker(3), zones: newZoneCache(), client: dns,
		wait:    func(context.Context, string) error { return nil },
		watched: func(fqdn string) bool { return slices.Contains(watched, fqdn) },
	}
}

func TestZoneObservation(t *testing.T) {
	z, ok := zoneObservation(nodata(0, "proxy.syamcloud.com", "SOA", "1"))
	if !ok {
		t.Fatal("no zone observation for a NODATA SOA answer")
	}
	if z.Domain != zoneSOAKey.Domain || z.QType != "SOA" || z.Resolver != zoneSOAKey.Resolver || z.Rcode != "NOERROR" ||
		!z.TS.Equal(t0) || !slices.Equal(z.Rdata, []string{soaValue("1")}) {
		t.Errorf("zone observation %+v", z)
	}

	for name, mutate := range map[string]func(*resolver.Observation){
		"answer present": func(o *resolver.Observation) {
			o.Answers = []resolver.Answer{{Name: "proxy.syamcloud.com", Type: "CNAME", Value: "x.example"}}
		},
		"nxdomain": func(o *resolver.Observation) { o.Rcode = "NXDOMAIN" },
		"a query":  func(o *resolver.Observation) { o.QType = "A" },
		"no zone":  func(o *resolver.Observation) { o.Zone, o.Authority = "", []resolver.Answer{} },
		"ns query with ns in authority": func(o *resolver.Observation) {
			o.QType = "NS"
			o.Authority = []resolver.Answer{{Name: "syamcloud.com", Type: "NS", Value: "ns1.example.net"}}
		},
	} {
		o := nodata(0, "proxy.syamcloud.com", "SOA", "1")
		mutate(&o)
		if z, ok := zoneObservation(o); ok {
			t.Errorf("%s: unexpected zone observation %+v", name, z)
		}
	}
}

func TestMeasureZoneSOADedup(t *testing.T) {
	m := newMeasurer(&fakeDNS{}, "syamcloud.com")
	see := func(o resolver.Observation) []gjallarhorn.Event {
		t.Helper()
		out, release := m.measure(context.Background(), o, "spynote", nil)
		release()
		if len(out) != 1 || out[0].Obs.Domain != o.Domain {
			t.Fatalf("items %+v, want only the measured observation %s", out, o.Domain)
		}
		return out[0].Events
	}

	see(nodata(0, "proxy.syamcloud.com", "SOA", "1"))
	if s, ok := m.tr.state[zoneSOAKey]; !ok || !slices.Equal(s.Tracked, []string{soaValue("1")}) {
		t.Fatalf("zone state %+v, %v", s, ok)
	}

	// Another name of the zone within the window: no derived observation.
	if evs := see(nodata(30*time.Second, "api.syamcloud.com", "SOA", "2")); len(evs) != 0 {
		t.Fatalf("events within the window: %+v", evs)
	}
	if s := m.tr.state[zoneSOAKey]; !slices.Equal(s.Tracked, []string{soaValue("1")}) {
		t.Fatalf("zone state updated within the window: %+v", s)
	}

	evs := see(nodata(61*time.Second, "api.syamcloud.com", "SOA", "2"))
	if len(evs) != 1 {
		t.Fatalf("events after the window: %+v", evs)
	}
	e := evs[0]
	if e.Kind != gjallarhorn.KindSOASerialChange || e.Domain != zoneSOAKey.Domain || e.Campaign != "spynote" || e.Resolver != zoneSOAKey.Resolver {
		t.Errorf("event %+v", e)
	}
	if len(m.tr.pending) != 0 {
		t.Errorf("pending not cleared: %v", m.tr.pending)
	}

	m.tr.prune(map[string]struct{}{})
	if _, ok := m.tr.state[zoneSOAKey]; !ok {
		t.Error("zone tuple pruned with the watchlist")
	}
}

func TestMeasureZoneNSProbe(t *testing.T) {
	dns := &fakeDNS{ns: []string{"ns1.example.net", "ns2.example.net"}}
	m := newMeasurer(dns)
	classes := []gjallarhorn.NSClass{{Pattern: "sinkhole.example", Kind: gjallarhorn.NSKindSinkhole}}
	measure := func(o resolver.Observation) []ch.Item {
		t.Helper()
		dns.ts = o.TS
		out, release := m.measure(context.Background(), o, "spynote", classes)
		if len(out) == 2 && (m.tr.pending[key(o)] != 1 || m.tr.pending[zoneNSKey] != 1) {
			t.Errorf("pending before release %v, want both items", m.tr.pending)
		}
		release()
		if len(m.tr.pending) != 0 {
			t.Errorf("pending after release: %v", m.tr.pending)
		}
		return out
	}

	out := measure(nodata(0, "proxy.syamcloud.com", "A", "1"))
	if len(out) != 2 || out[0].Obs.Domain != "proxy.syamcloud.com" || out[1].Obs.Domain != "syamcloud.com" || out[1].Obs.QType != "NS" {
		t.Fatalf("items %+v, want the observation then the NS of syamcloud.com", out)
	}
	if s, ok := m.tr.state[zoneNSKey]; !ok || !slices.Equal(s.Tracked, dns.ns) {
		t.Fatalf("tracker state under %+v: %+v, %v", zoneNSKey, s, ok)
	}
	if _, ok := m.tr.state[gjallarhorn.Key{Domain: "syamcloud.com", QType: "NS", Resolver: "9.9.9.9:53"}]; ok {
		t.Error("zone NS tracked under the bare zone name")
	}

	if out := measure(nodata(30*time.Second, "api.syamcloud.com", "AAAA", "1")); len(out) != 1 {
		t.Fatalf("second NS query within the window: %+v", out)
	}
	if len(dns.calls) != 1 || dns.calls[0] != "syamcloud.com/NS" {
		t.Fatalf("queries %v, want one NS query on syamcloud.com", dns.calls)
	}

	dns.ns = []string{"ns1.sinkhole.example"}
	out = measure(nodata(61*time.Second, "api.syamcloud.com", "A", "1"))
	if len(out) != 2 || len(dns.calls) != 2 {
		t.Fatalf("no NS query after the window: %d items, queries %v", len(out), dns.calls)
	}
	evs := out[1].Events
	i := slices.IndexFunc(evs, func(e gjallarhorn.Event) bool { return e.Kind == gjallarhorn.KindNSSinkhole })
	if i < 0 || evs[i].Domain != zoneNSKey.Domain || evs[i].Campaign != "spynote" {
		t.Errorf("events %+v, want ns_sinkhole on %s for spynote", evs, zoneNSKey.Domain)
	}
}

func TestMeasureZoneNSProbeSkipsWatchedZone(t *testing.T) {
	dns := &fakeDNS{ns: []string{"ns1.example.net"}}
	m := newMeasurer(dns, "syamcloud.com")
	out, release := m.measure(context.Background(), nodata(0, "proxy.syamcloud.com", "A", "1"), "spynote", nil)
	release()
	if len(out) != 1 || len(dns.calls) != 0 {
		t.Fatalf("watched zone queried: %d items, queries %v", len(out), dns.calls)
	}
	if _, ok := m.tr.state[zoneNSKey]; ok {
		t.Error("zone NS tracked for a watched zone")
	}
}
