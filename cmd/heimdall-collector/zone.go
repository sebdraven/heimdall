package main

import (
	"context"
	"slices"
	"sync"
	"time"

	gjallarhorn "github.com/sebdraven/heimdall/internal/changes"
	"github.com/sebdraven/heimdall/internal/resolver"
	"github.com/sebdraven/heimdall/internal/store/ch"
)

const zoneWindow = 60 * time.Second

// zoneObservation derives an observation of the enclosing zone from a SOA
// query answered NOERROR with an empty answer section, the zone SOA being in
// the authority section.
func zoneObservation(obs resolver.Observation) (resolver.Observation, bool) {
	if obs.QType != "SOA" || obs.Rcode != "NOERROR" || len(obs.Answers) > 0 || obs.Zone == "" {
		return resolver.Observation{}, false
	}
	rdata := []string{}
	for _, a := range obs.Authority {
		if a.Name == obs.Zone && a.Type == obs.QType {
			rdata = append(rdata, a.Value)
		}
	}
	if len(rdata) == 0 {
		return resolver.Observation{}, false
	}
	slices.Sort(rdata)
	rdata = slices.Compact(rdata)
	return resolver.Observation{
		TS: obs.TS, Domain: gjallarhorn.ZonePrefix + obs.Zone, QType: obs.QType, Resolver: obs.Resolver,
		Rcode: "NOERROR", Rdata: rdata, AnswerHash: resolver.AnswerHash("NOERROR", rdata),
	}, true
}

// zoneCache lets one zone tuple through per zoneWindow, however many watched
// names share the zone.
type zoneCache struct {
	mu    sync.Mutex
	seen  map[gjallarhorn.Key]time.Time
	swept time.Time
}

func newZoneCache() *zoneCache {
	return &zoneCache{seen: make(map[gjallarhorn.Key]time.Time)}
}

func (c *zoneCache) allow(k gjallarhorn.Key, ts time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ts.Sub(c.swept) >= zoneWindow {
		for key, last := range c.seen {
			if ts.Sub(last) >= zoneWindow {
				delete(c.seen, key)
			}
		}
		c.swept = ts
	}
	if last, ok := c.seen[k]; ok && ts.Sub(last) < zoneWindow {
		return false
	}
	c.seen[k] = ts
	return true
}

// dnsClient is the part of resolver.Client used by the workers.
type dnsClient interface {
	Resolve(ctx context.Context, server, fqdn, qtype string) resolver.Observation
}

// measurer feeds observations to the tracker, with the SOA derived from
// their authority section and an active NS query on the zone it names.
type measurer struct {
	tr      *tracker
	zones   *zoneCache
	client  dnsClient
	wait    func(ctx context.Context, server string) error
	watched func(fqdn string) bool
}

// measure returns the items for the writer: obs, then the zone NS
// observation if one was queried. release must be called once all of them
// have been handed to the writer.
func (m *measurer) measure(ctx context.Context, obs resolver.Observation, campaign string, classes []gjallarhorn.NSClass) ([]ch.Item, func()) {
	ns, probed := m.probeNS(ctx, obs)

	changes, events, release := m.tr.observe(obs, campaign, classes)
	if z, ok := zoneObservation(obs); ok && m.zones.allow(key(z), z.TS) {
		zc, ze, zrelease := m.tr.observe(z, campaign, classes)
		changes, events, release = append(changes, zc...), append(events, ze...), both(release, zrelease)
	}
	items := []ch.Item{{Obs: obs, Changes: changes, Events: events}}
	if probed {
		tracked := ns
		tracked.Domain = gjallarhorn.ZonePrefix + ns.Domain
		nc, ne, nrelease := m.tr.observe(tracked, campaign, classes)
		items = append(items, ch.Item{Obs: ns, Changes: nc, Events: ne})
		release = both(release, nrelease)
	}
	return items, release
}

// probeNS queries the NS of the zone named by an empty NOERROR answer, at
// most once per zone and resolver per zoneWindow, unless the zone is watched.
func (m *measurer) probeNS(ctx context.Context, obs resolver.Observation) (resolver.Observation, bool) {
	if obs.Rcode != "NOERROR" || len(obs.Answers) > 0 || obs.Zone == "" || m.watched(obs.Zone) {
		return resolver.Observation{}, false
	}
	k := gjallarhorn.Key{Domain: gjallarhorn.ZonePrefix + obs.Zone, QType: "NS", Resolver: obs.Resolver}
	if !m.zones.allow(k, obs.TS) || m.wait(ctx, obs.Resolver) != nil {
		return resolver.Observation{}, false
	}
	return m.client.Resolve(context.WithoutCancel(ctx), obs.Resolver, obs.Zone, "NS"), true
}

func key(o resolver.Observation) gjallarhorn.Key {
	return gjallarhorn.Key{Domain: o.Domain, QType: o.QType, Resolver: o.Resolver}
}

func both(a, b func()) func() {
	return func() {
		a()
		b()
	}
}
