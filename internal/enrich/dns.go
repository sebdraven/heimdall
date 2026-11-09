package enrich

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sebdraven/heimdall/internal/resolver"
)

// DNSTimeout bounds each query of Lookup.
const DNSTimeout = 3 * time.Second

// Resolver asks one question to a server; *resolver.Client is one.
type Resolver interface {
	Resolve(ctx context.Context, server, fqdn, qtype string) resolver.Observation
}

type Record struct {
	QType string   `json:"qtype"`
	Rcode string   `json:"rcode"`
	TTL   uint32   `json:"ttl"`
	Rdata []string `json:"rdata"`
}

// DNS is the answer of Resolver to each of resolver.QTypes.
type DNS struct {
	Resolver string   `json:"resolver"`
	Records  []Record `json:"records"`
}

// Rdata returns the values of qtype.
func (d *DNS) Rdata(qtype string) []string {
	for _, r := range d.Records {
		if r.QType == qtype {
			return r.Rdata
		}
	}
	return []string{}
}

// Zone is the zone of a name, with its SOA and NS.
type Zone struct {
	Name string   `json:"name"`
	SOA  []string `json:"soa"`
	NS   []string `json:"ns"`
}

// Lookup asks server the resolver.QTypes of fqdn at once. The zone is fqdn
// when it owns a SOA, else the zone of an authority section, asked then its
// SOA and NS; it is nil when none is found. Lookup fails when no query got
// an answer.
func Lookup(ctx context.Context, c Resolver, server, fqdn string) (*DNS, *Zone, error) {
	obs := resolveAll(ctx, c, server, fqdn, resolver.QTypes)
	d := &DNS{Resolver: server, Records: make([]Record, 0, len(obs))}
	answered := false
	for _, o := range obs {
		d.Records = append(d.Records, Record{QType: o.QType, Rcode: o.Rcode, TTL: o.TTL, Rdata: nonNil(o.Rdata)})
		answered = answered || (o.Rcode != resolver.RcodeTimeout && o.Rcode != resolver.RcodeNetErr)
	}
	if !answered {
		return nil, nil, fmt.Errorf("no answer from %s", server)
	}
	name := zoneOf(fqdn, obs)
	if name == "" {
		return d, nil, nil
	}
	z := &Zone{Name: name, SOA: d.Rdata("SOA"), NS: d.Rdata("NS")}
	if name != fqdn {
		zo := resolveAll(ctx, c, server, name, []string{"SOA", "NS"})
		z.SOA, z.NS = nonNil(zo[0].Rdata), nonNil(zo[1].Rdata)
	}
	return d, z, nil
}

func resolveAll(ctx context.Context, c Resolver, server, fqdn string, qtypes []string) []resolver.Observation {
	out := make([]resolver.Observation, len(qtypes))
	var wg sync.WaitGroup
	for i, qt := range qtypes {
		wg.Go(func() {
			qctx, cancel := context.WithTimeout(ctx, DNSTimeout)
			defer cancel()
			out[i] = c.Resolve(qctx, server, fqdn, qt)
		})
	}
	wg.Wait()
	return out
}

func zoneOf(fqdn string, obs []resolver.Observation) string {
	for _, o := range obs {
		for _, a := range o.Answers {
			if a.Type == "SOA" && a.Name == fqdn {
				return fqdn
			}
		}
	}
	for _, o := range obs {
		if z := resolver.Zone(o.Authority); z != "" {
			return z
		}
	}
	return ""
}
