package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/sebdraven/heimdall/internal/resolver"
)

const (
	// IANABootstrap maps each TLD to its RDAP servers.
	IANABootstrap = "https://data.iana.org/rdap/dns.json"

	rdapTimeout  = 15 * time.Second
	bootstrapTTL = 24 * time.Hour
	maxRDAPBody  = 4 << 20
	// maxEntityDepth bounds the nesting of entities read.
	maxEntityDepth = 3
)

type Registrar struct {
	Name   string `json:"name"`
	IANAID string `json:"iana_id"`
}

// Entity is a contact of a registration, by role and name only.
type Entity struct {
	Roles []string `json:"roles"`
	Name  string   `json:"name"`
}

// RDAP is the registration of Domain, the registrable domain of a name.
type RDAP struct {
	Domain       string     `json:"domain"`
	Registrar    *Registrar `json:"registrar"`
	Registration time.Time  `json:"registration,omitzero"`
	Expiration   time.Time  `json:"expiration,omitzero"`
	LastChanged  time.Time  `json:"last_changed,omitzero"`
	Status       []string   `json:"status"`
	Nameservers  []string   `json:"nameservers"`
	Entities     []Entity   `json:"entities"`
}

// RDAPClient finds the RDAP server of a TLD in the IANA bootstrap, kept
// bootstrapTTL in memory.
type RDAPClient struct {
	HTTP      *http.Client
	Bootstrap string
	Now       func() time.Time

	mu      sync.Mutex
	servers map[string]string
	loaded  time.Time
}

func NewRDAPClient() *RDAPClient {
	return &RDAPClient{HTTP: &http.Client{Timeout: rdapTimeout}, Bootstrap: IANABootstrap, Now: time.Now}
}

// Lookup returns the registration of the registrable domain of name.
func (c *RDAPClient) Lookup(ctx context.Context, name string) (*RDAP, error) {
	domain, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		return nil, fmt.Errorf("no registrable domain for %s", name)
	}
	base, err := c.server(ctx, domain[strings.LastIndexByte(domain, '.')+1:])
	if err != nil {
		return nil, err
	}
	var raw rdapDomain
	if err := getJSON(ctx, c.HTTP, base+"domain/"+domain, "application/rdap+json", maxRDAPBody, &raw); err != nil {
		return nil, fmt.Errorf("rdap %s: %w", domain, err)
	}
	return raw.parse(domain), nil
}

// server returns the base URL of the RDAP server of tld. A bootstrap that
// cannot be reloaded is kept.
func (c *RDAPClient) server(ctx context.Context, tld string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.servers == nil || c.Now().Sub(c.loaded) >= bootstrapTTL {
		servers, err := c.loadBootstrap(ctx)
		switch {
		case err == nil:
			c.servers, c.loaded = servers, c.Now()
		case c.servers == nil:
			return "", fmt.Errorf("rdap bootstrap: %w", err)
		}
	}
	base, ok := c.servers[strings.ToLower(tld)]
	if !ok {
		return "", fmt.Errorf("no RDAP server for .%s", tld)
	}
	return base, nil
}

func (c *RDAPClient) loadBootstrap(ctx context.Context) (map[string]string, error) {
	var b struct {
		Services [][][]string `json:"services"`
	}
	if err := getJSON(ctx, c.HTTP, c.Bootstrap, "application/json", maxRDAPBody, &b); err != nil {
		return nil, err
	}
	servers := map[string]string{}
	for _, s := range b.Services {
		if len(s) < 2 {
			continue
		}
		base := pickURL(s[1])
		if base == "" {
			continue
		}
		for _, tld := range s[0] {
			servers[strings.ToLower(tld)] = base
		}
	}
	return servers, nil
}

// pickURL prefers an https URL, and ends it with a slash.
func pickURL(urls []string) string {
	if len(urls) == 0 {
		return ""
	}
	u := urls[0]
	if i := slices.IndexFunc(urls, func(v string) bool { return strings.HasPrefix(v, "https://") }); i >= 0 {
		u = urls[i]
	}
	if !strings.HasSuffix(u, "/") {
		u += "/"
	}
	return u
}

type rdapDomain struct {
	Status []string `json:"status"`
	Events []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Nameservers []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
	Entities []rdapEntity `json:"entities"`
}

type rdapEntity struct {
	Roles     []string        `json:"roles"`
	VCard     json.RawMessage `json:"vcardArray"`
	PublicIDs []struct {
		Type       string `json:"type"`
		Identifier string `json:"identifier"`
	} `json:"publicIds"`
	Entities []rdapEntity `json:"entities"`
}

func (d rdapDomain) parse(domain string) *RDAP {
	out := &RDAP{Domain: domain, Status: nonNil(d.Status), Nameservers: []string{}, Entities: []Entity{}}
	for _, e := range d.Events {
		t, err := time.Parse(time.RFC3339, e.Date)
		if err != nil {
			continue
		}
		switch strings.ToLower(e.Action) {
		case "registration":
			out.Registration = t.UTC()
		case "expiration":
			out.Expiration = t.UTC()
		case "last changed":
			out.LastChanged = t.UTC()
		}
	}
	for _, ns := range d.Nameservers {
		if n := resolver.Name(ns.LDHName); n != "" {
			out.Nameservers = append(out.Nameservers, n)
		}
	}
	slices.Sort(out.Nameservers)
	out.Nameservers = slices.Compact(out.Nameservers)
	out.addEntities(d.Entities, 0)
	return out
}

func (r *RDAP) addEntities(entities []rdapEntity, depth int) {
	if depth >= maxEntityDepth {
		return
	}
	for _, e := range entities {
		name := vcardName(e.VCard)
		r.Entities = append(r.Entities, Entity{Roles: nonNil(e.Roles), Name: name})
		if r.Registrar == nil && slices.Contains(e.Roles, "registrar") {
			r.Registrar = &Registrar{Name: name}
			for _, id := range e.PublicIDs {
				if strings.EqualFold(id.Type, "IANA Registrar ID") {
					r.Registrar.IANAID = id.Identifier
				}
			}
		}
		r.addEntities(e.Entities, depth+1)
	}
}

// vcardName returns the fn of a jCard, else its org. No other property is
// read.
func vcardName(raw json.RawMessage) string {
	var card []json.RawMessage
	if json.Unmarshal(raw, &card) != nil || len(card) < 2 {
		return ""
	}
	var props [][]json.RawMessage
	if json.Unmarshal(card[1], &props) != nil {
		return ""
	}
	var org string
	for _, p := range props {
		if len(p) < 4 {
			continue
		}
		var name, value string
		if json.Unmarshal(p[0], &name) != nil || json.Unmarshal(p[3], &value) != nil {
			continue
		}
		switch strings.ToLower(name) {
		case "fn":
			if value != "" {
				return value
			}
		case "org":
			org = value
		}
	}
	return org
}
