// Package cdn classifies IP addresses against a static list of CDN prefixes,
// whose addresses are shared by unrelated names.
package cdn

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
)

type Prefix struct {
	Prefix   netip.Prefix
	Provider string
}

// Classifier is safe for concurrent use.
type Classifier struct {
	prefixes atomic.Pointer[[]Prefix]
}

func New(prefixes []Prefix) *Classifier {
	c := &Classifier{}
	c.Set(prefixes)
	return c
}

// Set replaces the prefixes.
func (c *Classifier) Set(prefixes []Prefix) {
	ps := slices.Clone(prefixes)
	slices.SortStableFunc(ps, func(a, b Prefix) int { return cmp.Compare(b.Prefix.Bits(), a.Prefix.Bits()) })
	c.prefixes.Store(&ps)
}

// Classify returns the provider of the most specific prefix containing addr.
// Values that are not IP addresses are never classified.
func (c *Classifier) Classify(addr string) (provider string, ok bool) {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return "", false
	}
	ps := c.prefixes.Load()
	if ps == nil {
		return "", false
	}
	a = a.Unmap()
	for _, p := range *ps {
		if p.Prefix.Contains(a) {
			return p.Provider, true
		}
	}
	return "", false
}

// ParsePrefix accepts a CIDR prefix without host bits, or a single address.
func ParsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil || p.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("invalid prefix %q", s)
	}
	if m := p.Masked(); m != p {
		return netip.Prefix{}, fmt.Errorf("prefix %q has host bits set, use %s", s, m)
	}
	return p, nil
}
