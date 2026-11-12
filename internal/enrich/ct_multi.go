package enrich

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
)

const (
	CTSourceCertSpotter = "certspotter"
	CTSourceOnyphe      = "onyphe"
)

// MultiCT searches Cert Spotter and ONYPHE at once and merges their
// certificates by full SHA-256. A nil source is left out.
type MultiCT struct {
	CertSpotter CTLog
	Onyphe      CTLog
}

type sourcedCT struct {
	source string
	from   CTLog
	ct     *CT
	err    error
}

// Lookup merges what each source returned, a partial CT included, and joins
// their errors, each of which names its source.
func (m *MultiCT) Lookup(ctx context.Context, zone string) (*CT, error) {
	var parts []*sourcedCT
	if m.CertSpotter != nil {
		parts = append(parts, &sourcedCT{source: CTSourceCertSpotter, from: m.CertSpotter})
	}
	if m.Onyphe != nil {
		parts = append(parts, &sourcedCT{source: CTSourceOnyphe, from: m.Onyphe})
	}
	if len(parts) == 0 {
		return nil, errors.New("no certificate transparency source")
	}
	var wg sync.WaitGroup
	for _, p := range parts {
		wg.Go(func() { p.ct, p.err = p.from.Lookup(ctx, zone) })
	}
	wg.Wait()

	var msgs []string
	for _, p := range parts {
		if p.err != nil {
			msgs = append(msgs, p.err.Error())
		}
	}
	var err error
	if msgs != nil {
		err = errors.New(strings.Join(msgs, "; "))
	}
	return mergeCT(zone, parts), err
}

// mergeCT keeps one certificate per SHA-256: the union of the names and
// sources, the other fields of the first source that has them, Cert
// Spotter first. Nil when no source returned a CT.
func mergeCT(zone string, parts []*sourcedCT) *CT {
	out := &CT{Zone: zone, Certificates: []Certificate{}}
	found := false
	bySHA := map[string]int{}
	for _, p := range parts {
		if p.ct == nil {
			continue
		}
		found = true
		out.Truncated = out.Truncated || p.ct.Truncated
		for _, c := range p.ct.Certificates {
			key := strings.ToLower(c.CertSHA256)
			i, ok := bySHA[key]
			if key == "" || !ok {
				c.Names = slices.Clone(c.Names)
				c.Sources = []string{p.source}
				if key != "" {
					bySHA[key] = len(out.Certificates)
				}
				out.Certificates = append(out.Certificates, c)
				continue
			}
			m := &out.Certificates[i]
			m.Names = normalizeNames(append(m.Names, c.Names...))
			if !slices.Contains(m.Sources, p.source) {
				m.Sources = append(m.Sources, p.source)
			}
			if m.Issuer == "" {
				m.Issuer = c.Issuer
			}
			if m.NotBefore.IsZero() {
				m.NotBefore = c.NotBefore
			}
			if m.NotAfter.IsZero() {
				m.NotAfter = c.NotAfter
			}
			if m.ID == "" {
				m.ID = c.ID
			}
		}
	}
	if !found {
		return nil
	}
	if len(out.Certificates) > MaxCertificates {
		slices.SortStableFunc(out.Certificates, latestFirst)
		out.Truncated = true
	}
	return out.finish()
}
