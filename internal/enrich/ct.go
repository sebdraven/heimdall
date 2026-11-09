package enrich

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

const (
	DefaultCTURL = "https://crt.sh"
	// MaxCertificates caps the certificates kept, latest first.
	MaxCertificates = 500

	ctTimeout = 30 * time.Second
	maxCTBody = 64 << 20
)

type Certificate struct {
	ID        int64     `json:"id"`
	Issuer    string    `json:"issuer"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	Names     []string  `json:"names"`
}

// CT holds the certificates logged for the names below Zone. Total counts
// them all, Names are those of them all.
type CT struct {
	Zone         string        `json:"zone"`
	Total        int           `json:"total"`
	Certificates []Certificate `json:"certificates"`
	Names        []string      `json:"names"`
	Truncated    bool          `json:"truncated"`
}

// CTClient searches crt.sh.
type CTClient struct {
	HTTP    *http.Client
	BaseURL string
}

func NewCTClient(baseURL string) *CTClient {
	if baseURL == "" {
		baseURL = DefaultCTURL
	}
	return &CTClient{HTTP: &http.Client{Timeout: ctTimeout}, BaseURL: baseURL}
}

func (c *CTClient) Lookup(ctx context.Context, zone string) (*CT, error) {
	u := strings.TrimSuffix(c.BaseURL, "/") + "/?q=" + url.QueryEscape("%."+zone) + "&output=json"
	var rows []crtRow
	if err := getJSON(ctx, c.HTTP, u, "application/json", maxCTBody, &rows); err != nil {
		return nil, fmt.Errorf("crt.sh: %w", err)
	}
	return parseCT(zone, rows), nil
}

type crtRow struct {
	ID         int64  `json:"id"`
	IssuerName string `json:"issuer_name"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
	NameValue  string `json:"name_value"`
}

func parseCT(zone string, rows []crtRow) *CT {
	out := &CT{Zone: zone, Certificates: []Certificate{}}
	seen := map[int64]bool{}
	names := map[string]bool{}
	for _, r := range rows {
		if seen[r.ID] {
			continue
		}
		seen[r.ID] = true
		c := Certificate{ID: r.ID, Issuer: r.IssuerName, NotBefore: crtTime(r.NotBefore), NotAfter: crtTime(r.NotAfter), Names: splitNames(r.NameValue)}
		for _, n := range c.Names {
			names[n] = true
		}
		out.Certificates = append(out.Certificates, c)
	}
	out.Total = len(out.Certificates)
	slices.SortStableFunc(out.Certificates, func(a, b Certificate) int {
		return cmp.Or(b.NotBefore.Compare(a.NotBefore), cmp.Compare(b.ID, a.ID))
	})
	if len(out.Certificates) > MaxCertificates {
		out.Certificates, out.Truncated = out.Certificates[:MaxCertificates], true
	}
	out.Names = slices.Sorted(maps.Keys(names))
	if out.Names == nil {
		out.Names = []string{}
	}
	return out
}

// splitNames reads the names of a name_value, one per line.
func splitNames(v string) []string {
	out := []string{}
	for line := range strings.Lines(v) {
		if n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(line)), "."); n != "" {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// crtTime reads a crt.sh date, UTC without a zone.
func crtTime(v string) time.Time {
	for _, layout := range []string{"2006-01-02T15:04:05", time.RFC3339} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
