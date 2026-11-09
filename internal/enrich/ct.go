package enrich

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

const (
	DefaultCTURL = "https://api.certspotter.com"
	// MaxCertificates caps the certificates read.
	MaxCertificates = 500

	ctTimeout = 30 * time.Second
	maxCTPage = 16 << 20
)

// Certificate is a Cert Spotter issuance. CertSHA256 is empty for an
// enrichment stored before Cert Spotter.
type Certificate struct {
	ID         string    `json:"id"`
	CertSHA256 string    `json:"cert_sha256"`
	Issuer     string    `json:"issuer"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	Revoked    bool      `json:"revoked"`
	Names      []string  `json:"names"`
}

// UnmarshalJSON also reads the numeric id of a certificate stored before
// Cert Spotter.
func (c *Certificate) UnmarshalJSON(b []byte) error {
	type plain Certificate
	var v struct {
		plain
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*c = Certificate(v.plain)
	c.ID = ""
	switch id := strings.TrimSpace(string(v.ID)); {
	case strings.HasPrefix(id, `"`):
		return json.Unmarshal(v.ID, &c.ID)
	case id != "" && id != "null":
		c.ID = id
	}
	return nil
}

// CT holds the certificates issued for Zone and its subdomains: Total is
// the number read, Names the union of their names. Truncated is set when
// the search stopped at MaxCertificates.
type CT struct {
	Zone         string        `json:"zone"`
	Total        int           `json:"total"`
	Certificates []Certificate `json:"certificates"`
	Names        []string      `json:"names"`
	Truncated    bool          `json:"truncated"`
}

// CTClient searches the issuances of Cert Spotter. Without APIKey, the
// public API limits the requests.
type CTClient struct {
	HTTP    *http.Client
	BaseURL string
	APIKey  string
}

func NewCTClient(baseURL, apiKey string) *CTClient {
	if baseURL == "" {
		baseURL = DefaultCTURL
	}
	return &CTClient{HTTP: &http.Client{Timeout: ctTimeout}, BaseURL: baseURL, APIKey: apiKey}
}

type issuance struct {
	ID         string   `json:"id"`
	CertSHA256 string   `json:"cert_sha256"`
	DNSNames   []string `json:"dns_names"`
	Issuer     struct {
		FriendlyName string `json:"friendly_name"`
		Name         string `json:"name"`
	} `json:"issuer"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	Revoked   bool      `json:"revoked"`
}

// Lookup reads the issuances of zone page after page, at most
// MaxCertificates in 30 seconds, and returns them latest first.
func (c *CTClient) Lookup(ctx context.Context, zone string) (*CT, error) {
	ctx, cancel := context.WithTimeout(ctx, ctTimeout)
	defer cancel()
	header := http.Header{}
	if c.APIKey != "" {
		header.Set("Authorization", "Bearer "+c.APIKey)
	}
	out := &CT{Zone: zone, Certificates: []Certificate{}}
	seen := map[string]bool{}
	after := ""
	for {
		if len(out.Certificates) >= MaxCertificates {
			out.Truncated = true
			break
		}
		var page []issuance
		if err := fetchJSON(ctx, c.HTTP, c.issuancesURL(zone, after), "application/json", header, maxCTPage, &page); err != nil {
			return nil, ctError(err)
		}
		if len(page) == 0 {
			break
		}
		for _, is := range page {
			if !seen[is.ID] {
				seen[is.ID] = true
				out.Certificates = append(out.Certificates, is.certificate())
			}
		}
		next := page[len(page)-1].ID
		if next == "" || next == after {
			break
		}
		after = next
	}
	if len(out.Certificates) > MaxCertificates {
		out.Certificates = out.Certificates[:MaxCertificates]
	}
	slices.SortStableFunc(out.Certificates, func(a, b Certificate) int {
		return cmp.Or(b.NotBefore.Compare(a.NotBefore), cmp.Compare(a.ID, b.ID))
	})
	names := map[string]bool{}
	for _, cert := range out.Certificates {
		for _, n := range cert.Names {
			names[n] = true
		}
	}
	out.Names = slices.Sorted(maps.Keys(names))
	if out.Names == nil {
		out.Names = []string{}
	}
	out.Total = len(out.Certificates)
	return out, nil
}

func (c *CTClient) issuancesURL(zone, after string) string {
	q := url.Values{"domain": {zone}, "include_subdomains": {"true"}, "expand": {"dns_names", "issuer"}}
	if after != "" {
		q.Set("after", after)
	}
	return strings.TrimSuffix(c.BaseURL, "/") + "/v1/issuances?" + q.Encode()
}

func (is issuance) certificate() Certificate {
	issuer := is.Issuer.FriendlyName
	if issuer == "" {
		issuer = is.Issuer.Name
	}
	return Certificate{
		ID: is.ID, CertSHA256: is.CertSHA256, Issuer: issuer, NotBefore: is.NotBefore.UTC(), NotAfter: is.NotAfter.UTC(),
		Revoked: is.Revoked, Names: normalizeNames(is.DNSNames),
	}
}

func ctError(err error) error {
	var se *statusError
	if errors.As(err, &se) && se.Code == http.StatusTooManyRequests {
		if se.RetryAfter != "" {
			return fmt.Errorf("cert spotter rate limited, retry after %s", se.RetryAfter)
		}
		return errors.New("cert spotter rate limited")
	}
	return fmt.Errorf("cert spotter: %w", err)
}

// normalizeNames lowercases names and drops their final dot, sorted and
// unique.
func normalizeNames(names []string) []string {
	out := []string{}
	for _, n := range names {
		if n = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), "."); n != "" {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}
