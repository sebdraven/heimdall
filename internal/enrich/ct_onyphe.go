package enrich

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

const (
	DefaultOnypheURL = "https://www.onyphe.io/api/v2"
	// DefaultOnypheCTWindow is the last 48 months: without a time function
	// ONYPHE searches the last 30 days.
	DefaultOnypheCTWindow = "-since:48M"
)

// OnypheClient searches the certificates of the ONYPHE category ctl over
// Window, an OQL time function.
type OnypheClient struct {
	HTTP    *http.Client
	BaseURL string
	APIKey  string
	Window  string
}

func NewOnypheClient(baseURL, apiKey, window string) *OnypheClient {
	if baseURL == "" {
		baseURL = DefaultOnypheURL
	}
	return &OnypheClient{HTTP: &http.Client{Timeout: ctTimeout}, BaseURL: baseURL, APIKey: apiKey, Window: window}
}

type onyphePage struct {
	Error   int          `json:"error"`
	Text    string       `json:"text"`
	MaxPage int          `json:"max_page"`
	Results []onypheCert `json:"results"`
}

type onypheCert struct {
	Fingerprint struct {
		SHA256 string `json:"sha256"`
	} `json:"fingerprint"`
	Hostname strs `json:"hostname"`
	Subject  struct {
		AltName strs `json:"altname"`
	} `json:"subject"`
	Issuer struct {
		CommonName   string `json:"commonname"`
		Organization string `json:"organization"`
	} `json:"issuer"`
	Validity struct {
		NotBefore time.Time `json:"notbefore"`
		NotAfter  time.Time `json:"notafter"`
	} `json:"validity"`
}

// strs reads a string or an array of strings.
type strs []string

func (s *strs) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*s = strs{one}
		return nil
	}
	return json.Unmarshal(b, (*[]string)(s))
}

// Lookup reads the certificates of zone page after page up to max_page, at
// most MaxCertificates in 30 seconds, and returns them latest first, one per
// SHA-256. ONYPHE files a certificate under its registrable domain: below
// it, only the certificates with a name within zone are kept. A 429 after
// the first page returns the certificates read, Truncated, with the error.
func (c *OnypheClient) Lookup(ctx context.Context, zone string) (*CT, error) {
	ctx, cancel := context.WithTimeout(ctx, ctTimeout)
	defer cancel()
	domain, err := publicsuffix.EffectiveTLDPlusOne(zone)
	if err != nil {
		return nil, fmt.Errorf("onyphe: no registrable domain for %s", zone)
	}
	header := http.Header{"Authorization": {"bearer " + c.APIKey}}
	out := &CT{Zone: zone, Certificates: []Certificate{}}
	seen := map[string]bool{}
	for page := 1; ; page++ {
		if len(out.Certificates) >= MaxCertificates {
			out.Truncated = true
			break
		}
		var res onyphePage
		if err := fetchJSON(ctx, c.HTTP, c.searchURL(domain, page), "application/json", header, maxCTPage, &res); err != nil {
			var se *statusError
			if len(out.Certificates) > 0 && errors.As(err, &se) && se.Code == http.StatusTooManyRequests {
				out.Truncated = true
				return out.finish(), onypheError(err)
			}
			return nil, onypheError(err)
		}
		if res.Error != 0 {
			return nil, fmt.Errorf("onyphe: error %d: %s", res.Error, res.Text)
		}
		for _, r := range res.Results {
			sha := strings.ToLower(strings.TrimSpace(r.Fingerprint.SHA256))
			if sha == "" || seen[sha] {
				continue
			}
			seen[sha] = true
			if cert := r.certificate(sha); domain == zone || anyWithin(cert.Names, zone) {
				out.Certificates = append(out.Certificates, cert)
			}
		}
		if page >= res.MaxPage || len(res.Results) == 0 {
			break
		}
	}
	return out.finish(), nil
}

func (c *OnypheClient) searchURL(domain string, page int) string {
	oql := strings.TrimSpace("category:ctl domain:" + domain + " " + c.Window)
	q := url.Values{"q": {oql}, "page": {strconv.Itoa(page)}}
	return strings.TrimSuffix(c.BaseURL, "/") + "/search/?" + q.Encode()
}

func (r onypheCert) certificate(sha string) Certificate {
	issuer := r.Issuer.CommonName
	if issuer == "" {
		issuer = r.Issuer.Organization
	}
	return Certificate{
		CertSHA256: sha, Issuer: issuer, NotBefore: r.Validity.NotBefore.UTC(), NotAfter: r.Validity.NotAfter.UTC(),
		Names: normalizeNames(append(r.Subject.AltName, r.Hostname...)),
	}
}

func anyWithin(names []string, zone string) bool {
	for _, n := range names {
		if within(strings.TrimPrefix(n, "*."), zone) {
			return true
		}
	}
	return false
}

func onypheError(err error) error {
	var se *statusError
	if !errors.As(err, &se) {
		return fmt.Errorf("onyphe: %w", err)
	}
	if se.Code == http.StatusTooManyRequests {
		msg := "onyphe rate limited"
		if se.RetryAfter != "" {
			msg += ", retry after " + se.RetryAfter
		}
		return errors.New(msg)
	}
	var body struct {
		Text string `json:"text"`
	}
	if json.Unmarshal([]byte(se.Body), &body) == nil && body.Text != "" {
		return fmt.Errorf("onyphe: %w: %s", err, body.Text)
	}
	return fmt.Errorf("onyphe: %w", err)
}
