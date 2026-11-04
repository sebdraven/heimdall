// Package vt reads passive DNS resolutions from the VirusTotal API v3.
package vt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/time/rate"
)

const (
	BaseURL = "https://www.virustotal.com/api/v3"
	// PageLimit is the limit of the single page read per object.
	// TODO: the docs give the default (10) but no maximum for limit; 40 is
	// assumed to be accepted.
	PageLimit = 40
	// RatePerSecond stays well under the 300 lookups per minute of the key.
	RatePerSecond = 4

	maxBody = 4 << 20
)

// ErrQuota is returned on HTTP 429: QuotaExceededError or TooManyRequestsError.
var ErrQuota = errors.New("virustotal quota exceeded")

// APIError is any other error answer.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("virustotal: HTTP %d %s: %s", e.Status, e.Code, e.Message)
}

// Resolution is a VirusTotal resolution object: host_name resolved to
// ip_address on date.
type Resolution struct {
	HostName string
	IP       string
	Date     time.Time
}

// Client is safe for concurrent use; its requests share one rate limit.
type Client struct {
	key  string
	base string
	http *http.Client
	lim  *rate.Limiter
}

func New(key string) *Client {
	return &Client{
		key:  key,
		base: BaseURL,
		http: &http.Client{Timeout: 20 * time.Second},
		lim:  rate.NewLimiter(RatePerSecond, 1),
	}
}

// DomainResolutions returns the first page of resolutions of domain, none if
// VirusTotal does not know it.
func (c *Client) DomainResolutions(ctx context.Context, domain string) ([]Resolution, error) {
	return c.resolutions(ctx, "/domains/"+url.PathEscape(domain)+"/resolutions")
}

// IPResolutions returns the first page of resolutions of ip, none if
// VirusTotal does not know it.
func (c *Client) IPResolutions(ctx context.Context, ip string) ([]Resolution, error) {
	return c.resolutions(ctx, "/ip_addresses/"+url.PathEscape(ip)+"/resolutions")
}

type resolutionsBody struct {
	Data []struct {
		Attributes struct {
			Date      int64  `json:"date"`
			HostName  string `json:"host_name"`
			IPAddress string `json:"ip_address"`
		} `json:"attributes"`
	} `json:"data"`
}

type errorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (c *Client) resolutions(ctx context.Context, path string) ([]Resolution, error) {
	if err := c.lim.Wait(ctx); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path+"?limit="+strconv.Itoa(PageLimit), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-apikey", c.key)
	req.Header.Set("Accept", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body := io.LimitReader(res.Body, maxBody)

	switch res.StatusCode {
	case http.StatusOK:
	// TODO: the docs do not say what an object unknown to VirusTotal returns;
	// NotFoundError (404) is assumed.
	case http.StatusNotFound:
		return nil, nil
	default:
		var e errorBody
		_ = json.NewDecoder(body).Decode(&e)
		if res.StatusCode == http.StatusTooManyRequests {
			return nil, fmt.Errorf("%w (%s)", ErrQuota, e.Error.Code)
		}
		return nil, &APIError{Status: res.StatusCode, Code: e.Error.Code, Message: e.Error.Message}
	}

	var b resolutionsBody
	if err := json.NewDecoder(body).Decode(&b); err != nil {
		return nil, fmt.Errorf("virustotal: decode resolutions: %w", err)
	}
	out := make([]Resolution, 0, len(b.Data))
	for _, d := range b.Data {
		a := d.Attributes
		if a.HostName == "" || a.IPAddress == "" {
			continue
		}
		// The docs call date a "UTC timestamp"; seconds, as in their example.
		out = append(out, Resolution{HostName: a.HostName, IP: a.IPAddress, Date: time.Unix(a.Date, 0).UTC()})
	}
	return out, nil
}
