package cdn

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"
)

const (
	SyncTimeout = 30 * time.Second
	userAgent   = "heimdall"
	maxListBody = 64 << 20
)

// Source is the official list of a provider. Name is its key for heimdall-cli
// cdn-sync -provider and in the source "sync:<name>" of its prefixes,
// Provider its name in cdn_prefixes. Parse reads the body of one of URLs.
type Source struct {
	Name     string
	Provider string
	URLs     []string
	Parse    func(io.Reader) ([]netip.Prefix, error)
}

// Sources are the providers synced by default.
var Sources = []Source{
	{
		Name: "cloudflare", Provider: "Cloudflare", Parse: ParseCloudflare,
		URLs: []string{"https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"},
	},
	{
		Name: "fastly", Provider: "Fastly", Parse: ParseFastly,
		URLs: []string{"https://api.fastly.com/public-ip-list"},
	},
	{
		Name: "cloudfront", Provider: "CloudFront", Parse: ParseCloudFront,
		URLs: []string{"https://ip-ranges.amazonaws.com/ip-ranges.json"},
	},
	{
		Name: "bunny", Provider: "Bunny", Parse: ParseBunny,
		URLs: []string{"https://bunnycdn.com/api/system/edgeserverlist", "https://bunnycdn.com/api/system/edgeserverlist/IPv6"},
	},
}

// RIPEStatURL lists the prefixes announced by an AS.
const RIPEStatURL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%d"

// ASNSource lists the prefixes announced by asn, named provider. An AS may
// also announce hosting that is not a CDN.
func ASNSource(asn uint32, provider string) Source {
	return Source{
		Name: strings.ToLower(provider), Provider: provider, Parse: ParseRIPEStat,
		URLs: []string{fmt.Sprintf(RIPEStatURL, asn)},
	}
}

func NewSyncClient() *http.Client {
	return &http.Client{Timeout: SyncTimeout}
}

// Fetch reads every URL of src and returns their prefixes, sorted and
// unique. An empty list is an error: syncing it would remove every prefix.
func Fetch(ctx context.Context, c *http.Client, src Source) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, u := range src.URLs {
		ps, err := fetchList(ctx, c, u, src.Parse)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", u, err)
		}
		out = append(out, ps...)
	}
	out = SortPrefixes(out)
	if len(out) == 0 {
		return nil, errors.New("no prefix listed")
	}
	return out, nil
}

func fetchList(ctx context.Context, c *http.Client, u string, parse func(io.Reader) ([]netip.Prefix, error)) ([]netip.Prefix, error) {
	ctx, cancel := context.WithTimeout(ctx, SyncTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json, text/plain;q=0.9")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxListBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxListBody {
		return nil, fmt.Errorf("list larger than %d bytes", maxListBody)
	}
	return parse(bytes.NewReader(body))
}

// SortPrefixes sorts ps by address then length, without duplicates.
func SortPrefixes(ps []netip.Prefix) []netip.Prefix {
	ps = slices.Clone(ps)
	slices.SortFunc(ps, func(a, b netip.Prefix) int {
		return cmp.Or(a.Addr().Compare(b.Addr()), cmp.Compare(a.Bits(), b.Bits()))
	})
	return slices.Compact(ps)
}

// ParseCloudflare reads one prefix per line.
func ParseCloudflare(r io.Reader) ([]netip.Prefix, error) {
	var values []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if v := strings.TrimSpace(sc.Text()); v != "" {
			values = append(values, v)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return parsePrefixes(values)
}

// ParseFastly reads {"addresses": [...], "ipv6_addresses": [...]}.
func ParseFastly(r io.Reader) ([]netip.Prefix, error) {
	var v struct {
		Addresses     []string `json:"addresses"`
		IPv6Addresses []string `json:"ipv6_addresses"`
	}
	if err := json.NewDecoder(r).Decode(&v); err != nil {
		return nil, err
	}
	return parsePrefixes(append(v.Addresses, v.IPv6Addresses...))
}

// ParseCloudFront reads the AWS ranges, "ip_prefix" in "prefixes" and
// "ipv6_prefix" in "ipv6_prefixes", and keeps those of service CLOUDFRONT.
func ParseCloudFront(r io.Reader) ([]netip.Prefix, error) {
	var v struct {
		Prefixes []struct {
			Prefix  string `json:"ip_prefix"`
			Service string `json:"service"`
		} `json:"prefixes"`
		IPv6Prefixes []struct {
			Prefix  string `json:"ipv6_prefix"`
			Service string `json:"service"`
		} `json:"ipv6_prefixes"`
	}
	if err := json.NewDecoder(r).Decode(&v); err != nil {
		return nil, err
	}
	var values []string
	for _, p := range v.Prefixes {
		if p.Service == "CLOUDFRONT" {
			values = append(values, p.Prefix)
		}
	}
	for _, p := range v.IPv6Prefixes {
		if p.Service == "CLOUDFRONT" {
			values = append(values, p.Prefix)
		}
	}
	return parsePrefixes(values)
}

// ParseBunny reads a JSON array of edge server addresses, each a /32 or a
// /128.
func ParseBunny(r io.Reader) ([]netip.Prefix, error) {
	var values []string
	if err := json.NewDecoder(r).Decode(&values); err != nil {
		return nil, err
	}
	out := make([]netip.Prefix, 0, len(values))
	var bad []string
	for _, v := range values {
		a, err := netip.ParseAddr(strings.TrimSpace(v))
		if err != nil || a.Zone() != "" {
			bad = append(bad, fmt.Sprintf("%q", v))
			continue
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	if len(bad) > 0 {
		return nil, fmt.Errorf("%d invalid address(es): %s", len(bad), strings.Join(bad, ", "))
	}
	return out, nil
}

// ParseRIPEStat reads the "announced-prefixes" data call.
func ParseRIPEStat(r io.Reader) ([]netip.Prefix, error) {
	var v struct {
		Status string `json:"status"`
		Data   struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(r).Decode(&v); err != nil {
		return nil, err
	}
	if v.Status != "ok" {
		return nil, fmt.Errorf("RIPEstat status %q", v.Status)
	}
	values := make([]string, 0, len(v.Data.Prefixes))
	for _, p := range v.Data.Prefixes {
		values = append(values, p.Prefix)
	}
	return parsePrefixes(values)
}

// parsePrefixes rejects the whole list if any value is invalid.
func parsePrefixes(values []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(values))
	var bad []string
	for _, v := range values {
		p, err := ParsePrefix(v)
		if err != nil {
			bad = append(bad, err.Error())
			continue
		}
		out = append(out, p)
	}
	if len(bad) > 0 {
		return nil, fmt.Errorf("%d invalid prefix(es): %s", len(bad), strings.Join(bad, "; "))
	}
	return out, nil
}
