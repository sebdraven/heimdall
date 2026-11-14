package enrich

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	DefaultLookylooMaxCaptures = 10
	DefaultLookylooMaxAge      = 720 * time.Hour

	// lookylooTimeout bounds the source within the 2 minutes of the job:
	// without a submission, a search then 3 rounds of 4 captures at 20
	// seconds a request at worst.
	lookylooTimeout        = 90 * time.Second
	lookylooRequestTimeout = 20 * time.Second
	lookylooParallel       = 4
	// lookylooSearchFactor: hostname_info answers one row per capture and
	// hostnode.
	lookylooSearchFactor = 4
	lookylooWait         = 45 * time.Second
	lookylooPollEvery    = 5 * time.Second
	maxLookylooBody      = 16 << 20
)

// Not measured on the instance: the answer to a submission and the status
// of a capture. These are the forms read.
const (
	lookylooSubmitPath = "/submit"
	lookylooStatusDone = 1
)

var (
	lookylooUUIDKeys   = []string{"uuid", "capture_uuid", "perma_uuid"}
	lookylooStatusKeys = []string{"status_code", "status"}
	lookylooDoneStatus = []string{"done", "ready", "finished"}
)

var reUUID = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)

// ErrLookylooNotConfigured is the error of the source without
// HEIMDALL_LOOKYLOO_URL; it does not count in the status.
var ErrLookylooNotConfigured = errors.New("lookyloo not configured")

// Lookyloo holds the captures of a name read on Instance, latest first, and
// the trackers and hosts of those whose navigation goes through the name.
// Truncated is set past the captures read, or when one could not be read.
// Submitted is the capture asked for by this enrichment.
type Lookyloo struct {
	Instance      string        `json:"instance"`
	CapturesFound int           `json:"captures_found"`
	CapturesRead  int           `json:"captures_read"`
	Truncated     bool          `json:"truncated"`
	Submitted     *string       `json:"submitted"`
	Captures      []Capture     `json:"captures"`
	Trackers      []TrackerSeen `json:"trackers"`
	Hosts         []CaptureHost `json:"hosts"`
}

// Capture is a capture of the instance; a part not read stays empty.
type Capture struct {
	UUID      string    `json:"uuid"`
	Time      time.Time `json:"time"`
	URL       string    `json:"url"`
	Title     string    `json:"title"`
	FinalURL  string    `json:"final_url"`
	Redirects []string  `json:"redirects"`
	Hostnames []string  `json:"hostnames"`
	Trackers  []Tracker `json:"trackers"`
}

// TrackerSeen is a tracker of Captures captures, the first and last at
// FirstSeen and LastSeen.
type TrackerSeen struct {
	Kind      string    `json:"kind"`
	ID        string    `json:"id"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Captures  int       `json:"captures"`
}

type CaptureHost struct {
	Name      string    `json:"name"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// TreeURL is the page of a capture on the instance.
func (l *Lookyloo) TreeURL(uuid string) string {
	return l.Instance + "/tree/" + url.PathEscape(uuid)
}

// Visits reports whether fqdn is the host of the URL, a redirect or the
// final URL of c.
func (c Capture) Visits(fqdn string) bool {
	for _, u := range append([]string{c.URL, c.FinalURL}, c.Redirects...) {
		if URLHost(u) == fqdn {
			return true
		}
	}
	return false
}

// URLHost returns the host of a URL, lowercased, without final dot.
func URLHost(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return hostOf(u)
}

// LookylooClient reads the captures of an open Lookyloo instance and, with
// Submit, captures a name none of whose captures is younger than MaxAge.
type LookylooClient struct {
	HTTP        *http.Client
	BaseURL     string
	MaxCaptures int
	Submit      bool
	MaxAge      time.Duration
	PollEvery   time.Duration
	Now         func() time.Time
}

func NewLookylooClient(baseURL string, maxCaptures int, submit bool, maxAge time.Duration) *LookylooClient {
	return &LookylooClient{
		HTTP: &http.Client{Timeout: lookylooRequestTimeout}, BaseURL: strings.TrimSuffix(baseURL, "/"),
		MaxCaptures: maxCaptures, Submit: submit, MaxAge: maxAge, PollEvery: lookylooPollEvery,
	}
}

type lookylooHit struct {
	UUID  string `json:"capture_uuid"`
	Start string `json:"start_timestamp"`
	Title string `json:"title"`
}

// Captures reads the MaxCaptures latest captures of fqdn, 4 at a time, in
// 90 seconds. A capture of which a part failed is kept with the error,
// which names its route; the source fails only when the search does.
func (c *LookylooClient) Captures(ctx context.Context, fqdn string) (*Lookyloo, error) {
	ctx, cancel := context.WithTimeout(ctx, lookylooTimeout)
	defer cancel()
	maxCaptures := cmp.Or(max(c.MaxCaptures, 0), DefaultLookylooMaxCaptures)
	limit := lookylooSearchFactor * maxCaptures
	var hits []lookylooHit
	if err := postJSON(ctx, c.HTTP, c.BaseURL+"/json/hostname_info", map[string]any{"hostname": fqdn, "limit": limit}, maxLookylooBody, &hits); err != nil {
		return nil, lookylooError("hostname_info", err)
	}
	found := uniqueCaptures(hits)
	out := &Lookyloo{Instance: c.BaseURL, CapturesFound: len(found), Truncated: len(hits) >= limit}
	errs := errorSet{}
	if c.Submit && !anyAfter(found, c.now().Add(-cmp.Or(c.MaxAge, DefaultLookylooMaxAge))) {
		sub, err := c.submit(ctx, fqdn)
		errs.add(err)
		if sub.UUID != "" {
			out.Submitted = &sub.UUID
		}
		if err == nil {
			found = append([]Capture{sub}, found...)
			out.CapturesFound++
		}
	}
	if len(found) > maxCaptures {
		found, out.Truncated = found[:maxCaptures], true
	}

	read := make([]bool, len(found))
	sem := make(chan struct{}, lookylooParallel)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := range found {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			ok, failed := c.readCapture(ctx, &found[i])
			read[i] = ok
			mu.Lock()
			defer mu.Unlock()
			errs.add(failed...)
		})
	}
	wg.Wait()
	for i, cp := range found {
		if read[i] {
			out.Captures = append(out.Captures, cp)
		} else {
			out.Truncated = true
		}
	}
	out.finish(fqdn)
	return out, errs.err()
}

func (c *LookylooClient) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// uniqueCaptures keeps one capture per uuid, latest first.
func uniqueCaptures(hits []lookylooHit) []Capture {
	var out []Capture
	seen := map[string]bool{}
	for _, h := range hits {
		id := strings.TrimSpace(h.UUID)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, Capture{UUID: id, Time: lookylooTime(h.Start), Title: h.Title})
	}
	slices.SortStableFunc(out, latestCapture)
	return out
}

func latestCapture(a, b Capture) int {
	return cmp.Or(b.Time.Compare(a.Time), cmp.Compare(a.UUID, b.UUID))
}

func anyAfter(captures []Capture, t time.Time) bool {
	return slices.ContainsFunc(captures, func(c Capture) bool { return c.Time.After(t) })
}

func lookylooTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(s))
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// readCapture fills cp from its four routes at once, and reports whether
// one of them answered.
func (c *LookylooClient) readCapture(ctx context.Context, cp *Capture) (bool, []error) {
	var info struct {
		URL         string `json:"url"`
		Title       string `json:"title"`
		CaptureTime string `json:"capture_time"`
	}
	var redirects struct {
		Response struct {
			URL       string   `json:"url"`
			Redirects []string `json:"redirects"`
		} `json:"response"`
	}
	var hostnames struct {
		Response struct {
			Hostnames []string `json:"hostnames"`
		} `json:"response"`
	}
	var urls struct {
		Response struct {
			URLs []string `json:"urls"`
		} `json:"response"`
	}
	calls := []struct {
		route string
		v     any
	}{{"info", &info}, {"redirects", &redirects}, {"hostnames", &hostnames}, {"urls", &urls}}
	errs := make([]error, len(calls))
	var wg sync.WaitGroup
	for i, call := range calls {
		wg.Go(func() {
			u := c.BaseURL + "/json/" + url.PathEscape(cp.UUID) + "/" + call.route
			if err := getJSON(ctx, c.HTTP, u, "application/json", maxLookylooBody, call.v); err != nil {
				errs[i] = lookylooError(call.route, err)
			}
		})
	}
	wg.Wait()

	if errs[0] == nil {
		cp.URL, cp.Title = cmp.Or(info.URL, cp.URL), cmp.Or(info.Title, cp.Title)
		if t := lookylooTime(info.CaptureTime); !t.IsZero() {
			cp.Time = t
		}
	}
	cp.Redirects = []string{}
	if errs[1] == nil {
		cp.URL = cmp.Or(cp.URL, redirects.Response.URL)
		cp.Redirects = nonNil(redirects.Response.Redirects)
	}
	cp.FinalURL = cp.URL
	if n := len(cp.Redirects); n > 0 {
		cp.FinalURL = cp.Redirects[n-1]
	}
	cp.Hostnames = []string{}
	if errs[2] == nil {
		cp.Hostnames = normalizeNames(hostnames.Response.Hostnames)
	}
	cp.Trackers = []Tracker{}
	if errs[3] == nil {
		cp.Trackers = Trackers(urls.Response.URLs)
	}
	return slices.Contains(errs, nil), errs
}

// submit captures https://fqdn/ unlisted and waits for it, lookylooWait at
// most. The capture has the uuid of the answer even when the wait failed.
func (c *LookylooClient) submit(ctx context.Context, fqdn string) (Capture, error) {
	target := "https://" + fqdn + "/"
	body, err := postRaw(ctx, c.HTTP, c.BaseURL+lookylooSubmitPath, map[string]any{"url": target, "listing": false}, maxErrBody)
	if err != nil {
		return Capture{}, lookylooError("submit", err)
	}
	id := submittedUUID(body)
	if id == "" {
		return Capture{}, errors.New("lookyloo submit: no capture uuid in the answer")
	}
	cp := Capture{UUID: id, Time: c.now().UTC(), URL: target}
	wait, cancel := context.WithTimeout(ctx, lookylooWait)
	defer cancel()
	return cp, c.wait(wait, id)
}

func (c *LookylooClient) wait(ctx context.Context, id string) error {
	every := cmp.Or(c.PollEvery, lookylooPollEvery)
	for {
		var status json.RawMessage
		err := getJSON(ctx, c.HTTP, c.BaseURL+"/json/"+url.PathEscape(id)+"/status", "application/json", maxErrBody, &status)
		switch {
		case err != nil && ctx.Err() != nil:
			return fmt.Errorf("lookyloo status: capture %s not ready", id)
		case err != nil:
			return lookylooError("status", err)
		case captureDone(status):
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("lookyloo status: capture %s not ready", id)
		case <-time.After(every):
		}
	}
}

// submittedUUID reads a uuid as a JSON string, an object or plain text.
func submittedUUID(body []byte) string {
	body = bytes.TrimSpace(body)
	var s string
	if json.Unmarshal(body, &s) == nil {
		return validUUID(s)
	}
	var obj map[string]any
	if json.Unmarshal(body, &obj) == nil {
		for _, k := range lookylooUUIDKeys {
			if s, ok := obj[k].(string); ok && validUUID(s) != "" {
				return validUUID(s)
			}
		}
		return ""
	}
	return validUUID(string(body))
}

func validUUID(s string) string {
	if s = strings.TrimSpace(s); reUUID.MatchString(s) {
		return s
	}
	return ""
}

// captureDone reads a status as a number, a string or an object holding
// one of them.
func captureDone(raw json.RawMessage) bool {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) == nil {
		for _, k := range lookylooStatusKeys {
			if v, ok := obj[k]; ok {
				return statusDone(v)
			}
		}
		return false
	}
	return statusDone(raw)
}

func statusDone(v json.RawMessage) bool {
	var n int
	if json.Unmarshal(v, &n) == nil {
		return n == lookylooStatusDone
	}
	var s string
	return json.Unmarshal(v, &s) == nil && slices.Contains(lookylooDoneStatus, strings.ToLower(strings.TrimSpace(s)))
}

// finish orders the captures and gathers the trackers and hosts of those
// that visit fqdn.
func (l *Lookyloo) finish(fqdn string) {
	if l.Captures == nil {
		l.Captures = []Capture{}
	}
	slices.SortStableFunc(l.Captures, latestCapture)
	l.CapturesRead = len(l.Captures)
	trackers := map[Tracker]*TrackerSeen{}
	hosts := map[string]*CaptureHost{}
	for _, c := range l.Captures {
		if !c.Visits(fqdn) {
			continue
		}
		for _, t := range c.Trackers {
			s := trackers[t]
			if s == nil {
				s = &TrackerSeen{Kind: t.Kind, ID: t.ID}
				trackers[t] = s
			}
			s.Captures++
			s.FirstSeen, s.LastSeen = widen(s.FirstSeen, s.LastSeen, c.Time)
		}
		for _, n := range c.Hostnames {
			h := hosts[n]
			if h == nil {
				h = &CaptureHost{Name: n}
				hosts[n] = h
			}
			h.FirstSeen, h.LastSeen = widen(h.FirstSeen, h.LastSeen, c.Time)
		}
	}
	l.Trackers = []TrackerSeen{}
	for _, t := range slices.SortedFunc(maps.Keys(trackers), compareTracker) {
		l.Trackers = append(l.Trackers, *trackers[t])
	}
	l.Hosts = []CaptureHost{}
	for _, n := range slices.Sorted(maps.Keys(hosts)) {
		l.Hosts = append(l.Hosts, *hosts[n])
	}
}

func widen(first, last, t time.Time) (time.Time, time.Time) {
	if t.IsZero() {
		return first, last
	}
	if first.IsZero() || t.Before(first) {
		first = t
	}
	if t.After(last) {
		last = t
	}
	return first, last
}

func lookylooError(route string, err error) error {
	var se *statusError
	var ue *url.Error
	switch {
	case errors.As(err, &se) && se.Code == http.StatusTooManyRequests:
		msg := "lookyloo " + route + ": rate limited"
		if se.RetryAfter != "" {
			msg += ", retry after " + se.RetryAfter
		}
		return errors.New(msg)
	case errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ue) && ue.Timeout():
		return fmt.Errorf("lookyloo %s: timed out", route)
	case errors.As(err, &ue):
		return fmt.Errorf("lookyloo %s: %w", route, ue.Err)
	}
	return fmt.Errorf("lookyloo %s: %w", route, err)
}

// errorSet joins distinct messages, sorted.
type errorSet map[string]bool

func (s errorSet) add(errs ...error) {
	for _, err := range errs {
		if err != nil {
			s[err.Error()] = true
		}
	}
}

func (s errorSet) err() error {
	if len(s) == 0 {
		return nil
	}
	return errors.New(strings.Join(slices.Sorted(maps.Keys(s)), "; "))
}
