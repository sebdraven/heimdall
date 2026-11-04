package vt

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/sebdraven/heimdall/internal/cdn"
	"github.com/sebdraven/heimdall/internal/resolver"
)

// MaxLookups caps the lookups of one Enrich call.
const MaxLookups = 300

const (
	StopDailyBudget = "daily budget reached"
	StopCallCap     = "per-call cap reached"
	StopQuota       = "VirusTotal quota exceeded"
)

const (
	statusOK    = "ok"
	statusEmpty = "empty"
	statusError = "error"
)

type Lookup interface {
	DomainResolutions(ctx context.Context, domain string) ([]Resolution, error)
	IPResolutions(ctx context.Context, ip string) ([]Resolution, error)
}

// Ledger keeps, in Postgres, the lookups of the day and when each object
// was last fetched. Objects are "d:<fqdn>" or "ip:<ip>".
type Ledger interface {
	// ReserveVTLookup counts one lookup for the current UTC day unless budget
	// lookups are already counted, and reports whether it did.
	ReserveVTLookup(ctx context.Context, budget int) (bool, error)
	VTUsageToday(ctx context.Context) (int, error)
	// FreshVTObjects returns the objects fetched without error since since.
	FreshVTObjects(ctx context.Context, objects []string, since time.Time) (map[string]bool, error)
	RecordVTFetch(ctx context.Context, object, status string, count int) error
}

// Sink stores resolutions in ClickHouse.
type Sink interface {
	InsertVTResolutions(ctx context.Context, rs []Resolution, fetchedAt time.Time) error
}

type Enricher struct {
	Lookup Lookup
	Ledger Ledger
	Sink   Sink
	CDN    *cdn.Classifier
	Budget int
	TTL    time.Duration
	Log    *slog.Logger
	Now    func() time.Time
}

type Summary struct {
	LookedUp        int    `json:"looked_up"`
	Cached          int    `json:"cached"`
	SkippedCDN      int    `json:"skipped_cdn"`
	SkippedReserved int    `json:"skipped_reserved"`
	SkippedBudget   int    `json:"skipped_budget"`
	StoppedReason   string `json:"stopped_reason"`
}

// Usage returns the lookups counted today and those left.
func (e *Enricher) Usage(ctx context.Context) (used, remaining int, err error) {
	used, err = e.Ledger.VTUsageToday(ctx)
	if err != nil {
		return 0, 0, err
	}
	return used, max(e.Budget-used, 0), nil
}

// Remaining returns the lookups left today.
func (e *Enricher) Remaining(ctx context.Context) (int, error) {
	_, n, err := e.Usage(ctx)
	return n, err
}

func (e *Enricher) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// Enrich looks up the objects, "d:<fqdn>" or "ip:<ip>", that were not fetched
// within TTL, skipping CDN and non-public addresses, within the daily budget
// and MaxLookups. A budget or quota stop is not an error: the objects left
// count as skipped_budget and StoppedReason says why.
func (e *Enricher) Enrich(ctx context.Context, objects []string) (Summary, error) {
	var sum Summary
	var todo []string
	for _, o := range slices.Compact(slices.Sorted(slices.Values(objects))) {
		if ip, ok := strings.CutPrefix(o, "ip:"); ok {
			a, err := netip.ParseAddr(ip)
			if err != nil || !Public(a) {
				sum.SkippedReserved++
				continue
			}
			if _, ok := e.CDN.Classify(ip); ok {
				sum.SkippedCDN++
				continue
			}
		} else if !strings.HasPrefix(o, "d:") {
			continue
		}
		todo = append(todo, o)
	}
	if len(todo) == 0 {
		return sum, nil
	}
	fresh, err := e.Ledger.FreshVTObjects(ctx, todo, e.now().Add(-e.TTL))
	if err != nil {
		return sum, fmt.Errorf("vt fetches: %w", err)
	}
	for _, o := range todo {
		switch {
		case fresh[o]:
			sum.Cached++
			continue
		case sum.StoppedReason != "":
			sum.SkippedBudget++
			continue
		case sum.LookedUp >= MaxLookups:
			sum.StoppedReason = StopCallCap
			sum.SkippedBudget++
			continue
		}
		ok, err := e.Ledger.ReserveVTLookup(ctx, e.Budget)
		if err != nil {
			return sum, fmt.Errorf("vt usage: %w", err)
		}
		if !ok {
			sum.StoppedReason = StopDailyBudget
			sum.SkippedBudget++
			continue
		}
		sum.LookedUp++
		if err := e.fetch(ctx, o); err != nil {
			if errors.Is(err, ErrQuota) {
				sum.StoppedReason = StopQuota
				continue
			}
			var ae *APIError
			if errors.As(err, &ae) {
				e.Log.Warn("vt lookup", "object", o, "err", err)
				if rerr := e.Ledger.RecordVTFetch(ctx, o, statusError, 0); rerr != nil {
					return sum, fmt.Errorf("vt fetches: %w", rerr)
				}
				sum.StoppedReason = fmt.Sprintf("VirusTotal error %d %s", ae.Status, ae.Code)
				continue
			}
			return sum, err
		}
	}
	return sum, nil
}

func (e *Enricher) fetch(ctx context.Context, object string) error {
	var rs []Resolution
	var err error
	if ip, ok := strings.CutPrefix(object, "ip:"); ok {
		rs, err = e.Lookup.IPResolutions(ctx, ip)
	} else {
		rs, err = e.Lookup.DomainResolutions(ctx, strings.TrimPrefix(object, "d:"))
	}
	if err != nil {
		return err
	}
	rs = normalize(rs)
	if len(rs) > 0 {
		if err := e.Sink.InsertVTResolutions(ctx, rs, e.now()); err != nil {
			return fmt.Errorf("vt resolutions: %w", err)
		}
	}
	status := statusOK
	if len(rs) == 0 {
		status = statusEmpty
	}
	if err := e.Ledger.RecordVTFetch(ctx, object, status, len(rs)); err != nil {
		return fmt.Errorf("vt fetches: %w", err)
	}
	return nil
}

// normalize spells names and addresses as the graph does and drops the
// resolutions whose address does not parse.
func normalize(rs []Resolution) []Resolution {
	out := rs[:0]
	for _, r := range rs {
		a, err := netip.ParseAddr(r.IP)
		if err != nil {
			continue
		}
		r.HostName, r.IP = resolver.Name(r.HostName), a.Unmap().String()
		if r.HostName != "" {
			out = append(out, r)
		}
	}
	return out
}

var reserved = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// Public reports whether a is a global unicast address outside the private,
// shared, documentation and other reserved ranges.
func Public(a netip.Addr) bool {
	a = a.Unmap()
	if a.Zone() != "" || !a.IsGlobalUnicast() || a.IsPrivate() {
		return false
	}
	for _, p := range reserved {
		if p.Contains(a) {
			return false
		}
	}
	return true
}
