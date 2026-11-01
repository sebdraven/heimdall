package ch

import (
	"context"
	"slices"
	"strings"
	"time"

	gjallarhorn "github.com/sebdraven/heimdall/internal/changes"
)

// Aliases never reuse a column name: ClickHouse resolves aliases before
// columns, which turns min(first_seen) AS first_seen into a cycle.

// LoadStates returns the latest persisted state of every tuple.
func (s *Store) LoadStates(ctx context.Context) ([]TupleState, error) {
	rows, err := s.conn.Query(ctx, `
		SELECT domain, qtype, resolver, ts, rcode, tracked, missing, hash, ttl, ceiling, settled, win_start, win_max, win_n
		FROM tuple_state FINAL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TupleState
	for rows.Next() {
		var t TupleState
		var settled uint8
		st := &t.State
		if err := rows.Scan(&t.Key.Domain, &t.Key.QType, &t.Key.Resolver, &st.TS, &st.Rcode, &st.Tracked, &st.Missing,
			&st.Hash, &st.TTL, &st.Ceiling, &settled, &st.WinStart, &st.WinMax, &st.WinN); err != nil {
			return nil, err
		}
		st.Settled = settled != 0
		out = append(out, t)
	}
	return out, rows.Err()
}

type PDNSRecord struct {
	RRName    string
	RRType    string
	RData     string
	FirstSeen time.Time
	LastSeen  time.Time
	Count     uint64
}

func (s *Store) PDNSByName(ctx context.Context, rrname string, limit int) ([]PDNSRecord, error) {
	return s.pdns(ctx, `rrname = ?`, rrname, limit)
}

func (s *Store) PDNSByRdata(ctx context.Context, rdata string, limit int) ([]PDNSRecord, error) {
	return s.pdns(ctx, `rdata = ?`, rdata, limit)
}

func (s *Store) pdns(ctx context.Context, where string, arg any, limit int) ([]PDNSRecord, error) {
	rows, err := s.conn.Query(ctx, `
		SELECT rrname, rrtype, rdata, min(first_seen) AS fs, max(last_seen) AS ls, sum(count) AS n
		FROM pdns
		WHERE `+where+`
		GROUP BY rrname, rrtype, rdata
		ORDER BY ls DESC, rrname, rrtype, rdata
		LIMIT ?`, arg, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PDNSRecord
	for rows.Next() {
		var r PDNSRecord
		if err := rows.Scan(&r.RRName, &r.RRType, &r.RData, &r.FirstSeen, &r.LastSeen, &r.Count); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// NameMatch aggregates the pdns records of one owner name.
type NameMatch struct {
	RRName    string
	RRTypes   []string
	FirstSeen time.Time
	LastSeen  time.Time
	Count     uint64
}

// SearchNames returns the owner names matching the ILIKE pattern, most
// recently seen first.
func (s *Store) SearchNames(ctx context.Context, pattern string, limit int) ([]NameMatch, error) {
	rows, err := s.conn.Query(ctx, `
		SELECT rrname, arraySort(groupUniqArray(rrtype)) AS types, min(first_seen) AS fs, max(last_seen) AS ls, sum(count) AS n
		FROM pdns
		WHERE rrname ILIKE ?
		GROUP BY rrname
		ORDER BY ls DESC, rrname
		LIMIT ?`, pattern, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NameMatch
	for rows.Next() {
		var m NameMatch
		if err := rows.Scan(&m.RRName, &m.RRTypes, &m.FirstSeen, &m.LastSeen, &m.Count); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ValueMatch aggregates the pdns records holding one value.
type ValueMatch struct {
	RData     string
	RRType    string
	Names     uint64
	FirstSeen time.Time
	LastSeen  time.Time
}

// SearchValues returns the (rdata, rrtype) pairs whose rdata matches the
// ILIKE pattern, most recently seen first.
func (s *Store) SearchValues(ctx context.Context, pattern string, limit int) ([]ValueMatch, error) {
	rows, err := s.conn.Query(ctx, `
		SELECT rdata, rrtype, uniqExact(rrname) AS names, min(first_seen) AS fs, max(last_seen) AS ls
		FROM pdns
		WHERE rdata ILIKE ?
		GROUP BY rdata, rrtype
		ORDER BY ls DESC, rdata, rrtype
		LIMIT ?`, pattern, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ValueMatch
	for rows.Next() {
		var m ValueMatch
		if err := rows.Scan(&m.RData, &m.RRType, &m.Names, &m.FirstSeen, &m.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// RdataSharing counts, for each value, the distinct pdns owner names that
// held it, ignoring the names in exclude. Values held by no counted name are
// absent.
func (s *Store) RdataSharing(ctx context.Context, values, exclude []string) (map[string]uint64, error) {
	out := make(map[string]uint64, len(values))
	if len(values) == 0 {
		return out, nil
	}
	args := make([]any, 0, len(values)+len(exclude))
	for _, v := range values {
		args = append(args, v)
	}
	where := `rdata IN (` + placeholders(len(values)) + `)`
	if len(exclude) > 0 {
		where += ` AND rrname NOT IN (` + placeholders(len(exclude)) + `)`
		for _, v := range exclude {
			args = append(args, v)
		}
	}
	rows, err := s.conn.Query(ctx, `
		SELECT rdata, uniqExact(rrname) AS names
		FROM pdns
		WHERE `+where+`
		GROUP BY rdata`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var v string
		var n uint64
		if err := rows.Scan(&v, &n); err != nil {
			return nil, err
		}
		out[v] = n
	}
	return out, rows.Err()
}

type Current struct {
	QType    string
	Resolver string
	TS       time.Time
	Rcode    string
	TTL      uint32
	Rdata    []string
}

func (s *Store) CurrentState(ctx context.Context, domain string) ([]Current, error) {
	rows, err := s.conn.Query(ctx, `
		SELECT qtype, resolver, max(ts), argMax(rcode, ts), argMax(ttl, ts), argMax(rdata, ts)
		FROM observations
		WHERE domain = ? AND ts > now() - INTERVAL 7 DAY
		GROUP BY qtype, resolver
		ORDER BY qtype, resolver`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Current
	for rows.Next() {
		var c Current
		if err := rows.Scan(&c.QType, &c.Resolver, &c.TS, &c.Rcode, &c.TTL, &c.Rdata); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) DomainChanges(ctx context.Context, domain string, limit int) ([]gjallarhorn.Change, error) {
	rows, err := s.conn.Query(ctx, `
		SELECT ts, domain, qtype, resolver, prev_tracked_hash, new_tracked_hash, prev_rcode, new_rcode, added, removed, prev_ttl, new_ttl
		FROM changes
		WHERE domain = ?
		ORDER BY ts DESC
		LIMIT ?`, domain, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []gjallarhorn.Change
	for rows.Next() {
		var c gjallarhorn.Change
		if err := rows.Scan(&c.TS, &c.Domain, &c.QType, &c.Resolver, &c.PrevTrackedHash, &c.NewTrackedHash, &c.PrevRcode, &c.NewRcode,
			&c.Added, &c.Removed, &c.PrevTTL, &c.NewTTL); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

type EventFilter struct {
	Since    time.Time
	Until    time.Time
	Kind     string
	Campaign string
	Domain   string
	Limit    int
}

func (s *Store) Events(ctx context.Context, f EventFilter) ([]gjallarhorn.Event, error) {
	where := []string{"ts >= ?"}
	args := []any{f.Since}
	if !f.Until.IsZero() {
		where, args = append(where, "ts < ?"), append(args, f.Until)
	}
	if f.Kind != "" {
		where, args = append(where, "kind = ?"), append(args, f.Kind)
	}
	if f.Campaign != "" {
		where, args = append(where, "campaign = ?"), append(args, f.Campaign)
	}
	if f.Domain != "" {
		where, args = append(where, "domain = ?"), append(args, f.Domain)
	}
	args = append(args, f.Limit)
	rows, err := s.conn.Query(ctx, `
		SELECT ts, domain, campaign, kind, qtype, resolver, detail
		FROM events
		WHERE `+strings.Join(where, " AND ")+`
		ORDER BY ts DESC
		LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []gjallarhorn.Event
	for rows.Next() {
		var e gjallarhorn.Event
		if err := rows.Scan(&e.TS, &e.Domain, &e.Campaign, &e.Kind, &e.QType, &e.Resolver, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

type Period struct {
	First time.Time
	Last  time.Time
}

type Pivot struct {
	Domain  string
	RRType  string
	RData   string
	Target  Period
	Other   Period
	Overlap *Period
}

// PivotValue is an A or AAAA value owned by a name, with the period it was
// seen.
type PivotValue struct {
	RRType string
	RData  string
	Period Period
}

// PivotValues returns the A and AAAA values owned by fqdn. NS values pivot by
// whole set, see NSPairPivots.
// pdns is keyed by RR owner, so a CNAME'd name has no A/AAAA of its own.
func (s *Store) PivotValues(ctx context.Context, fqdn string) ([]PivotValue, error) {
	rows, err := s.conn.Query(ctx, `
		SELECT rrtype, rdata, min(first_seen), max(last_seen)
		FROM pdns
		WHERE rrname = ? AND rrtype IN ('A', 'AAAA')
		GROUP BY rrtype, rdata
		ORDER BY rrtype, rdata`, fqdn)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PivotValue
	for rows.Next() {
		var v PivotValue
		if err := rows.Scan(&v.RRType, &v.RData, &v.Period.First, &v.Period.Last); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// Pivots returns the other owner names that held one of values, with each
// side's observation period and their overlap, if any.
func (s *Store) Pivots(ctx context.Context, fqdn string, values []PivotValue, limit int) ([]Pivot, error) {
	if len(values) == 0 {
		return nil, nil
	}
	type rk struct{ rrtype, rdata string }
	target := make(map[rk]Period, len(values))
	args := []any{fqdn}
	for _, v := range values {
		target[rk{v.RRType, v.RData}] = v.Period
		args = append(args, v.RData)
	}
	args = append(args, limit)
	// rdata alone selects the rows: an A and an AAAA value never share a spelling.
	rows, err := s.conn.Query(ctx, `
		SELECT rrname, rrtype, rdata, min(first_seen), max(last_seen)
		FROM pdns
		WHERE rrtype IN ('A', 'AAAA') AND rrname != ? AND rdata IN (`+placeholders(len(values))+`)
		GROUP BY rrname, rrtype, rdata
		ORDER BY rrname, rrtype, rdata
		LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Pivot
	for rows.Next() {
		var p Pivot
		if err := rows.Scan(&p.Domain, &p.RRType, &p.RData, &p.Other.First, &p.Other.Last); err != nil {
			return nil, err
		}
		var ok bool
		if p.Target, ok = target[rk{p.RRType, p.RData}]; !ok {
			continue
		}
		first, last := later(p.Target.First, p.Other.First), earlier(p.Target.Last, p.Other.Last)
		if !first.After(last) {
			p.Overlap = &Period{First: first, Last: last}
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// MinNSSet is the smallest NS set worth pivoting on: a single nameserver is
// shared by every zone of its provider.
const MinNSSet = 2

// nsCurrent keeps the NS records seen in the last 7 days.
const nsCurrent = `max(last_seen) >= now64(3) - INTERVAL 7 DAY`

// NSSet is the current NS set of a zone, sorted, and the period it covers.
type NSSet struct {
	Zone   string
	NS     []string
	Period Period
}

type nsRecord struct {
	rrname, rdata string
	period        Period
}

// NSSet returns the current NS set of fqdn or, if it owns none, of its
// nearest ancestor below the TLD that does. It returns nil if none does.
func (s *Store) NSSet(ctx context.Context, fqdn string) (*NSSet, error) {
	names := zoneCandidates(fqdn)
	if len(names) == 0 {
		return nil, nil
	}
	args := make([]any, 0, len(names))
	for _, n := range names {
		args = append(args, n)
	}
	rows, err := s.conn.Query(ctx, `
		SELECT rrname, rdata, min(first_seen), max(last_seen)
		FROM pdns
		WHERE rrtype = 'NS' AND rrname IN (`+placeholders(len(names))+`)
		GROUP BY rrname, rdata
		HAVING `+nsCurrent, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var recs []nsRecord
	for rows.Next() {
		var r nsRecord
		if err := rows.Scan(&r.rrname, &r.rdata, &r.period.First, &r.period.Last); err != nil {
			return nil, err
		}
		recs = append(recs, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return pickZone(names, recs), nil
}

// zoneCandidates lists fqdn and its ancestors, nearest first, down to the
// last one that still has a dot.
func zoneCandidates(fqdn string) []string {
	var out []string
	for name := fqdn; strings.Contains(name, "."); _, name, _ = strings.Cut(name, ".") {
		out = append(out, name)
	}
	return out
}

// pickZone returns the first of names owning NS records, with its sorted set.
func pickZone(names []string, recs []nsRecord) *NSSet {
	for _, name := range names {
		var z *NSSet
		for _, r := range recs {
			if r.rrname != name {
				continue
			}
			if z == nil {
				z = &NSSet{Zone: name, Period: r.period}
			}
			z.NS = append(z.NS, r.rdata)
			z.Period = Period{First: earlier(z.Period.First, r.period.First), Last: later(z.Period.Last, r.period.Last)}
		}
		if z != nil {
			slices.Sort(z.NS)
			z.NS = slices.Compact(z.NS)
			return z
		}
	}
	return nil
}

// NSPairPivot is another name whose current NS set equals the zone's.
type NSPairPivot struct {
	Domain  string
	Target  Period
	Other   Period
	Overlap *Period
}

// NSPairPivots returns the other owner names whose current NS set is exactly
// set, the NS set of zone. It returns nil for a set below MinNSSet.
func (s *Store) NSPairPivots(ctx context.Context, zone string, set []string, limit int) ([]NSPairPivot, error) {
	set = slices.Compact(slices.Sorted(slices.Values(set)))
	if len(set) < MinNSSet {
		return nil, nil
	}
	args := make([]any, 0, len(set)+1)
	for _, ns := range set {
		args = append(args, ns)
	}
	args = append(args, len(set))
	// The subquery keeps the names holding every NS of set at some point; the
	// equality of current sets is checked in Go.
	rows, err := s.conn.Query(ctx, `
		SELECT rrname, groupArray(rdata) AS ns, min(f) AS fs, max(l) AS ls
		FROM (
			SELECT rrname, rdata, min(first_seen) AS f, max(last_seen) AS l
			FROM pdns
			WHERE rrtype = 'NS' AND rrname IN (
				SELECT rrname FROM pdns
				WHERE rrtype = 'NS' AND rdata IN (`+placeholders(len(set))+`)
				GROUP BY rrname
				HAVING uniqExact(rdata) = ?)
			GROUP BY rrname, rdata
			HAVING `+nsCurrent+`)
		GROUP BY rrname
		ORDER BY rrname`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sets []NSSet
	for rows.Next() {
		var z NSSet
		if err := rows.Scan(&z.Zone, &z.NS, &z.Period.First, &z.Period.Last); err != nil {
			return nil, err
		}
		sets = append(sets, z)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return matchNSSet(zone, set, sets, limit), nil
}

// matchNSSet keeps the sets other than zone's that equal set, which must be
// sorted. The target period is that of zone's own row.
func matchNSSet(zone string, set []string, sets []NSSet, limit int) []NSPairPivot {
	var target Period
	for _, z := range sets {
		if z.Zone == zone {
			target = z.Period
		}
	}
	var out []NSPairPivot
	for _, z := range sets {
		if z.Zone == zone || !slices.Equal(slices.Sorted(slices.Values(z.NS)), set) {
			continue
		}
		if limit > 0 && len(out) == limit {
			break
		}
		p := NSPairPivot{Domain: z.Zone, Target: target, Other: z.Period}
		first, last := later(p.Target.First, p.Other.First), earlier(p.Target.Last, p.Other.Last)
		if !first.After(last) {
			p.Overlap = &Period{First: first, Last: last}
		}
		out = append(out, p)
	}
	return out
}

func placeholders(n int) string { return strings.TrimSuffix(strings.Repeat("?, ", n), ", ") }

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
