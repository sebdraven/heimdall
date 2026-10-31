package ch

import (
	"context"
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
	in := func(n int) string { return strings.TrimSuffix(strings.Repeat("?, ", n), ", ") }
	args := make([]any, 0, len(values)+len(exclude))
	for _, v := range values {
		args = append(args, v)
	}
	where := `rdata IN (` + in(len(values)) + `)`
	if len(exclude) > 0 {
		where += ` AND rrname NOT IN (` + in(len(exclude)) + `)`
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

// Pivots returns the other owner names that shared an A, AAAA or NS value
// with fqdn, with each side's observation period and their overlap, if any.
// pdns is keyed by RR owner, so a CNAME'd name has no A/AAAA of its own.
func (s *Store) Pivots(ctx context.Context, fqdn string, limit int) ([]Pivot, error) {
	type rk struct{ rrtype, rdata string }
	target := map[rk]Period{}
	rows, err := s.conn.Query(ctx, `
		SELECT rrtype, rdata, min(first_seen), max(last_seen)
		FROM pdns
		WHERE rrname = ? AND rrtype IN ('A', 'AAAA', 'NS')
		GROUP BY rrtype, rdata`, fqdn)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var k rk
		var p Period
		if err := rows.Scan(&k.rrtype, &k.rdata, &p.First, &p.Last); err != nil {
			rows.Close()
			return nil, err
		}
		target[k] = p
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(target) == 0 {
		return nil, nil
	}

	rows, err = s.conn.Query(ctx, `
		SELECT rrname, rrtype, rdata, min(first_seen), max(last_seen)
		FROM pdns
		WHERE rrtype IN ('A', 'AAAA', 'NS') AND rrname != ?
		  AND (rrtype, rdata) IN (
		      SELECT rrtype, rdata FROM pdns WHERE rrname = ? AND rrtype IN ('A', 'AAAA', 'NS'))
		GROUP BY rrname, rrtype, rdata
		ORDER BY rrname, rrtype, rdata
		LIMIT ?`, fqdn, fqdn, limit)
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
		p.Target = target[rk{p.RRType, p.RData}]
		first, last := later(p.Target.First, p.Other.First), earlier(p.Target.Last, p.Other.Last)
		if !first.After(last) {
			p.Overlap = &Period{First: first, Last: last}
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

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
