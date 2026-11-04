package ch

import (
	"context"
	"slices"
	"time"

	gjallarhorn "github.com/sebdraven/heimdall/internal/changes"
)

// The analytics queries read the domains of one campaign from since on.
// Days are UTC dates, YYYY-MM-DD.

// DayState is the last A or AAAA observation of a domain on a day, answers
// without data aside: Rcode is "" when the day had only those. IPs are the
// addresses answered that day.
type DayState struct {
	Domain string
	Day    string
	Rcode  string
	LastTS time.Time
	IPs    []string
}

// CampaignLiveness returns one DayState per domain and day observed.
func (s *Store) CampaignLiveness(ctx context.Context, domains []string, since time.Time) ([]DayState, error) {
	if len(domains) == 0 {
		return nil, nil
	}
	rows, err := s.conn.Query(ctx, `
		SELECT domain, toString(toDate(ts, 'UTC')) AS day,
			argMaxIf(rcode, ts, NOT (rcode = 'NOERROR' AND empty(rdata))) AS last_rcode,
			max(ts) AS last_ts,
			arraySort(groupUniqArrayArrayIf(rdata, rcode = 'NOERROR')) AS ips
		FROM observations
		WHERE domain IN (`+placeholders(len(domains))+`) AND qtype IN ('A', 'AAAA') AND ts >= ?
		GROUP BY domain, day
		ORDER BY domain, day`, append(strArgs(domains), since)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DayState
	for rows.Next() {
		var d DayState
		if err := rows.Scan(&d.Domain, &d.Day, &d.Rcode, &d.LastTS, &d.IPs); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// KindCount is the number of events of a kind on a day.
type KindCount struct {
	Day  string
	Kind string
	N    uint64
}

func (s *Store) CampaignEventCounts(ctx context.Context, campaign string, domains []string, since time.Time) ([]KindCount, error) {
	where, args := campaignEvents(campaign, domains, since)
	rows, err := s.conn.Query(ctx, `
		SELECT toString(toDate(ts, 'UTC')) AS day, kind, count() AS n
		FROM events
		WHERE `+where+`
		GROUP BY day, kind
		ORDER BY day, kind`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KindCount
	for rows.Next() {
		var c KindCount
		if err := rows.Scan(&c.Day, &c.Kind, &c.N); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CampaignEvents returns the latest events of the campaign, newest first.
func (s *Store) CampaignEvents(ctx context.Context, campaign string, domains []string, since time.Time, limit int) ([]gjallarhorn.Event, error) {
	where, args := campaignEvents(campaign, domains, since)
	rows, err := s.conn.Query(ctx, `
		SELECT ts, domain, campaign, kind, qtype, resolver, detail
		FROM events
		WHERE `+where+`
		ORDER BY ts DESC
		LIMIT ?`, append(args, limit)...)
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

// campaignEvents selects the events tagged with the campaign, zone tuples
// included, or about one of its domains.
func campaignEvents(campaign string, domains []string, since time.Time) (string, []any) {
	where, args := `ts >= ? AND (campaign = ?`, []any{since, campaign}
	if len(domains) > 0 {
		where += ` OR domain IN (` + placeholders(len(domains)) + `)`
		args = append(args, strArgs(domains)...)
	}
	return where + `)`, args
}

// ZoneNSSets returns, keyed by domain, the current NS set of the zone of
// each domain as NSSet finds it. Domains without one are absent.
func (s *Store) ZoneNSSets(ctx context.Context, domains []string) (map[string]*NSSet, error) {
	out := map[string]*NSSet{}
	var names []string
	for _, d := range domains {
		names = append(names, zoneCandidates(d)...)
	}
	names = slices.Compact(slices.Sorted(slices.Values(names)))
	if len(names) == 0 {
		return out, nil
	}
	rows, err := s.conn.Query(ctx, `
		SELECT rrname, rdata, min(first_seen), max(last_seen)
		FROM pdns
		WHERE rrtype = 'NS' AND rrname IN (`+placeholders(len(names))+`)
		GROUP BY rrname, rdata
		HAVING `+nsCurrent, strArgs(names)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byName := map[string][]nsRecord{}
	for rows.Next() {
		var r nsRecord
		if err := rows.Scan(&r.rrname, &r.rdata, &r.period.First, &r.period.Last); err != nil {
			return nil, err
		}
		byName[r.rrname] = append(byName[r.rrname], r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, d := range domains {
		cands := zoneCandidates(d)
		var recs []nsRecord
		for _, c := range cands {
			recs = append(recs, byName[c]...)
		}
		if z := pickZone(cands, recs); z != nil {
			out[d] = z
		}
	}
	return out, nil
}

// FirstSeen returns when each name first owned a pdns record. Names without
// any are absent.
func (s *Store) FirstSeen(ctx context.Context, names []string) (map[string]time.Time, error) {
	out := make(map[string]time.Time, len(names))
	if len(names) == 0 {
		return out, nil
	}
	rows, err := s.conn.Query(ctx, `
		SELECT rrname, min(first_seen) AS fs
		FROM pdns
		WHERE rrname IN (`+placeholders(len(names))+`)
		GROUP BY rrname`, strArgs(names)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var t time.Time
		if err := rows.Scan(&name, &t); err != nil {
			return nil, err
		}
		out[name] = t
	}
	return out, rows.Err()
}

// NewIPs are the addresses first seen on Day.
type NewIPs struct {
	Day string
	IPs []string
}

// NewIPsByDay groups by day those of ips whose first A or AAAA record, under
// any owner, is not older than since.
func (s *Store) NewIPsByDay(ctx context.Context, ips []string, since time.Time) ([]NewIPs, error) {
	if len(ips) == 0 {
		return nil, nil
	}
	rows, err := s.conn.Query(ctx, `
		SELECT toString(toDate(fs, 'UTC')) AS day, arraySort(groupArray(ip)) AS ips
		FROM (
			SELECT rdata AS ip, min(first_seen) AS fs
			FROM pdns
			WHERE rrtype IN ('A', 'AAAA') AND rdata IN (`+placeholders(len(ips))+`)
			GROUP BY ip)
		WHERE fs >= ?
		GROUP BY day
		ORDER BY day`, append(strArgs(ips), since)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NewIPs
	for rows.Next() {
		var n NewIPs
		if err := rows.Scan(&n.Day, &n.IPs); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func strArgs(vs []string) []any {
	out := make([]any, 0, len(vs)+1)
	for _, v := range vs {
		out = append(out, v)
	}
	return out
}
