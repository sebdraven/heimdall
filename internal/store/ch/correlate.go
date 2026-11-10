package ch

import (
	"cmp"
	"context"
	"slices"
	"strings"

	"github.com/sebdraven/heimdall/internal/resolver"
)

// maxNames bounds the names of one IN list, well under max_query_size.
const maxNames = 500

// Owned is a value an owner name held in passive DNS.
type Owned struct {
	RRName string
	RRType string
	RData  string
	Period Period
}

// OwnedRecords returns the values of rrtypes owned by names, querying them
// maxNames at a time.
func (s *Store) OwnedRecords(ctx context.Context, names, rrtypes []string) ([]Owned, error) {
	var out []Owned
	if len(rrtypes) == 0 {
		return nil, nil
	}
	for chunk := range slices.Chunk(names, maxNames) {
		rows, err := s.conn.Query(ctx, `
			SELECT rrname, rrtype, rdata, min(first_seen) AS fs, max(last_seen) AS ls
			FROM pdns
			WHERE rrname IN (`+placeholders(len(chunk))+`) AND rrtype IN (`+placeholders(len(rrtypes))+`)
			GROUP BY rrname, rrtype, rdata
			ORDER BY rrname, rrtype, rdata`, append(strArgs(chunk), strArgs(rrtypes)...)...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var o Owned
			if err := rows.Scan(&o.RRName, &o.RRType, &o.RData, &o.Period.First, &o.Period.Last); err != nil {
				rows.Close()
				return nil, err
			}
			out = append(out, o)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// SOA is the current SOA of a zone: its primary nameserver MName and the
// mailbox RName, over the period they were seen with any serial.
type SOA struct {
	Zone   string
	MName  string
	RName  string
	Period Period
}

type soaRecord struct {
	rrname, rdata string
	period        Period
}

// ZoneSOAs returns, keyed by domain, the SOA last seen in the last 7 days of
// the nearest zone owning one, the domain or an ancestor below the TLD.
// Domains without one are absent.
func (s *Store) ZoneSOAs(ctx context.Context, domains []string) (map[string]*SOA, error) {
	out := map[string]*SOA{}
	var names []string
	for _, d := range domains {
		names = append(names, zoneCandidates(d)...)
	}
	names = slices.Compact(slices.Sorted(slices.Values(names)))
	byName := map[string][]soaRecord{}
	for chunk := range slices.Chunk(names, maxNames) {
		rows, err := s.conn.Query(ctx, `
			SELECT rrname, rdata, min(first_seen), max(last_seen)
			FROM pdns
			WHERE rrtype = 'SOA' AND rrname IN (`+placeholders(len(chunk))+`)
			GROUP BY rrname, rdata
			HAVING `+nsCurrent, strArgs(chunk)...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var r soaRecord
			if err := rows.Scan(&r.rrname, &r.rdata, &r.period.First, &r.period.Last); err != nil {
				rows.Close()
				return nil, err
			}
			byName[r.rrname] = append(byName[r.rrname], r)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	for _, d := range domains {
		for _, name := range zoneCandidates(d) {
			if z := currentSOA(name, byName[name]); z != nil {
				out[d] = z
				break
			}
		}
	}
	return out, nil
}

// currentSOA reads the mname and rname of the latest record of zone, the
// period spanning its records with the same pair.
func currentSOA(zone string, recs []soaRecord) *SOA {
	var z *SOA
	slices.SortFunc(recs, func(a, b soaRecord) int {
		return cmp.Or(b.period.Last.Compare(a.period.Last), cmp.Compare(a.rdata, b.rdata))
	})
	for _, r := range recs {
		f := strings.Fields(r.rdata)
		if len(f) < 2 {
			continue
		}
		m, rn := resolver.Name(f[0]), resolver.Name(f[1])
		switch {
		case z == nil:
			z = &SOA{Zone: zone, MName: m, RName: rn, Period: r.period}
		case z.MName == m && z.RName == rn:
			z.Period = Period{First: earlier(z.Period.First, r.period.First), Last: later(z.Period.Last, r.period.Last)}
		}
	}
	return z
}
