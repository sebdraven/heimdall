package ch

import (
	"context"
	"strings"
	"time"

	"github.com/sebdraven/heimdall/internal/vt"
)

func (s *Store) InsertVTResolutions(ctx context.Context, rs []vt.Resolution, fetchedAt time.Time) error {
	if len(rs) == 0 {
		return nil
	}
	b, err := s.conn.PrepareBatch(ctx, `INSERT INTO vt_resolutions (host_name, ip, date, fetched_at)`)
	if err != nil {
		return err
	}
	for _, r := range rs {
		if err := b.Append(r.HostName, r.IP, r.Date, fetchedAt); err != nil {
			_ = b.Abort()
			return err
		}
	}
	return b.Send()
}

// VTPair is a name and an address VirusTotal saw together, with the dates
// of the first and last resolution.
type VTPair struct {
	HostName string
	IP       string
	Period   Period
}

// VTPairs returns the cached VirusTotal pairs whose name is in hosts or
// whose address is in ips.
func (s *Store) VTPairs(ctx context.Context, hosts, ips []string, limit int) ([]VTPair, error) {
	var where []string
	var args []any
	if len(hosts) > 0 {
		where = append(where, `host_name IN (`+placeholders(len(hosts))+`)`)
		for _, h := range hosts {
			args = append(args, h)
		}
	}
	if len(ips) > 0 {
		where = append(where, `ip IN (`+placeholders(len(ips))+`)`)
		for _, ip := range ips {
			args = append(args, ip)
		}
	}
	if len(where) == 0 {
		return nil, nil
	}
	args = append(args, limit)
	rows, err := s.conn.Query(ctx, `
		SELECT host_name, ip, min(date) AS fs, max(date) AS ls
		FROM vt_resolutions
		WHERE `+strings.Join(where, " OR ")+`
		GROUP BY host_name, ip
		ORDER BY host_name, ip
		LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VTPair
	for rows.Next() {
		var p VTPair
		if err := rows.Scan(&p.HostName, &p.IP, &p.Period.First, &p.Period.Last); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
