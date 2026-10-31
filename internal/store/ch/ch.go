package ch

import (
	"context"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	gjallarhorn "github.com/sebdraven/heimdall/internal/changes"
	"github.com/sebdraven/heimdall/internal/resolver"
)

type Options struct {
	Addr     string
	Database string
	User     string
	Password string
}

type Store struct {
	conn driver.Conn
}

func Open(ctx context.Context, o Options) (*Store, error) {
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr:        []string{o.Addr},
		Auth:        clickhouse.Auth{Database: o.Database, Username: o.User, Password: o.Password},
		DialTimeout: 5 * time.Second,
		Compression: &clickhouse.Compression{Method: clickhouse.CompressionLZ4},
	})
	if err != nil {
		return nil, err
	}
	if err := conn.Ping(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return &Store{conn: conn}, nil
}

func (s *Store) Close() error { return s.conn.Close() }

func (s *Store) Ping(ctx context.Context) error { return s.conn.Ping(ctx) }

func (s *Store) InsertObservations(ctx context.Context, obs []resolver.Observation) error {
	b, err := s.conn.PrepareBatch(ctx, `INSERT INTO observations
		(ts, domain, qtype, resolver, rcode, ttl, rdata, answers, answer_hash, latency_ms, truncated, wire, authority)`)
	if err != nil {
		return err
	}
	for _, o := range obs {
		if err := b.Append(o.TS, o.Domain, o.QType, o.Resolver, o.Rcode, o.TTL, nonNil(o.Rdata), tuples(o.Answers),
			o.AnswerHash, o.LatencyMs, boolUInt8(o.Truncated), string(o.Wire), tuples(o.Authority)); err != nil {
			_ = b.Abort()
			return err
		}
	}
	return b.Send()
}

func (s *Store) InsertStates(ctx context.Context, states []TupleState) error {
	b, err := s.conn.PrepareBatch(ctx, `INSERT INTO tuple_state
		(ts, domain, qtype, resolver, rcode, tracked, missing, hash, ttl, ceiling, settled, win_start, win_max, win_n)`)
	if err != nil {
		return err
	}
	for _, t := range states {
		st := t.State
		missing := st.Missing
		if missing == nil {
			missing = []uint32{}
		}
		if err := b.Append(st.TS, t.Key.Domain, t.Key.QType, t.Key.Resolver, st.Rcode, nonNil(st.Tracked), missing,
			st.Hash, st.TTL, st.Ceiling, boolUInt8(st.Settled), st.WinStart, st.WinMax, st.WinN); err != nil {
			_ = b.Abort()
			return err
		}
	}
	return b.Send()
}

func (s *Store) InsertChanges(ctx context.Context, changes []gjallarhorn.Change) error {
	b, err := s.conn.PrepareBatch(ctx, `INSERT INTO changes
		(ts, domain, qtype, resolver, prev_tracked_hash, new_tracked_hash, prev_rcode, new_rcode, added, removed, prev_ttl, new_ttl)`)
	if err != nil {
		return err
	}
	for _, c := range changes {
		if err := b.Append(c.TS, c.Domain, c.QType, c.Resolver, c.PrevTrackedHash, c.NewTrackedHash, c.PrevRcode, c.NewRcode,
			nonNil(c.Added), nonNil(c.Removed), c.PrevTTL, c.NewTTL); err != nil {
			_ = b.Abort()
			return err
		}
	}
	return b.Send()
}

func (s *Store) InsertEvents(ctx context.Context, events []gjallarhorn.Event) error {
	b, err := s.conn.PrepareBatch(ctx, `INSERT INTO events (ts, domain, campaign, kind, qtype, resolver, detail)`)
	if err != nil {
		return err
	}
	for _, e := range events {
		if err := b.Append(e.TS, e.Domain, e.Campaign, e.Kind, e.QType, e.Resolver, e.Detail); err != nil {
			_ = b.Abort()
			return err
		}
	}
	return b.Send()
}

func tuples(rrs []resolver.Answer) []map[string]any {
	out := make([]map[string]any, 0, len(rrs))
	for _, a := range rrs {
		out = append(out, map[string]any{"name": a.Name, "type": a.Type, "value": a.Value})
	}
	return out
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func boolUInt8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}
