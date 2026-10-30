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
		(ts, domain, qtype, resolver, rcode, ttl, rdata, answer_hash, latency_ms, truncated, wire)`)
	if err != nil {
		return err
	}
	for _, o := range obs {
		var truncated uint8
		if o.Truncated {
			truncated = 1
		}
		if err := b.Append(o.TS, o.Domain, o.QType, o.Resolver, o.Rcode, o.TTL, nonNil(o.Rdata),
			o.AnswerHash, o.LatencyMs, truncated, string(o.Wire)); err != nil {
			_ = b.Abort()
			return err
		}
	}
	return b.Send()
}

func (s *Store) InsertChanges(ctx context.Context, changes []gjallarhorn.Change) error {
	b, err := s.conn.PrepareBatch(ctx, `INSERT INTO changes
		(ts, domain, qtype, resolver, prev_hash, new_hash, prev_rcode, new_rcode, added, removed, prev_ttl, new_ttl)`)
	if err != nil {
		return err
	}
	for _, c := range changes {
		if err := b.Append(c.TS, c.Domain, c.QType, c.Resolver, c.PrevHash, c.NewHash, c.PrevRcode, c.NewRcode,
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

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}
