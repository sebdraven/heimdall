package pg

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

const vtToday = `(now() AT TIME ZONE 'UTC')::date`

// ReserveVTLookup counts one lookup for the current UTC day unless budget
// lookups are already counted, and reports whether it did.
func (s *Store) ReserveVTLookup(ctx context.Context, budget int) (bool, error) {
	var n int
	err := s.pool.QueryRow(ctx, `
		INSERT INTO vt_usage AS u (day, lookups) VALUES (`+vtToday+`, 1)
		ON CONFLICT (day) DO UPDATE SET lookups = u.lookups + 1 WHERE u.lookups < $1
		RETURNING lookups`, budget).Scan(&n)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, mapErr(err)
}

func (s *Store) VTUsageToday(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx,
		`SELECT coalesce((SELECT lookups FROM vt_usage WHERE day = `+vtToday+`), 0)`).Scan(&n)
	return n, mapErr(err)
}

// FreshVTObjects returns the objects fetched without error since since.
func (s *Store) FreshVTObjects(ctx context.Context, objects []string, since time.Time) (map[string]bool, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT object FROM vt_fetches
		WHERE object = ANY($1) AND fetched_at >= $2 AND status <> 'error'`, objects, since)
	got, err := collect(rows, err, func(r pgx.Row) (string, error) {
		var o string
		err := r.Scan(&o)
		return o, err
	})
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(got))
	for _, o := range got {
		out[o] = true
	}
	return out, nil
}

func (s *Store) RecordVTFetch(ctx context.Context, object, status string, count int) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO vt_fetches (object, fetched_at, status, count) VALUES ($1, now(), $2, $3)
		ON CONFLICT (object) DO UPDATE SET fetched_at = excluded.fetched_at, status = excluded.status, count = excluded.count`,
		object, status, count)
	return mapErr(err)
}
