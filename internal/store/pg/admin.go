package pg

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

type Resolver struct {
	ID      int64
	Address string
	Label   string
	Enabled bool
	QPS     int
}

type NSClass struct {
	ID      int64
	Pattern string
	Kind    string
	Label   string
}

type AuditEntry struct {
	ID       int64
	UserID   *int64
	Username string
	Action   string
	Target   string
	At       time.Time
}

func scanResolver(r pgx.Row) (Resolver, error) {
	var v Resolver
	err := r.Scan(&v.ID, &v.Address, &v.Label, &v.Enabled, &v.QPS)
	return v, mapErr(err)
}

func (s *Store) Resolvers(ctx context.Context) ([]Resolver, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, address, label, enabled, qps FROM resolvers ORDER BY id`)
	return collect(rows, err, scanResolver)
}

func (s *Store) CreateResolver(ctx context.Context, address, label string, qps int) (Resolver, error) {
	return scanResolver(s.pool.QueryRow(ctx,
		`INSERT INTO resolvers (address, label, qps) VALUES ($1, $2, $3) RETURNING id, address, label, enabled, qps`,
		address, label, qps))
}

func (s *Store) ToggleResolver(ctx context.Context, id int64) (Resolver, error) {
	return scanResolver(s.pool.QueryRow(ctx,
		`UPDATE resolvers SET enabled = NOT enabled WHERE id = $1 RETURNING id, address, label, enabled, qps`, id))
}

func (s *Store) DeleteResolver(ctx context.Context, id int64) (Resolver, error) {
	return scanResolver(s.pool.QueryRow(ctx,
		`DELETE FROM resolvers WHERE id = $1 RETURNING id, address, label, enabled, qps`, id))
}

func scanNSClass(r pgx.Row) (NSClass, error) {
	var c NSClass
	err := r.Scan(&c.ID, &c.Pattern, &c.Kind, &c.Label)
	return c, mapErr(err)
}

func (s *Store) NSClasses(ctx context.Context) ([]NSClass, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, pattern, kind, label FROM ns_classes ORDER BY kind, pattern`)
	return collect(rows, err, scanNSClass)
}

func (s *Store) CreateNSClass(ctx context.Context, pattern, kind, label string) (NSClass, error) {
	return scanNSClass(s.pool.QueryRow(ctx,
		`INSERT INTO ns_classes (pattern, kind, label) VALUES ($1, $2, $3) RETURNING id, pattern, kind, label`,
		pattern, kind, label))
}

func (s *Store) DeleteNSClass(ctx context.Context, id int64) (NSClass, error) {
	return scanNSClass(s.pool.QueryRow(ctx,
		`DELETE FROM ns_classes WHERE id = $1 RETURNING id, pattern, kind, label`, id))
}

func (s *Store) Audit(ctx context.Context, userID *int64, action, target string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO audit_log (user_id, action, target) VALUES ($1, $2, $3)`, userID, action, target)
	return mapErr(err)
}

func (s *Store) AuditLog(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT a.id, a.user_id, coalesce(u.username, ''), a.action, a.target, a.at
		FROM audit_log a LEFT JOIN users u ON u.id = a.user_id
		ORDER BY a.at DESC, a.id DESC LIMIT $1`, limit)
	return collect(rows, err, func(r pgx.Row) (AuditEntry, error) {
		var e AuditEntry
		err := r.Scan(&e.ID, &e.UserID, &e.Username, &e.Action, &e.Target, &e.At)
		return e, err
	})
}
