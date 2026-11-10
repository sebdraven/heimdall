package pg

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

type CDNPrefix struct {
	ID        int64
	Prefix    netip.Prefix
	Provider  string
	Source    string
	CreatedAt time.Time
}

const cdnPrefixColumns = `id, prefix, provider, source, created_at`

func scanCDNPrefix(r pgx.Row) (CDNPrefix, error) {
	var p CDNPrefix
	err := r.Scan(&p.ID, &p.Prefix, &p.Provider, &p.Source, &p.CreatedAt)
	return p, mapErr(err)
}

func (s *Store) CDNPrefixes(ctx context.Context) ([]CDNPrefix, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+cdnPrefixColumns+` FROM cdn_prefixes ORDER BY provider, prefix`)
	return collect(rows, err, scanCDNPrefix)
}

func (s *Store) CreateCDNPrefix(ctx context.Context, prefix netip.Prefix, provider, source string) (CDNPrefix, error) {
	return scanCDNPrefix(s.pool.QueryRow(ctx,
		`INSERT INTO cdn_prefixes (prefix, provider, source) VALUES ($1, $2, $3) RETURNING `+cdnPrefixColumns,
		prefix, provider, source))
}

func (s *Store) DeleteCDNPrefix(ctx context.Context, id int64) (CDNPrefix, error) {
	return scanCDNPrefix(s.pool.QueryRow(ctx,
		`DELETE FROM cdn_prefixes WHERE id = $1 RETURNING `+cdnPrefixColumns, id))
}

// ImportCDNPrefixes inserts the prefixes not yet listed and returns how many
// were inserted.
func (s *Store) ImportCDNPrefixes(ctx context.Context, prefixes []netip.Prefix, provider, source string) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO cdn_prefixes (prefix, provider, source)
		SELECT p, $2::text, $3::text FROM unnest($1::cidr[]) AS p
		ON CONFLICT (prefix) DO NOTHING`,
		prefixes, provider, source)
	return tag.RowsAffected(), mapErr(err)
}

// CDNSync counts what a sync of one provider did, or would do. Skipped are
// the listed prefixes held by another source, left as they are.
type CDNSync struct {
	Added     int
	Removed   int
	Unchanged int
	Skipped   int
}

type cdnHeld struct {
	prefix netip.Prefix
	source string
}

// planCDNSync compares want with the rows of source and the rows of other
// sources holding one of want: it adds what no row holds and removes the
// rows of source no longer wanted.
func planCDNSync(source string, want []netip.Prefix, held []cdnHeld) (add, remove []netip.Prefix, res CDNSync) {
	wanted := make(map[netip.Prefix]bool, len(want))
	for _, p := range want {
		wanted[p] = true
	}
	owner := make(map[netip.Prefix]string, len(held))
	for _, h := range held {
		owner[h.prefix] = h.source
		if h.source == source && !wanted[h.prefix] {
			remove = append(remove, h.prefix)
		}
	}
	for p := range wanted {
		switch src, ok := owner[p]; {
		case !ok:
			add = append(add, p)
		case src == source:
			res.Unchanged++
		default:
			res.Skipped++
		}
	}
	slices.SortFunc(add, comparePrefix)
	slices.SortFunc(remove, comparePrefix)
	res.Added, res.Removed = len(add), len(remove)
	return add, remove, res
}

func comparePrefix(a, b netip.Prefix) int {
	return cmp.Or(a.Addr().Compare(b.Addr()), cmp.Compare(a.Bits(), b.Bits()))
}

// SyncCDNPrefixes makes the prefixes of source those of prefixes, in one
// transaction, without touching the rows of any other source. With dryRun it
// only counts.
func (s *Store) SyncCDNPrefixes(ctx context.Context, provider, source string, prefixes []netip.Prefix, dryRun bool) (CDNSync, error) {
	if len(prefixes) == 0 {
		return CDNSync{}, fmt.Errorf("%w: no prefix to sync for %s", ErrInvalid, source)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return CDNSync{}, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	query := `SELECT prefix, source FROM cdn_prefixes WHERE source = $1 OR prefix = ANY($2::cidr[])`
	if !dryRun {
		query += ` FOR UPDATE`
	}
	rows, err := tx.Query(ctx, query, source, prefixes)
	held, err := collect(rows, err, func(r pgx.Row) (cdnHeld, error) {
		var h cdnHeld
		err := r.Scan(&h.prefix, &h.source)
		return h, err
	})
	if err != nil {
		return CDNSync{}, err
	}
	add, remove, res := planCDNSync(source, prefixes, held)
	if dryRun {
		return res, nil
	}
	if len(remove) > 0 {
		if _, err := tx.Exec(ctx, `DELETE FROM cdn_prefixes WHERE source = $1 AND prefix = ANY($2::cidr[])`, source, remove); err != nil {
			return CDNSync{}, mapErr(err)
		}
	}
	if len(add) > 0 {
		tag, err := tx.Exec(ctx, `
			INSERT INTO cdn_prefixes (prefix, provider, source)
			SELECT p, $2::text, $3::text FROM unnest($1::cidr[]) AS p
			ON CONFLICT (prefix) DO NOTHING`,
			add, provider, source)
		if err != nil {
			return CDNSync{}, mapErr(err)
		}
		// A prefix inserted meanwhile by another source is left to it.
		n := int(tag.RowsAffected())
		res.Skipped += res.Added - n
		res.Added = n
	}
	return res, mapErr(tx.Commit(ctx))
}
