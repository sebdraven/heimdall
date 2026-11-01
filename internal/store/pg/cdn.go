package pg

import (
	"context"
	"net/netip"
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
