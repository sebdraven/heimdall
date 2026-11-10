package pg

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// CorrelationLink is a link of the history, DomainA < DomainB.
type CorrelationLink struct {
	ID        int64
	Kind      string
	Value     string
	DomainA   string
	CampaignA int64
	DomainB   string
	CampaignB int64
	FirstSeen time.Time
	LastSeen  time.Time
}

const correlationColumns = `id, kind, value, domain_a, campaign_a, domain_b, campaign_b, first_seen, last_seen`

func scanCorrelationLink(r pgx.Row) (CorrelationLink, error) {
	var l CorrelationLink
	err := r.Scan(&l.ID, &l.Kind, &l.Value, &l.DomainA, &l.CampaignA, &l.DomainB, &l.CampaignB, &l.FirstSeen, &l.LastSeen)
	return l, mapErr(err)
}

// upsertChunk bounds the links of one statement.
const upsertChunk = 5000

// UpsertCorrelationLinks records links as seen at, in one transaction: a new
// link gets first_seen = last_seen = at, a known one last_seen = at and its
// current campaigns. It returns the links as stored. The links must be
// unique by (kind, value, domain_a, domain_b).
func (s *Store) UpsertCorrelationLinks(ctx context.Context, links []CorrelationLink, at time.Time) ([]CorrelationLink, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	out := make([]CorrelationLink, 0, len(links))
	for start := 0; start < len(links); start += upsertChunk {
		chunk := links[start:min(start+upsertChunk, len(links))]
		kinds, values, as, bs := make([]string, len(chunk)), make([]string, len(chunk)), make([]string, len(chunk)), make([]string, len(chunk))
		cas, cbs := make([]int64, len(chunk)), make([]int64, len(chunk))
		for i, l := range chunk {
			kinds[i], values[i], as[i], cas[i], bs[i], cbs[i] = l.Kind, l.Value, l.DomainA, l.CampaignA, l.DomainB, l.CampaignB
		}
		rows, err := tx.Query(ctx, `
			INSERT INTO correlation_links AS c (kind, value, domain_a, campaign_a, domain_b, campaign_b, first_seen, last_seen)
			SELECT k, v, da, ca, db, cb, $7, $7
			FROM unnest($1::text[], $2::text[], $3::text[], $4::bigint[], $5::text[], $6::bigint[]) AS t(k, v, da, ca, db, cb)
			ON CONFLICT (kind, value, domain_a, domain_b) DO UPDATE SET
				last_seen = greatest(c.last_seen, excluded.last_seen),
				campaign_a = excluded.campaign_a, campaign_b = excluded.campaign_b
			RETURNING `+correlationColumns,
			kinds, values, as, cas, bs, cbs, at)
		saved, err := collect(rows, err, scanCorrelationLink)
		if err != nil {
			return nil, err
		}
		out = append(out, saved...)
	}
	return out, mapErr(tx.Commit(ctx))
}

// CorrelationFilter selects links first seen at or after Since when set, of
// Kinds when set, between campaigns CampaignA and CampaignB in either order
// when both are set.
type CorrelationFilter struct {
	Since     time.Time
	Kinds     []string
	CampaignA int64
	CampaignB int64
	Limit     int
}

// CorrelationLinks returns the links of f, latest first seen first.
func (s *Store) CorrelationLinks(ctx context.Context, f CorrelationFilter) ([]CorrelationLink, error) {
	var where []string
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	if !f.Since.IsZero() {
		where = append(where, "first_seen >= "+arg(f.Since))
	}
	if len(f.Kinds) > 0 {
		where = append(where, "kind = ANY("+arg(f.Kinds)+"::text[])")
	}
	if f.CampaignA != 0 && f.CampaignB != 0 {
		a, b := arg(f.CampaignA), arg(f.CampaignB)
		where = append(where, "((campaign_a = "+a+" AND campaign_b = "+b+") OR (campaign_a = "+b+" AND campaign_b = "+a+"))")
	}
	query := `SELECT ` + correlationColumns + ` FROM correlation_links`
	if len(where) > 0 {
		query += ` WHERE ` + strings.Join(where, " AND ")
	}
	query += ` ORDER BY first_seen DESC, id DESC`
	if f.Limit > 0 {
		query += ` LIMIT ` + arg(f.Limit)
	}
	rows, err := s.pool.Query(ctx, query, args...)
	return collect(rows, err, scanCorrelationLink)
}

// EnrichCert is a certificate of the stored enrichment of a watched domain.
type EnrichCert struct {
	FQDN      string
	SHA256    string
	NotBefore *time.Time
	NotAfter  *time.Time
}

// EnrichCerts returns the certificates with a SHA-256 of the stored
// enrichments of watched domains.
func (s *Store) EnrichCerts(ctx context.Context) ([]EnrichCert, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT e.fqdn, lower(c->>'cert_sha256'), (c->>'not_before')::timestamptz, (c->>'not_after')::timestamptz
		FROM domain_enrich e
		JOIN domains d ON d.fqdn = e.fqdn
		CROSS JOIN LATERAL jsonb_array_elements(
			CASE WHEN jsonb_typeof(e.ct->'certificates') = 'array' THEN e.ct->'certificates' ELSE '[]'::jsonb END) AS c
		WHERE coalesce(c->>'cert_sha256', '') <> ''
		ORDER BY e.fqdn`)
	return collect(rows, err, func(r pgx.Row) (EnrichCert, error) {
		var c EnrichCert
		err := r.Scan(&c.FQDN, &c.SHA256, &c.NotBefore, &c.NotAfter)
		return c, err
	})
}

// EnrichRegistration is the RDAP registration of the stored enrichment of a
// watched domain.
type EnrichRegistration struct {
	FQDN        string
	Domain      string
	RegistrarID string
	Registrar   string
	Registered  time.Time
}

// EnrichRegistrations returns the registrations with a registrar and a
// registration date of the stored enrichments of watched domains.
func (s *Store) EnrichRegistrations(ctx context.Context) ([]EnrichRegistration, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT e.fqdn, coalesce(e.rdap->>'domain', ''), coalesce(e.rdap->'registrar'->>'iana_id', ''),
			coalesce(e.rdap->'registrar'->>'name', ''), (e.rdap->>'registration')::timestamptz
		FROM domain_enrich e
		JOIN domains d ON d.fqdn = e.fqdn
		WHERE jsonb_typeof(e.rdap->'registrar') = 'object' AND e.rdap->>'registration' IS NOT NULL
		ORDER BY e.fqdn`)
	return collect(rows, err, func(r pgx.Row) (EnrichRegistration, error) {
		var g EnrichRegistration
		err := r.Scan(&g.FQDN, &g.Domain, &g.RegistrarID, &g.Registrar, &g.Registered)
		return g, err
	})
}
