package pg

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

type Campaign struct {
	ID          int64
	Name        string
	Family      string
	Description string
	CreatedAt   time.Time
	Domains     int
}

type Domain struct {
	ID              int64
	FQDN            string
	CampaignID      *int64
	Campaign        string
	IntervalSeconds int
	Enabled         bool
	Source          string
	AddedBy         *int64
	AddedAt         time.Time
}

type NewDomain struct {
	FQDN            string
	CampaignID      *int64
	IntervalSeconds int
	Enabled         bool
	Source          string
	AddedBy         *int64
}

type DomainPatch struct {
	SetCampaign     bool
	CampaignID      *int64
	IntervalSeconds *int
	Enabled         *bool
	Source          *string
}

const campaignSelect = `
	SELECT c.id, c.name, c.family, c.description, c.created_at, count(d.id)
	FROM campaigns c LEFT JOIN domains d ON d.campaign_id = c.id`

func scanCampaign(r pgx.Row) (Campaign, error) {
	var c Campaign
	err := r.Scan(&c.ID, &c.Name, &c.Family, &c.Description, &c.CreatedAt, &c.Domains)
	return c, mapErr(err)
}

func (s *Store) Campaigns(ctx context.Context) ([]Campaign, error) {
	rows, err := s.pool.Query(ctx, campaignSelect+` GROUP BY c.id ORDER BY c.name`)
	return collect(rows, err, scanCampaign)
}

func (s *Store) Campaign(ctx context.Context, id int64) (Campaign, error) {
	return scanCampaign(s.pool.QueryRow(ctx, campaignSelect+` WHERE c.id = $1 GROUP BY c.id`, id))
}

func (s *Store) CampaignByName(ctx context.Context, name string) (Campaign, error) {
	return scanCampaign(s.pool.QueryRow(ctx, campaignSelect+` WHERE c.name = $1 GROUP BY c.id`, name))
}

func (s *Store) CreateCampaign(ctx context.Context, name, family, description string) (Campaign, error) {
	var id int64
	err := s.pool.QueryRow(ctx,
		`INSERT INTO campaigns (name, family, description) VALUES ($1, $2, $3) RETURNING id`,
		name, family, description).Scan(&id)
	if err != nil {
		return Campaign{}, mapErr(err)
	}
	return s.Campaign(ctx, id)
}

const domainSelect = `
	SELECT d.id, d.fqdn, d.campaign_id, coalesce(c.name, ''), d.interval_seconds, d.enabled, d.source, d.added_by, d.added_at
	FROM domains d LEFT JOIN campaigns c ON c.id = d.campaign_id`

func scanDomain(r pgx.Row) (Domain, error) {
	var d Domain
	err := r.Scan(&d.ID, &d.FQDN, &d.CampaignID, &d.Campaign, &d.IntervalSeconds, &d.Enabled, &d.Source, &d.AddedBy, &d.AddedAt)
	return d, mapErr(err)
}

// Domains lists the watchlist, optionally restricted to one campaign.
func (s *Store) Domains(ctx context.Context, campaignID *int64) ([]Domain, error) {
	rows, err := s.pool.Query(ctx, domainSelect+` WHERE ($1::bigint IS NULL OR d.campaign_id = $1) ORDER BY d.fqdn`, campaignID)
	return collect(rows, err, scanDomain)
}

func (s *Store) EnabledDomains(ctx context.Context) ([]Domain, error) {
	rows, err := s.pool.Query(ctx, domainSelect+` WHERE d.enabled ORDER BY d.fqdn`)
	return collect(rows, err, scanDomain)
}

func (s *Store) Domain(ctx context.Context, fqdn string) (Domain, error) {
	return scanDomain(s.pool.QueryRow(ctx, domainSelect+` WHERE d.fqdn = $1`, fqdn))
}

// DomainsByFQDN returns the watched domains among fqdns, keyed by fqdn.
func (s *Store) DomainsByFQDN(ctx context.Context, fqdns []string) (map[string]Domain, error) {
	out := make(map[string]Domain, len(fqdns))
	if len(fqdns) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, domainSelect+` WHERE d.fqdn = ANY($1::text[])`, fqdns)
	domains, err := collect(rows, err, scanDomain)
	if err != nil {
		return nil, err
	}
	for _, d := range domains {
		out[d.FQDN] = d
	}
	return out, nil
}

// SearchDomains returns the watched domains whose fqdn matches the ILIKE
// pattern, by fqdn.
func (s *Store) SearchDomains(ctx context.Context, pattern string, limit int) ([]Domain, error) {
	rows, err := s.pool.Query(ctx, domainSelect+` WHERE d.fqdn ILIKE $1 ORDER BY d.fqdn LIMIT $2`, pattern, limit)
	return collect(rows, err, scanDomain)
}

func (s *Store) CreateDomain(ctx context.Context, d NewDomain) (Domain, error) {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO domains (fqdn, campaign_id, interval_seconds, enabled, source, added_by)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		d.FQDN, d.CampaignID, d.IntervalSeconds, d.Enabled, d.Source, d.AddedBy)
	if err != nil {
		return Domain{}, mapErr(err)
	}
	return s.Domain(ctx, d.FQDN)
}

// ImportDomains inserts the fqdns that are not yet watched and returns how
// many were inserted.
func (s *Store) ImportDomains(ctx context.Context, fqdns []string, campaignID *int64, intervalSeconds int, source string, addedBy *int64) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO domains (fqdn, campaign_id, interval_seconds, source, added_by)
		SELECT f, $2::bigint, $3::integer, $4::text, $5::bigint FROM unnest($1::text[]) AS f
		ON CONFLICT (fqdn) DO NOTHING`,
		fqdns, campaignID, intervalSeconds, source, addedBy)
	return tag.RowsAffected(), mapErr(err)
}

func (s *Store) UpdateDomain(ctx context.Context, fqdn string, p DomainPatch) (Domain, error) {
	err := affected(s.pool.Exec(ctx, `
		UPDATE domains SET
			campaign_id      = CASE WHEN $2 THEN $3::bigint ELSE campaign_id END,
			interval_seconds = coalesce($4::integer, interval_seconds),
			enabled          = coalesce($5::boolean, enabled),
			source           = coalesce($6::text, source)
		WHERE fqdn = $1`,
		fqdn, p.SetCampaign, p.CampaignID, p.IntervalSeconds, p.Enabled, p.Source))
	if err != nil {
		return Domain{}, err
	}
	return s.Domain(ctx, fqdn)
}

func (s *Store) DeleteDomain(ctx context.Context, fqdn string) error {
	return affected(s.pool.Exec(ctx, `DELETE FROM domains WHERE fqdn = $1`, fqdn))
}
