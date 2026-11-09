package pg

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/sebdraven/heimdall/internal/enrich"
)

// SaveDomainEnrich replaces the enrichment of r.FQDN.
func (s *Store) SaveDomainEnrich(ctx context.Context, r enrich.Result) error {
	var errs []byte
	if len(r.Errors) > 0 {
		var err error
		if errs, err = json.Marshal(r.Errors); err != nil {
			return err
		}
	}
	dns, err1 := jsonOrNull(r.DNS)
	zone, err2 := jsonOrNull(r.Zone)
	rdap, err3 := jsonOrNull(r.RDAP)
	ct, err4 := jsonOrNull(r.CT)
	subs, err5 := jsonOrNull(r.Subdomains)
	if err := errors.Join(err1, err2, err3, err4, err5); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO domain_enrich (fqdn, fetched_at, status, dns, zone, rdap, ct, subdomains, errors)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (fqdn) DO UPDATE SET
			fetched_at = excluded.fetched_at, status = excluded.status, dns = excluded.dns, zone = excluded.zone,
			rdap = excluded.rdap, ct = excluded.ct, subdomains = excluded.subdomains, errors = excluded.errors`,
		r.FQDN, r.FetchedAt, r.Status, dns, zone, rdap, ct, subs, errs)
	return mapErr(err)
}

// DomainEnrich returns the last enrichment of fqdn, or ErrNotFound.
func (s *Store) DomainEnrich(ctx context.Context, fqdn string) (enrich.Result, error) {
	r := enrich.Result{FQDN: fqdn}
	var dns, zone, rdap, ct, subs, errs []byte
	err := s.pool.QueryRow(ctx, `
		SELECT fetched_at, status, dns, zone, rdap, ct, subdomains, errors FROM domain_enrich WHERE fqdn = $1`, fqdn).
		Scan(&r.FetchedAt, &r.Status, &dns, &zone, &rdap, &ct, &subs, &errs)
	if err != nil {
		return r, mapErr(err)
	}
	if errs != nil {
		if err := json.Unmarshal(errs, &r.Errors); err != nil {
			return r, err
		}
	}
	return r, errors.Join(fromJSON(dns, &r.DNS), fromJSON(zone, &r.Zone), fromJSON(rdap, &r.RDAP),
		fromJSON(ct, &r.CT), fromJSON(subs, &r.Subdomains))
}

func jsonOrNull[T any](v *T) ([]byte, error) {
	if v == nil {
		return nil, nil
	}
	return json.Marshal(v)
}

func fromJSON[T any](b []byte, dst **T) error {
	if b == nil {
		return nil
	}
	*dst = new(T)
	return json.Unmarshal(b, *dst)
}
