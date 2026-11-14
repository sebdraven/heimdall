-- +goose Up
-- Past captures of the name in Lookyloo, NULL when its search failed or
-- Lookyloo is not configured.
ALTER TABLE domain_enrich ADD COLUMN lookyloo jsonb;

-- +goose Down
ALTER TABLE domain_enrich DROP COLUMN lookyloo;
