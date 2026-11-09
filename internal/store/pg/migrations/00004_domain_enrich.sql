-- +goose Up
-- Last enrichment of a name. A source that failed is NULL, its message in
-- errors.
CREATE TABLE domain_enrich (
    fqdn       text PRIMARY KEY,
    fetched_at timestamptz NOT NULL,
    status     text NOT NULL CHECK (status IN ('ok', 'partial', 'error')),
    dns        jsonb,
    zone       jsonb,
    rdap       jsonb,
    ct         jsonb,
    subdomains jsonb,
    errors     jsonb
);

-- +goose Down
DROP TABLE domain_enrich;
