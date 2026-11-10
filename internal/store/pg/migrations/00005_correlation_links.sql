-- +goose Up
-- Links between domains of different campaigns, domain_a < domain_b in
-- byte order, recomputed every hour by heimdall-api. A link no longer found
-- keeps its last_seen.
CREATE TABLE correlation_links (
    id         bigserial PRIMARY KEY,
    kind       text NOT NULL,
    value      text NOT NULL,
    domain_a   text NOT NULL,
    campaign_a bigint NOT NULL,
    domain_b   text NOT NULL,
    campaign_b bigint NOT NULL,
    first_seen timestamptz NOT NULL,
    last_seen  timestamptz NOT NULL,
    UNIQUE (kind, value, domain_a, domain_b),
    CHECK (domain_a COLLATE "C" < domain_b COLLATE "C")
);
CREATE INDEX correlation_links_campaigns_idx ON correlation_links (campaign_a, campaign_b);
CREATE INDEX correlation_links_first_seen_idx ON correlation_links (first_seen);

-- +goose Down
DROP TABLE correlation_links;
