-- +goose Up
CREATE TABLE cdn_prefixes (
    id         bigserial PRIMARY KEY,
    prefix     cidr UNIQUE NOT NULL,
    provider   text NOT NULL,
    source     text NOT NULL DEFAULT 'manual',
    created_at timestamptz NOT NULL DEFAULT now()
);

-- https://www.cloudflare.com/ips/
INSERT INTO cdn_prefixes (prefix, provider, source) VALUES
    ('173.245.48.0/20', 'Cloudflare', 'seed'),
    ('103.21.244.0/22', 'Cloudflare', 'seed'),
    ('103.22.200.0/22', 'Cloudflare', 'seed'),
    ('103.31.4.0/22', 'Cloudflare', 'seed'),
    ('141.101.64.0/18', 'Cloudflare', 'seed'),
    ('108.162.192.0/18', 'Cloudflare', 'seed'),
    ('190.93.240.0/20', 'Cloudflare', 'seed'),
    ('188.114.96.0/20', 'Cloudflare', 'seed'),
    ('197.234.240.0/22', 'Cloudflare', 'seed'),
    ('198.41.128.0/17', 'Cloudflare', 'seed'),
    ('162.158.0.0/15', 'Cloudflare', 'seed'),
    ('104.16.0.0/13', 'Cloudflare', 'seed'),
    ('104.24.0.0/14', 'Cloudflare', 'seed'),
    ('172.64.0.0/13', 'Cloudflare', 'seed'),
    ('131.0.72.0/22', 'Cloudflare', 'seed'),
    ('2400:cb00::/32', 'Cloudflare', 'seed'),
    ('2606:4700::/32', 'Cloudflare', 'seed'),
    ('2803:f800::/32', 'Cloudflare', 'seed'),
    ('2405:b500::/32', 'Cloudflare', 'seed'),
    ('2405:8100::/32', 'Cloudflare', 'seed'),
    ('2a06:98c0::/29', 'Cloudflare', 'seed'),
    ('2c0f:f248::/32', 'Cloudflare', 'seed');

-- +goose Down
DROP TABLE cdn_prefixes;
