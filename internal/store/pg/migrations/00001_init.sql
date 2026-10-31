-- +goose Up
CREATE TABLE users (
    id            bigserial PRIMARY KEY,
    username      text UNIQUE NOT NULL,
    password_hash text NOT NULL,
    role          text NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
    disabled      boolean NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz
);

CREATE TABLE sessions (
    token_sha256 bytea PRIMARY KEY,
    user_id      bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL
);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);
CREATE INDEX sessions_user_id_idx ON sessions (user_id);

CREATE TABLE api_tokens (
    id           bigserial PRIMARY KEY,
    token_sha256 bytea UNIQUE NOT NULL,
    user_id      bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    label        text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked      boolean NOT NULL DEFAULT false
);

CREATE TABLE campaigns (
    id          bigserial PRIMARY KEY,
    name        text UNIQUE NOT NULL,
    family      text NOT NULL DEFAULT '',
    description text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE domains (
    id               bigserial PRIMARY KEY,
    fqdn             text UNIQUE NOT NULL CHECK (fqdn = lower(fqdn) AND fqdn NOT LIKE '%.' AND fqdn <> ''),
    campaign_id      bigint REFERENCES campaigns (id) ON DELETE SET NULL,
    interval_seconds integer NOT NULL DEFAULT 300 CHECK (interval_seconds >= 10),
    enabled          boolean NOT NULL DEFAULT true,
    source           text NOT NULL DEFAULT '',
    added_by         bigint REFERENCES users (id) ON DELETE SET NULL,
    added_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX domains_campaign_id_idx ON domains (campaign_id);

CREATE TABLE resolvers (
    id      bigserial PRIMARY KEY,
    address text UNIQUE NOT NULL,
    label   text NOT NULL DEFAULT '',
    enabled boolean NOT NULL DEFAULT true,
    qps     integer NOT NULL DEFAULT 20 CHECK (qps > 0)
);

CREATE TABLE ns_classes (
    id      bigserial PRIMARY KEY,
    pattern text UNIQUE NOT NULL,
    kind    text NOT NULL CHECK (kind IN ('sinkhole', 'parking')),
    label   text NOT NULL DEFAULT ''
);

CREATE TABLE audit_log (
    id      bigserial PRIMARY KEY,
    user_id bigint REFERENCES users (id) ON DELETE SET NULL,
    action  text NOT NULL,
    target  text NOT NULL DEFAULT '',
    at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_log_at_idx ON audit_log (at);

-- +goose Down
DROP TABLE audit_log;
DROP TABLE ns_classes;
DROP TABLE resolvers;
DROP TABLE domains;
DROP TABLE campaigns;
DROP TABLE api_tokens;
DROP TABLE sessions;
DROP TABLE users;
