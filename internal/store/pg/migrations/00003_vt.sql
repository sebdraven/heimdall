-- +goose Up
-- VirusTotal lookups per UTC day, for HEIMDALL_VT_DAILY_BUDGET.
CREATE TABLE vt_usage (
    day     date PRIMARY KEY,
    lookups integer NOT NULL DEFAULT 0 CHECK (lookups >= 0)
);

-- Last VirusTotal fetch per object, "d:<fqdn>" or "ip:<ip>", for HEIMDALL_VT_TTL.
CREATE TABLE vt_fetches (
    object     text PRIMARY KEY,
    fetched_at timestamptz NOT NULL,
    status     text NOT NULL CHECK (status IN ('ok', 'empty', 'error')),
    count      integer NOT NULL DEFAULT 0
);

-- +goose Down
DROP TABLE vt_fetches;
DROP TABLE vt_usage;
