CREATE DATABASE IF NOT EXISTS heimdall;

CREATE TABLE IF NOT EXISTS heimdall.observations
(
    ts          DateTime64(3) CODEC(Delta, ZSTD),
    domain      String,
    qtype       LowCardinality(String),
    resolver    LowCardinality(String),
    rcode       LowCardinality(String),
    ttl         UInt32,
    rdata       Array(String),
    answer_hash UInt64,
    latency_ms  UInt32,
    truncated   UInt8,
    wire        String CODEC(ZSTD(3)) TTL toDateTime(ts) + INTERVAL 12 MONTH
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (domain, qtype, resolver, ts);

CREATE TABLE IF NOT EXISTS heimdall.pdns
(
    rrname     String,
    rrtype     LowCardinality(String),
    rdata      String,
    first_seen SimpleAggregateFunction(min, DateTime64(3)),
    last_seen  SimpleAggregateFunction(max, DateTime64(3)),
    count      SimpleAggregateFunction(sum, UInt64),
    INDEX idx_rdata rdata TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = AggregatingMergeTree
ORDER BY (rrname, rrtype, rdata);

-- The inner rename avoids aliasing arrayJoin(rdata) to its own source column.
CREATE MATERIALIZED VIEW IF NOT EXISTS heimdall.pdns_mv TO heimdall.pdns AS
SELECT
    rrname,
    rrtype,
    arrayJoin(vals) AS rdata,
    ts AS first_seen,
    ts AS last_seen,
    toUInt64(1) AS count
FROM
(
    SELECT
        domain AS rrname,
        qtype  AS rrtype,
        rdata  AS vals,
        ts
    FROM heimdall.observations
    WHERE rcode = 'NOERROR'
);

CREATE TABLE IF NOT EXISTS heimdall.changes
(
    ts         DateTime64(3) CODEC(Delta, ZSTD),
    domain     String,
    qtype      LowCardinality(String),
    resolver   LowCardinality(String),
    prev_hash  UInt64,
    new_hash   UInt64,
    prev_rcode LowCardinality(String),
    new_rcode  LowCardinality(String),
    added      Array(String),
    removed    Array(String),
    prev_ttl   UInt32,
    new_ttl    UInt32
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (domain, ts);

CREATE TABLE IF NOT EXISTS heimdall.events
(
    ts       DateTime64(3) CODEC(Delta, ZSTD),
    domain   String,
    campaign String,
    kind     LowCardinality(String),
    qtype    LowCardinality(String),
    resolver LowCardinality(String),
    detail   String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, domain);
