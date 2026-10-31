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
    answers     Array(Tuple(name String, type String, value String)),
    answer_hash UInt64,
    latency_ms  UInt32,
    truncated   UInt8,
    wire        String CODEC(ZSTD(3))
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

-- rrname is the owner of each answer RR, CNAME chain included. The inner
-- query exposes only ts and answers so the rdata alias cannot resolve to
-- observations.rdata.
CREATE MATERIALIZED VIEW IF NOT EXISTS heimdall.pdns_mv TO heimdall.pdns AS
SELECT
    tupleElement(a, 'name')  AS rrname,
    tupleElement(a, 'type')  AS rrtype,
    tupleElement(a, 'value') AS rdata,
    ts AS first_seen,
    ts AS last_seen,
    toUInt64(1) AS count
FROM
(
    SELECT ts, answers
    FROM heimdall.observations
    WHERE rcode = 'NOERROR'
)
ARRAY JOIN answers AS a;

CREATE TABLE IF NOT EXISTS heimdall.changes
(
    ts                DateTime64(3) CODEC(Delta, ZSTD),
    domain            String,
    qtype             LowCardinality(String),
    resolver          LowCardinality(String),
    prev_tracked_hash UInt64,
    new_tracked_hash  UInt64,
    prev_rcode        LowCardinality(String),
    new_rcode         LowCardinality(String),
    added             Array(String),
    removed           Array(String),
    prev_ttl          UInt32,
    new_ttl           UInt32
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

-- Change-detection state, one row per tuple after FINAL. missing[i] is the
-- consecutive absence count of tracked[i].
CREATE TABLE IF NOT EXISTS heimdall.tuple_state
(
    ts        DateTime64(3),
    domain    String,
    qtype     LowCardinality(String),
    resolver  LowCardinality(String),
    rcode     LowCardinality(String),
    tracked   Array(String),
    missing   Array(UInt32),
    hash      UInt64,
    ttl       UInt32,
    ceiling   UInt32,
    settled   UInt8,
    win_start DateTime64(3),
    win_max   UInt32,
    win_n     UInt32
)
ENGINE = ReplacingMergeTree(ts)
ORDER BY (domain, qtype, resolver);
