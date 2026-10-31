-- Authority section: applies to an installation created before it, see the
-- README. Idempotent. init.sql already includes it for new installations.

ALTER TABLE heimdall.observations
    ADD COLUMN IF NOT EXISTS authority Array(Tuple(name String, type String, value String)) DEFAULT [];

CREATE MATERIALIZED VIEW IF NOT EXISTS heimdall.pdns_authority_mv TO heimdall.pdns AS
SELECT
    tupleElement(a, 'name')  AS rrname,
    tupleElement(a, 'type')  AS rrtype,
    tupleElement(a, 'value') AS rdata,
    ts AS first_seen,
    ts AS last_seen,
    toUInt64(1) AS count
FROM
(
    SELECT ts, authority
    FROM heimdall.observations
    WHERE rcode = 'NOERROR'
)
ARRAY JOIN authority AS a;
