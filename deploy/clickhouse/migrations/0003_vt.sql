-- VirusTotal resolutions cache: applies to an installation created before
-- it, see the README. Idempotent. init.sql already includes it for new
-- installations.

CREATE TABLE IF NOT EXISTS heimdall.vt_resolutions
(
    host_name  String,
    ip         String,
    date       DateTime,
    fetched_at DateTime64(3),
    INDEX idx_ip ip TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = ReplacingMergeTree(fetched_at)
ORDER BY (host_name, ip, date);
