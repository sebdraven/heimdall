# Heimdall

Active DNS measurement for a watchlist of domains (Android RAT / stalkerware
campaign infrastructure). Every domain is resolved continuously against a set
of recursive resolvers for A, AAAA, CNAME, NS, MX, TXT and SOA; every answer is
stored in ClickHouse, from which Heimdall derives a passive DNS view
(first seen / last seen / count) and a stream of change events.

Scope is strictly DNS: no ASN, certificate transparency or scanning.

## Components

| Binary               | Role                                                                 |
|----------------------|----------------------------------------------------------------------|
| `heimdall-collector` | Scheduler, resolver workers, change detection and event classification |
| `heimdall-api`       | HTTP API, htmx front end, Postgres migrations                        |
| `heimdall-cli`       | Users, API tokens, watchlist import, resolvers, CDN prefixes         |

Postgres holds the watchlist, users and configuration; ClickHouse holds
observations, passive DNS, changes and events.

Event kinds: `new_rdata`, `removed_rdata`, `nxdomain`, `resurrection`,
`ns_sinkhole`, `ns_parking`, `soa_serial_change`, `ttl_change`.

For A, AAAA, NS, MX and TXT a new value is reported at once, but a value is
only reported removed after `HEIMDALL_REMOVAL_GRACE` (default 3) consecutive
answers without it, so that resolvers rotating through a pool do not produce
churn. NXDOMAIN and NOERROR transitions are immediate.

`observations.answer_hash` covers the answer as observed, while
`changes.prev_tracked_hash` / `changes.new_tracked_hash` and `tuple_state.hash`
cover the tracked set after hysteresis: the two families never match and must
not be joined.

## Passive DNS semantics

As in the Passive DNS Common Output Format, `rrname` is the **owner** of the
record, not the watched name that was queried. Every RR of the answer section
is recorded, CNAME chain included: an A query for `www.x` answered with a CNAME
to `cdn.y` yields two records, `(www.x, CNAME, cdn.y)` and `(cdn.y, A, <ip>)`.

Going from a watched name to its IPs therefore follows the CNAME chain: query
`/api/pdns/query/www.x`, then the CNAME targets. Likewise `/api/pivots/{fqdn}`
only sees the A/AAAA/NS owned by `fqdn` itself, and may return CNAME targets
that are not in the watchlist.

### Authority section

A NS or SOA query on a name that is not a zone apex (`proxy.syamcloud.com`)
is answered NOERROR with an empty answer: the zone's SOA, sometimes its NS,
come in the authority section. The collector keeps the NS and SOA of that
section in `observations.authority`, and `pdns_authority_mv` feeds them to
`pdns` under their owner, the zone apex, when the rcode is NOERROR.

The zone is then tracked like a watched domain under the name `zone:<zone>`
(same hysteresis, event kinds and `tuple_state`, campaign of the name that
was queried), at most once per zone, qtype and resolver per 60 s:

- SOA: derived from the authority section of a SOA query, not written to
  `observations`;
- NS: an empty NOERROR answer of any qtype triggers a real NS query on the
  zone, under the resolver's rate limit, so that `ns_sinkhole` and
  `ns_parking` apply to the zone. It is written to `observations` under the
  zone name, which feeds `pdns`. Zones in the watchlist are not queried
  again.

In the UI, `zone:X` reads "zone X" and links to `/domains/X`, whose change
timeline includes the changes of `zone:X`. The page of a name that is not an
apex shows the NS and SOA of its zone from passive DNS.

## CDN prefixes

Addresses of a CDN (Cloudflare, Fastly, Akamai…) are shared by unrelated
names, so sharing one is not an infrastructure link. Postgres table
`cdn_prefixes` lists their prefixes, seeded with the published Cloudflare
ranges (`source` = `seed`); nothing is looked up outside DNS. Other providers
are added by an admin on `/admin` or with the CLI:

```sh
heimdall-cli cdn add --prefix 192.0.2.0/24 --provider Example
heimdall-cli cdn import --file fastly.txt --provider Fastly   # one prefix per line, '#' comments
heimdall-cli cdn list
heimdall-cli cdn rm --id 42
```

The API loads the prefixes at start-up and reloads them every 60 s (at once
after a change on `/admin`). Only IP values are classified. A CDN address is
marked "CDN <provider>" in Current state, the change timeline and search,
gets no sharing badge, and its `/rdata/` page says so. Pivots leave out the
A/AAAA values that are CDN addresses.

## Quick start

```sh
cp .env.example .env        # set POSTGRES_PASSWORD and CLICKHOUSE_PASSWORD
docker compose up -d

docker compose run --rm api heimdall-cli user add --username alice --role admin
docker compose run --rm api heimdall-cli resolver add --address 9.9.9.9:53 --label quad9 --qps 20
docker compose run --rm -v "$PWD/domains.txt:/domains.txt:ro" api \
  heimdall-cli domain import --file /domains.txt --campaign spynote-2026
```

The UI listens on http://127.0.0.1:8080 only. Put a TLS reverse proxy in front
for remote access; set `HEIMDALL_INSECURE_COOKIE=true` only for local
plain-HTTP development.

### Upgrading ClickHouse

`deploy/clickhouse/init.sql` only runs on an empty volume. On an existing
installation, apply the migrations in order before starting the new
collector, which writes columns they add. They are idempotent:

```sh
docker compose exec -T clickhouse sh -c \
  'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --multiquery' \
  < deploy/clickhouse/migrations/0002_authority.sql
```

### ClickHouse system logs

`deploy/clickhouse/config.d/heimdall.xml`, mounted alone into the image's
`config.d`, caps the server at half the RAM and keeps the `system.*_log`
tables 7 days (`event_date + INTERVAL 7 DAY DELETE`). It is read when the
container starts:

```sh
docker compose up -d --force-recreate clickhouse
```

When the definition of a system log table changes, a new TTL included,
ClickHouse does not alter it: at the first flush it renames the old table
`system.<name>_0` (then `_1`, `_2`… on later changes) and creates a new one.
The renamed tables are no longer written nor purged. List them with their
size:

```sh
docker compose exec clickhouse sh -c 'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" -q "
  SELECT table, formatReadableSize(sum(bytes_on_disk)) AS size, sum(rows) AS rows
  FROM system.parts
  WHERE database = '\''system'\'' AND active AND match(table, '\''_log_[0-9]+$'\'')
  GROUP BY table ORDER BY sum(bytes_on_disk) DESC"'
```

then, after checking the list, drop each of them:

```sql
DROP TABLE system.query_log_0 SYNC;
```

## API

Authenticate with `Authorization: Bearer <token>`
(`heimdall-cli token create --username alice --label script`). Tokens inherit
the role of their user.

```
GET    /api/pdns/query/{rrname}     NDJSON, CIRCL Passive DNS COF
GET    /api/pdns/rdata/{value}      NDJSON, CIRCL Passive DNS COF
GET    /api/domains[?campaign=]
POST   /api/domains                 {"fqdn", "campaign", "interval_seconds", "enabled", "source"}
GET    /api/domains/{fqdn}/detail[?limit=]   what /domains/{fqdn} shows, see below
PATCH  /api/domains/{fqdn}
DELETE /api/domains/{fqdn}
GET    /api/campaigns
POST   /api/campaigns               {"name", "family", "description"}
GET    /api/campaigns/{id}/domains  same fields as GET /api/domains, 404 if unknown
GET    /api/events?since=&until=&kind=&campaign=&domain=&limit=
GET    /api/pivots/{fqdn}[?limit=]  domains sharing an A/AAAA/NS value, with overlap, see below
GET    /api/search?q=&limit=        watchlist, pdns names and pdns values, see below
GET    /healthz                     no auth
```

`since` and `until` accept a duration (`24h`), a date, RFC 3339 or epoch seconds.

`/api/domains/{fqdn}/detail` returns
`{"domain", "current", "changes", "pdns"}`: the watchlist entry (`null` if the
name is not watched, which is not a 404), the latest answer per qtype and
resolver over the last 7 days, the most recent changes (`limit`, default 200,
max 1000) and up to 1000 passive DNS records owned by the name. Dates are
RFC 3339 UTC.

`changes` merges, newest first and within the same `limit`, the changes of
the name and those of its zone `zone:{fqdn}`, as the page does. Each carries
`"scope": "name"` or `"scope": "zone"`. A `current` entry whose `rdata` holds
CDN addresses has `"cdn": {"<ip>": "<provider>"}`, absent otherwise.

`/api/pivots/{fqdn}` returns `{"pivots", "excluded_cdn"}`. `pivots` are
`{"domain", "rrtype", "rdata", "target", "other", "overlap"}`, `limit`
defaulting to 1000, at most 10000. The A/AAAA values of `fqdn` that are CDN
addresses are not pivoted on and are listed in `excluded_cdn` as
`{"value", "provider"}`.

## Search

The search bar (`/search?q=`) and `/api/search` take a domain, an IP or a
value:

- an IP goes to `/rdata/{ip}`;
- a name in the watchlist or owning pdns records, without `*`, goes to
  `/domains/{fqdn}`;
- anything else is a case-insensitive pattern over watchlist names, pdns
  names and pdns values: `*` matches any characters (`*.otax.fun`,
  `node*`), a query without `*` matches as a substring, `%` and `_` are
  literal. At least 3 characters besides `*` are required.

Each source returns at most 200 rows, most recently seen first for pdns, and
is flagged as truncated when it reaches that limit.

`/api/search` applies the same rules without redirecting and returns
`{"query", "kind", "domains", "names", "values", "truncated"}`. `kind` is
`ip`, `exact` or `pattern`; `domains` has the fields of `GET /api/domains`;
`names` are `{"rrname", "rrtypes", "first_seen", "last_seen", "count",
"watched", "campaign"}`; `values` are `{"rdata", "rrtype", "names",
"first_seen", "last_seen"}`, `names` counting distinct owners; `truncated`
has one boolean per source. For an IP, `names` are the owners that held it
(from at most 1000 pdns records) and `domains` the watched ones among them.
`limit` defaults to 200, at most 200. An empty or too short `q` is a 400.

Roles: `viewer` reads; `analyst` also manages domains and campaigns; `admin`
also manages resolvers, NS classes and CDN prefixes and reads the audit log.

## Front-end assets

`web/static/htmx.min.js` (htmx 2.x) is not vendored by the skeleton: commit it
so that it is embedded in the binaries. No JavaScript toolchain is used.

## Configuration

Environment variables only, prefixed `HEIMDALL_`: see `.env.example` and
`internal/config`.

## License

AGPL-3.0, see `LICENSE.md`.
