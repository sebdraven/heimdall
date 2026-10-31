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
| `heimdall-cli`       | Users, API tokens, watchlist import, resolvers                       |

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

## API

Authenticate with `Authorization: Bearer <token>`
(`heimdall-cli token create --username alice --label script`). Tokens inherit
the role of their user.

```
GET    /api/pdns/query/{rrname}     NDJSON, CIRCL Passive DNS COF
GET    /api/pdns/rdata/{value}      NDJSON, CIRCL Passive DNS COF
GET    /api/domains[?campaign=]
POST   /api/domains                 {"fqdn", "campaign", "interval_seconds", "enabled", "source"}
PATCH  /api/domains/{fqdn}
DELETE /api/domains/{fqdn}
GET    /api/campaigns
POST   /api/campaigns               {"name", "family", "description"}
GET    /api/events?since=&until=&kind=&campaign=&domain=&limit=
GET    /api/pivots/{fqdn}           domains sharing an A/AAAA/NS value, with overlap
GET    /healthz                     no auth
```

`since` and `until` accept a duration (`24h`), a date, RFC 3339 or epoch seconds.

Roles: `viewer` reads; `analyst` also manages domains and campaigns; `admin`
also manages resolvers and NS classes and reads the audit log.

## Front-end assets

`web/static/htmx.min.js` (htmx 2.x) is not vendored by the skeleton: commit it
so that it is embedded in the binaries. No JavaScript toolchain is used.

## Configuration

Environment variables only, prefixed `HEIMDALL_`: see `.env.example` and
`internal/config`.

## License

AGPL-3.0, see `LICENSE.md`.
