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
only sees the A/AAAA owned by `fqdn` itself, and may return CNAME targets
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

## VirusTotal passive DNS

Optional: the graph view can add the resolutions VirusTotal saw for its
domain and IP nodes. Nothing is sent to VirusTotal unless an analyst asks
for it, and nothing is sent at all without a key.

| Variable                   | Default | Meaning                                                        |
|----------------------------|---------|----------------------------------------------------------------|
| `HEIMDALL_VT_API_KEY`      | empty   | VirusTotal API v3 key; empty disables the feature, UI included |
| `HEIMDALL_VT_DAILY_BUDGET` | `500`   | lookups per UTC day for Heimdall                               |
| `HEIMDALL_VT_TTL`          | `168h`  | an object looked up less than this ago is not looked up again  |

`POST /graph/domain/{fqdn}/vt[?depth=]` and `POST /graph/campaign/{id}/vt`
(session, `analyst`, CSRF token, button "Enrich with VT" of the graph page)
look up every domain and IP node of the graph, as drawn without VirusTotal:

```
GET https://www.virustotal.com/api/v3/domains/{domain}/resolutions?limit=40
GET https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions?limit=40
```

The `resolutions` (`host_name`, `ip_address`, `date`) go to the ClickHouse
table `vt_resolutions`; the fetch goes to the Postgres table `vt_fetches`.

The enrichment runs in the background, for at most 10 minutes, and does not
depend on the request: the POST answers `202 {"job", "state": "running",
"started_at"}` at once. One enrichment runs at a time per domain or
campaign; a POST while one runs answers its state and starts nothing.
`GET` on the same path (session, `viewer`) answers the state of the last
enrichment, or `{"state": "none"}`. `/api/vt/enrich/...` does the same
under a bearer token (see API) and shares the jobs: a POST there while the
graph page enriches the same target answers that job.

- `running`;
- `done`, with `finished_at` and `{"looked_up", "cached", "skipped_cdn",
  "skipped_reserved", "skipped_budget", "stopped_reason"}`;
- `failed`, with the same fields and `error`.

The jobs live in the memory of the `heimdall-api` process: a restart loses
them, and a finished one is forgotten after an hour. The graph page polls
every 2 seconds, then reloads with `?vt=1`; it resumes polling when opened
during an enrichment. The action is in the audit log as `vt.enrich` at the
end of the enrichment.

Quota. The key is shared with other tools (300 lookups per minute, 1000 per
day, 31K per month), so each lookup is one request and:

- one page per object (`limit=40`), never the next ones;
- at most 4 requests per second per `heimdall-api` process;
- at most 300 lookups per enrichment;
- at most `HEIMDALL_VT_DAILY_BUDGET` lookups per UTC day, counted in the
  Postgres table `vt_usage` before each request, failed ones included;
- no lookup of an object fetched within `HEIMDALL_VT_TTL` (`cached`), of a
  CDN address (`skipped_cdn`) or of a private, shared, documentation or
  other reserved address (`skipped_reserved`);
- an HTTP 429 (`QuotaExceededError`, `TooManyRequestsError`) or any other
  VirusTotal error stops the enrichment at once; the objects left count as
  `skipped_budget` and `stopped_reason` says why. A 404 counts as no
  resolution.

The graph reads the cache only, never VirusTotal: with `?vt=1`,
`/graph/.../data` and `/api/graph/...` add an edge `{"kind": "VT",
"first_seen", "last_seen"}` (earliest and latest `date` of the pair) for
each cached pair touching a domain or IP node of the graph. A name or
address only VirusTotal saw becomes a node with `"source": "vt"` (other
nodes have `"source": "heimdall"`). CDN addresses are left out and counted
in `excluded_cdn`. The 500 nodes cap applies to the whole graph, Heimdall
nodes first. The "VirusTotal" box of the graph page reloads it with
`?vt=1`; the page shows the lookups left today. VT edges are dashed.

The domain and rdata pages read the cache only too. With a key,
`/domains/{fqdn}` has a "VirusTotal" section after Passive DNS:

- "last looked up <time> (<status>)" from `vt_fetches` for `d:<fqdn>`, or
  "not looked up yet";
- the addresses VirusTotal saw for the name, latest first: IP, first and
  last seen by VirusTotal, the CDN marker, and "also seen by Heimdall" when
  the address is in the name's passive DNS;
- the "Enrich with VT" button (`analyst`), which starts the enrichment of
  the depth 1 graph of the name, follows it as the graph page does and
  reloads the page at the end.

`/rdata/{value}`, when the value is an address, has the same section
without the button: its last lookup (`ip:<value>`) and the names VirusTotal
saw on it, marked "watched" when in the watchlist. `web/static/vtjob.js`
follows the enrichment on both the graph and the domain pages.

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
docker compose exec -T clickhouse sh -c \
  'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --multiquery' \
  < deploy/clickhouse/migrations/0003_vt.sql
```

`0003_vt.sql` creates `vt_resolutions`, which only `heimdall-api` uses, and
only when VirusTotal is configured.

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
GET    /api/pivots/{fqdn}[?limit=]  names sharing an A/AAAA value or the whole NS set, with overlap, see below
GET    /api/graph/domain/{fqdn}[?depth=]   graph around a name, see Graph view
GET    /api/graph/campaign/{id}     graph of a campaign, 404 if unknown, see Graph view
GET    /api/search?q=&limit=        watchlist, pdns names and pdns values, see below
GET    /api/vt/ip/{ip}              names VirusTotal saw on an address, cache only, see below
GET    /api/vt/budget               VirusTotal lookups of the UTC day
POST   /api/vt/enrich/domain/{fqdn}[?depth=]   analyst, enrichment job, see VirusTotal passive DNS
GET    /api/vt/enrich/domain/{fqdn} state of the job
POST   /api/vt/enrich/campaign/{id} analyst, enrichment job, 404 if unknown
GET    /api/vt/enrich/campaign/{id} state of the job
GET    /healthz                     no auth
```

`since` and `until` accept a duration (`24h`), a date, RFC 3339 or epoch seconds.

`/api/domains/{fqdn}/detail` returns
`{"domain", "current", "changes", "pdns", "vt"}`: the watchlist entry (`null`
if the name is not watched, which is not a 404), the latest answer per qtype
and resolver over the last 7 days, the most recent changes (`limit`, default
200, max 1000), up to 1000 passive DNS records owned by the name and the
cached VirusTotal resolutions. Dates are RFC 3339 UTC.

`vt` is `{"looked_up_at", "status", "resolutions": [{"ip", "first_seen",
"last_seen"}]}`, from the cache only, latest first, at most 500 addresses.
`status` is `ok`, `empty` or `error`. `looked_up_at` and `status` are
`null` when the name was never looked up itself; `resolutions` then holds
what the lookups of its addresses cached, as the page shows. `vt` is `null`
only without a VirusTotal key.

The `/api/vt/*` routes answer 404 without a VirusTotal key.

`/api/vt/ip/{ip}` returns `{"ip", "looked_up_at", "status", "names":
[{"host_name", "first_seen", "last_seen", "watched", "campaign"}]}`, what
`/rdata/{ip}` shows: the last lookup of `ip:{ip}` (`null` if none) and the
names VirusTotal saw on the address, latest first, at most 500, from the
cache only. `campaign` is that of the watched name, `""` otherwise. 400 if
`{ip}` is not an IP address.

`/api/vt/budget` returns `{"budget", "used_today", "remaining"}`:
`HEIMDALL_VT_DAILY_BUDGET`, the lookups counted in `vt_usage` for the
current UTC day and those left.

`POST /api/vt/enrich/domain/{fqdn}[?depth=]` and `POST
/api/vt/enrich/campaign/{id}` (`analyst`) start the enrichment of
`POST /graph/.../vt` and answer `202` with the state of the job; `GET`
(`viewer`) answers that state, or `{"state": "none"}`.

`changes` merges, newest first and within the same `limit`, the changes of
the name and those of its zone `zone:{fqdn}`, as the page does. Each carries
`"scope": "name"` or `"scope": "zone"`. A `current` entry whose `rdata` holds
CDN addresses has `"cdn": {"<ip>": "<provider>"}`, absent otherwise.

`/api/pivots/{fqdn}` returns `{"pivots", "excluded_cdn", "ns_pairs"}`, each
list holding at most `limit` entries (default 1000, at most 10000).

- A and AAAA pivot by value: `pivots` are the other names that held one of
  the A/AAAA values of `fqdn`, as `{"domain", "rrtype", "rdata", "target",
  "other", "overlap"}`. The values that are CDN addresses are not pivoted on
  and are listed in `excluded_cdn` as `{"value", "provider"}`.
- NS pivot by whole set. A single nameserver says nothing
  (`brianna.ns.cloudflare.com` serves millions of zones), but Cloudflare and
  others give each account its own pair, so two zones with exactly the same
  NS set likely have one operator. The zone is `fqdn` if it owns NS records
  seen in the last 7 days, else its nearest ancestor below the TLD that does.
  `ns_pairs` is `{"zone", "ns", "matches"}`: `ns` is that zone's current set,
  sorted, and `matches` are the other names whose current set is strictly
  equal to it (a subset or superset does not match), as `{"domain", "other",
  "target", "overlap"}`, `target` covering the zone's set. CDN prefixes do
  not apply: an identical Cloudflare pair is the signal. `ns_pairs` is `null`
  when no zone is found or its set has fewer than 2 nameservers.

The Zone block of `/domains/{fqdn}` lists the same matches under "Same NS
set (ns1, ns2)", the set itself first, also for a name that is itself a zone
apex.

## Graph view

`/graph/domain/{fqdn}` and `/graph/campaign/{id}`, linked as "Graph" from the
domain and campaign pages, draw the infrastructure with Pivotick. Clicking a
node opens its page. The browser reads the graph from
`/graph/domain/{fqdn}/data` and `/graph/campaign/{id}/data`, which return the
same JSON as `/api/graph/...` under the session cookie, since `/api` only
takes Bearer tokens.

`/api/graph/domain/{fqdn}?depth=` returns `{"nodes", "edges", "truncated",
"excluded_cdn"}`. `depth` is 1 by default, at most 2 (a larger value reads as
2).

- Depth 1: the name, its A/AAAA values from passive DNS, the CNAME targets of
  its current state and the NS set of its zone (as in `/api/pivots`, at least
  2 nameservers).
- Depth 2 adds the other names sharing one of those values or that NS set.

`/api/graph/campaign/{id}` holds every domain of the campaign at depth 1,
plus the names outside the campaign that share a value or an NS set with at
least two of its domains.

Both take `?vt=1` for the cached VirusTotal resolutions, see VirusTotal
passive DNS.

A node is `{"id", "kind", "label", "watched", "campaign", "href",
"source"}`:

| kind     | id                  | label         | href              |
|----------|---------------------|---------------|-------------------|
| `domain` | `d:<fqdn>`          | the name      | `/domains/<fqdn>` |
| `ip`     | `ip:<value>`        | the value     | `/rdata/<value>`  |
| `nsset`  | `ns:<ns1>,<ns2>`    | `ns1, ns2`    | `/domains/<zone>` |

The nameservers of an `nsset` are sorted. `watched` and `campaign` come from
the watchlist. An edge is `{"from", "to", "kind"}`, `kind` being `A`, `AAAA`,
`CNAME`, `NS_SET` or, with `first_seen` and `last_seen`, `VT`. Nodes and edges are unique. CDN addresses are left out
and counted in `excluded_cdn`. A graph stops at 500 nodes, the domains of the
request first, with `"truncated": true`; it is also set when a pivot query
reaches its limit of 500 rows.

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

Roles: `viewer` reads; `analyst` also manages domains and campaigns and
runs VirusTotal enrichments; `admin`
also manages resolvers, NS classes and CDN prefixes and reads the audit log.

## Front-end dependencies

Vendored under `web/static` and embedded in the binaries. No JavaScript
toolchain is used and nothing is loaded from a CDN.

| Library  | Version | File                                                   | sha256                                                             |
|----------|---------|--------------------------------------------------------|--------------------------------------------------------------------|
| htmx     | 2.0.11  | `web/static/htmx.min.js`                               | `d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717` |
| Pivotick | v3.0.0  | `web/static/vendor/pivotick/pivotick.iife.js`          | `e3472a1ad9dbc047b4e379d657276311fd7726180550133c25b68423b288c59d` |
| Pivotick | v3.0.0  | `web/static/vendor/pivotick/pivotick.css`              | `402afa28d1525ab64fa1c46638a2cc39a7e4680a1fc724d77dc428d6298e2244` |
| Pivotick | v3.0.0  | `web/static/vendor/pivotick/workers/simulation.worker.js` | `cda2c24a694de0fe86a8bb80c86e5640eac4c678d4bf5a5dbd547afca7ea2caf` |

The Pivotick files come from the release archive `pivotick-dist.zip`
(sha256 `78ccefad8485a9fa6a87d3ef109a234aa1c4c3c3300cc56c63a6bede25d18617`).
Only `/graph/...` pages load Pivotick, through `web/static/graph.js`. The
IIFE build inlines its simulation worker and starts it from a `blob:` URL,
which the CSP blocks, so `graph.js` sets `simulation.useWorker: false` and
the layout runs on the page; `workers/simulation.worker.js` is kept with the
release but not loaded.

To update one of them:

1. Download the new release: `htmx.min.js` from the `htmx.org` npm package
   (`dist/htmx.min.js`), `pivotick-dist.zip` from the Pivotick releases
   (<https://pivotick.github.io/Pivotick/>).
2. Check the sha256 of the archive or file against the one published with
   the release (`sha256sum`, or `shasum -a 256` on macOS), then replace the
   files at the paths above.
3. Update the version and sha256 in this table.
4. For Pivotick, check the type definitions of the release for renamed
   options or callbacks used by `graph.js` (`UI.mode`, `simulation.useWorker`,
   `render.nodeTypeAccessor`, `render.nodeStyleMap`, `render.defaultNodeStyle`
   with `textTruncate`, `render.edgeTypeAccessor`, `render.edgeStyleMap` with
   `dashed`, `animateDash` and `strokeColor`, `callbacks.onNodeClick`), and
   that the graph pages still work under the
   CSP of `cmd/heimdall-api/server.go`.

## Configuration

Environment variables only, prefixed `HEIMDALL_`: see `.env.example` and
`internal/config`.

## License

AGPL-3.0, see `LICENSE.md`.
