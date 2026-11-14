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
| `heimdall-cli`       | Users, API tokens, watchlist import, resolvers, CDN prefixes and their sync |

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
ranges (`source` = `seed`); nothing is looked up outside DNS unless
`heimdall-cli cdn-sync` is run. Other providers are added by an admin on
`/admin` or with the CLI:

```sh
heimdall-cli cdn add --prefix 192.0.2.0/24 --provider Example
heimdall-cli cdn import --file fastly.txt --provider Fastly   # one prefix per line, '#' comments
heimdall-cli cdn list
heimdall-cli cdn rm --id 42
```

`heimdall-cli cdn-sync` reads the official lists of the providers (30 s
timeout per request, User-Agent `heimdall`):

| `-provider`  | Provider   | Source                                                                 |
|--------------|------------|------------------------------------------------------------------------|
| `cloudflare` | Cloudflare | `https://www.cloudflare.com/ips-v4` and `ips-v6`, one prefix per line  |
| `fastly`     | Fastly     | `https://api.fastly.com/public-ip-list`, `addresses` and `ipv6_addresses` |
| `cloudfront` | CloudFront | `https://ip-ranges.amazonaws.com/ip-ranges.json`, service `CLOUDFRONT` of `prefixes` (`ip_prefix`) and `ipv6_prefixes` (`ipv6_prefix`) |
| `bunny`      | Bunny      | `https://bunnycdn.com/api/system/edgeserverlist` and `/IPv6`, JSON arrays of addresses, each a /32 or /128 |

```sh
heimdall-cli cdn-sync                                  # every provider above
heimdall-cli cdn-sync -provider fastly -provider bunny -dry-run
heimdall-cli cdn-sync -provider cloudflare -asn 64500 -as-provider ExampleCDN
```

Each provider is synced in its own transaction under the source
`sync:<provider>`: the listed prefixes no row holds are added, the
`sync:<provider>` rows no longer listed are removed, and the `seed`,
`manual`, `import:…` and other providers' rows are never touched (a listed
prefix they already hold is counted as "already listed by another
source"). The report gives, per provider, the prefixes added, removed and
unchanged; `-dry-run` writes nothing. A list that fails to download or parse,
or is empty, leaves that provider as it was; the others are still synced and
the command exits 1.

`-asn N -as-provider NAME`, repeatable, syncs the prefixes the AS announces
according to RIPEstat
(`https://stat.ripe.net/data/announced-prefixes/data.json?resource=ASN`)
under `sync:<name>`, only when asked and in addition to the providers above
(all of them without `-provider`). **An AS often announces hosting that is not
a CDN**: every address in it is then left out of sharing counts, pivots and
correlation, so the command prints a warning. `NAME` may not be that of a
built-in provider.

The API loads the prefixes at start-up and reloads them every 60 s (at once
after a change on `/admin`), so a sync applies within a minute without a
restart. `/admin` counts the prefixes per provider and per source. Only IP values are classified. A CDN address is
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

`POST /rdata/{ip}/vt[?depth=]` (session, `analyst`, CSRF token) enriches a
single address, `ip:<ip>`, spelled canonically:
`2001:4860:4860:0:0:0:0:8888` is `2001:4860:4860::8888`, an IPv4-mapped
address is unmapped. 400 if `{ip}` is not an address.

- Depth 1 (default): the address alone.
- Depth 2: the address, then the names seen on it, by Heimdall (its A/AAAA
  passive DNS records, as on `/rdata/{ip}`) and in the VirusTotal cache, at
  most 100, latest last seen first. A CDN address has no names: only the
  address is asked for, and skipped as CDN.

The enrichment runs in the background, for at most 10 minutes, and does not
depend on the request: the POST answers `202 {"job", "state": "running",
"started_at"}` at once. One enrichment runs at a time per domain, campaign
or address (whatever the depth); a POST while one runs answers its state
and starts nothing.
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

`/rdata/{value}`, when the value is an address, links to its IP graph
("Graph") and has the same section: its last lookup (`ip:<value>`), the
names VirusTotal saw on it, marked "watched" when in the watchlist, and the
"Enrich with VT" button (`analyst`) with a depth choice, 1 or 2, which posts
to `/rdata/{ip}/vt`, follows the job and reloads the page at the end. Opened
during an enrichment of the address, the page follows it too.

In every graph page, the context menu of an IP node (right click) has "Open
IP graph" and, for an IP or domain node, with a key and the `analyst` role,
"Enrich with VT": it posts to `/rdata/{ip}/vt?depth=1`, or for a domain to
`/graph/domain/{fqdn}/vt?depth=1` as the domain page does, and shows the
state of the job in the graph bar. The graph is not reloaded: once the job
has finished, the next click on the node expands it again with its cached
VirusTotal resolutions. `web/static/vtjob.js` follows the enrichment on the
graph, domain and rdata pages.

## Domain enrichment

An analyst can enrich any name, watched or not, with what Heimdall does not
collect on its own. Nothing is fetched unless asked for. Five sources run at
once:

- DNS: the first enabled resolver of `/admin` is asked A, AAAA, CNAME, NS,
  MX, TXT and SOA, 3 seconds per query. The zone is the name when it owns a
  SOA, else the zone named by an authority section, which is then asked its
  SOA and NS. Without an enabled resolver this source fails and the others
  still run.
- RDAP: the registrable domain of the name (public suffix list) is looked
  up on the RDAP server of its TLD, found in the IANA bootstrap
  (`https://data.iana.org/rdap/dns.json`, kept 24 hours in memory). Kept:
  the registrar (name, IANA id), the registration, expiration and last
  changed dates, the statuses, the nameservers and the role and name of each
  entity; no email address or phone number. 15 second timeout.
- Certificate Transparency, from Cert Spotter (SSLMate):
  `GET {HEIMDALL_CT_URL}/v1/issuances?domain={zone}&include_subdomains=true&expand=dns_names&expand=issuer`,
  then `&after=<id of the last issuance>` until a page of less than 100
  issuances or 500 certificates (`truncated` when it stops there), 30
  seconds in all. Kept per certificate: the Cert Spotter issuance id, the
  full SHA-256 of the certificate (`cert_sha256`, hex), the issuer (friendly
  name, else name), the validity, whether it is revoked and its DNS names
  (lowercased, without final dot, wildcards kept), latest `not_before`
  first; and the union of the names. An HTTP 429 gives `cert spotter rate
  limited`, or `cert spotter full-domain query quota exhausted` when the
  answer says so, with the `Retry-After`, if any; the certificates read
  before it are kept, `truncated`.

  With `HEIMDALL_ONYPHE_API_KEY`, ONYPHE is searched at the same time:
  `GET {HEIMDALL_ONYPHE_URL}/search/?q=category:ctl domain:{domain} {HEIMDALL_ONYPHE_CT_WINDOW}&page=N`
  with `Authorization: bearer <key>`, up to `max_page` or 500 certificates.
  `{domain}` is the registrable domain of the zone, under which ONYPHE files
  a certificate; below it, only the certificates with a name within the zone
  are kept. Per certificate: `fingerprint.sha256` (lowercased, in full; a
  result without it is skipped), the names of `subject.altname` and
  `hostname`, the issuer (`commonname`, else `organization`) and the
  validity. A 429 gives `onyphe rate limited` (and the `Retry-After`), with
  the certificates already read, as for Cert Spotter.

  The two are merged by full SHA-256, never by a prefix: one certificate,
  the union of the names, `sources` (`certspotter`, `onyphe`), and the id,
  issuer and validity of Cert Spotter, else of ONYPHE. A partial answer is
  merged too; the errors of both are joined, `; ` between them, in
  `errors.ct`. `truncated` is set when either search is, or when the union
  passes 500 certificates, the latest being kept.
- Subdomains: the names below the zone in Heimdall's passive DNS
  (ClickHouse only), with first and last seen, at most 500, latest first.
- Lookyloo, with `HEIMDALL_LOOKYLOO_URL`: the past captures of the name
  itself on a self-hosted, open Lookyloo instance (no authentication).
  `POST {url}/json/hostname_info` with `{"hostname": "<fqdn>", "limit":
  4 × HEIMDALL_LOOKYLOO_MAX_CAPTURES}` (the answer repeats a capture once per
  hostnode: one is kept per `capture_uuid`), then, for the
  `HEIMDALL_LOOKYLOO_MAX_CAPTURES` latest (`truncated` past them), 4
  captures at a time, `GET {url}/json/<uuid>/info`, `/redirects`,
  `/hostnames` and `/urls` at once, 20 seconds a request, 90 seconds for the
  source. Kept per capture: its uuid, time (UTC), URL, title, final URL (the
  last redirect, else the URL), redirect chain, hostnames and the trackers
  of its loaded URLs (below), linked to `{url}/tree/<uuid>`. The trackers and
  hosts of the captures whose URL, redirects or final URL go through the
  name are gathered with their first and last capture and the number of
  captures; a capture of another site that merely loads the name is listed
  but not gathered. A failed route keeps the capture with the error, named
  `lookyloo <route>: …` (`HTTP 404`, `rate limited, retry after N`, `timed
  out`, `decode: …` for an HTML answer); only a failed search fails the
  source. With `HEIMDALL_LOOKYLOO_SUBMIT=true` and no capture younger than
  `HEIMDALL_LOOKYLOO_MAX_AGE`, `https://<fqdn>/` is submitted unlisted
  (`POST {url}/submit`), `GET {url}/json/<uuid>/status` is polled every 5
  seconds for 45 seconds at most, and the new capture is read first. Without
  `HEIMDALL_LOOKYLOO_URL` the source is not asked: `lookyloo` is `null` and
  `errors.lookyloo` is `lookyloo not configured`, which does not count in the
  status.

  Lookyloo only covers what someone captured: a name without capture, or a
  tracker absent from the captures read, proves nothing.

CT and subdomains search below the zone found by DNS when it lies within the
registrable domain, else below the registrable domain. RDAP, Cert Spotter,
ONYPHE and Lookyloo are called by `heimdall-api`, with the `User-Agent`
`heimdall`.

The trackers are identifiers read from the loaded URLs by one table of rules
(`internal/enrich/trackers.go`), query parameters parsed, never truncated,
sorted and unique:

| Kind       | ID                    | Read from |
|------------|-----------------------|-----------|
| `ua`       | `UA-<n>-<n>`          | `tid=` of `google-analytics.com/collect` and `/j/collect`; `googletagmanager.com/gtag/js?id=` |
| `ga4`      | `G-<id>`              | `tid=` of `…/g/collect`; `gtag/js?id=`, `gtag/destination?id=` |
| `gtm`      | `GTM-<id>`            | `googletagmanager.com/gtm.js?id=` only, never the `gtm=` parameter of other hits |
| `gads`     | `AW-<n>`              | `gtag/js?id=AW-`, `gtag/destination?id=AW-`; `/pagead/1p-user-list/<n>/`, `/pagead/conversion/<n>/`, `/pagead/viewthroughconversion/<n>/` on `doubleclick.net`, `googleadservices.com`, `google.<suffix>` |
| `fbpixel`  | `<n>`                 | `connect.facebook.net/signals/config/<n>`; `facebook.com/tr?id=` |
| `bing_uet` | `<n>`                 | `bat.bing.com/p/action/<n>` |
| `payment`  | `<provider>[:<merchant>]` | `paddle` (`paddle.com`, `paddle.js`; `vendor`, `seller`), `stripe` (`stripe.com`; a `pk_live_…` parameter), `fastspring` (`<store>.onfastspring.com`, `sites.fastspring.com/<store>`), `2checkout` (`2checkout.com`, `avangate.com`; `merchant`), `paypal` (`paypal.com/sdk/…`; `client-id`) |
| `clarity`  | `<id>`                | `clarity.ms/tag/<id>` |
| `crazyegg` | `<n>`                 | `script.crazyegg.com/pages/scripts/<a>/<b>.js` (and `versioned/tracking-scripts`), the digits joined |
| `hotjar`   | `<n>`                 | `hjid=` on `hotjar.com`; `static.hotjar.com/c/hotjar-<n>.js` |
| `yandex`   | `<n>`                 | `mc.yandex.ru/watch/<n>` |

A provider named without merchant is left out when a URL of the same
capture names its merchant.

| Variable                       | Default                        | Meaning                                                |
|--------------------------------|--------------------------------|--------------------------------------------------------|
| `HEIMDALL_CT_URL`              | `https://api.certspotter.com`  | Cert Spotter API                                       |
| `HEIMDALL_CERTSPOTTER_API_KEY` | empty                          | Cert Spotter key, sent as `Authorization: Bearer`      |
| `HEIMDALL_ONYPHE_API_KEY`      | empty                          | ONYPHE key, sent as `Authorization: bearer`; empty: no ONYPHE search |
| `HEIMDALL_ONYPHE_URL`          | `https://www.onyphe.io/api/v2` | ONYPHE API                                             |
| `HEIMDALL_ONYPHE_CT_WINDOW`    | `-since:48M`                   | OQL time function of the search                        |
| `HEIMDALL_LOOKYLOO_URL`        | empty                          | Lookyloo instance; empty: no Lookyloo search           |
| `HEIMDALL_LOOKYLOO_MAX_CAPTURES` | `10`                         | captures read, latest first                            |
| `HEIMDALL_LOOKYLOO_SUBMIT`     | `false`                        | submit the name when no capture is recent enough       |
| `HEIMDALL_LOOKYLOO_MAX_AGE`    | `720h`                         | age under which a capture is recent enough             |

`HEIMDALL_LOOKYLOO_URL` must be a name the container resolves: on a
tailnet, the full MagicDNS name (`http://citizen-lab.tail399dd.ts.net:5100`),
since the DNS of the containers does not resolve the short ones.

Without a key, the public Cert Spotter API limits the number of requests,
and each page of a search is one request: enrichments may then fail with
`cert spotter rate limited`.

Without a time function ONYPHE searches the last 30 days. `-since:48M` asks
for the last 48 months, as far as the license allows; `-monthago:N` would
be the single calendar month N months ago.

`POST /domains/{fqdn}/enrich` (session, `analyst`, CSRF token) starts the
enrichment in the background, for at most 2 minutes, and answers `202` with
the state of the job, as the VirusTotal jobs do: one job per name, `GET` on
the same path (`viewer`) answers its state or `{"state": "none"}`, a
finished job is kept an hour in memory. A finished job adds `{"status",
"counts": {"dns", "rdap", "ct", "subdomains", "lookyloo"}, "errors",
"summary"}`, `counts.lookyloo` being the captures read and the summary
saying `lookyloo: no capture` for none, which is not an error. 400
`invalid fqdn` unless `{fqdn}` is a valid name. The action is in the audit
log as `domain.enrich`.

Each source can fail alone: its error is kept and the others are stored.
The status is `ok`, `partial` (some sources failed) or `error` (all of
them), a Lookyloo not configured left out. The last enrichment of a name
replaces the previous one in the Postgres table `domain_enrich` (`fqdn`,
`fetched_at`, `status`, and the `dns`, `zone`, `rdap`, `ct`, `subdomains`,
`lookyloo` and `errors` JSON, a failed source being `NULL`; CT and Lookyloo
keep what they read before an error).

`GET /domains/{fqdn}/enrich/data` (`viewer`) returns the stored enrichment,
`{"fqdn", "fetched_at", "status", "dns", "zone", "rdap", "ct",
"subdomains", "lookyloo", "errors", "graph"}`, 404 before the first one.
`lookyloo` is `{"instance", "captures_found", "captures_read",
"truncated", "submitted", "captures": [{"uuid", "time", "url", "title",
"final_url", "redirects", "hostnames", "trackers": [{"kind", "id"}]}],
"trackers": [{"kind", "id", "first_seen", "last_seen", "captures"}],
"hosts": [{"name", "first_seen", "last_seen"}]}`, `submitted` being the
uuid of the capture this enrichment asked for, else `null`. `graph` is a
graph as in Graph view, at most 500 nodes: the name, its addresses (edges
`A`/`AAAA`, CDN addresses left out and counted), its CNAME and MX targets
(`CNAME`, `MX`), the NS set of its zone (`NS_SET`, 2 nameservers at least),
its subdomains (`SUB`), the names of the certificates (`CERT`, a wildcard
as its base name), the host of the final URL of each capture going through
the name when it differs (`REDIRECT`, unlike `CNAME` an HTTP redirect seen
by Lookyloo) and its trackers (`TRACKER`, `tracker` nodes).

`/domains/{fqdn}` has an "Enrichment" section after VirusTotal: the date,
the resolver, the records, the zone (SOA, NS), RDAP, the certificates
("Certificate Transparency": count, full SHA-256, issuer, validity,
revocation, names, sources; "—" for the SHA-256 of an enrichment stored
before Cert Spotter, and for the sources of one stored before ONYPHE), the
subdomains, linked to their page, the Lookyloo captures (time, title linked
to the capture on the instance, URL and final URL, redirect chain) and
their trackers (kind, full id, first and last capture, captures), and the
error of each failed source. Its
"Enrich" button (`analyst`) starts the job, follows it with
`web/static/vtjob.js` and reloads the page at the end.

### Link to campaign

`POST /domains/{fqdn}/link` (session, `analyst`, CSRF token) puts a name in
a campaign. The body is `{"campaign": <id>}` or `{"new_campaign": {"name",
"description"}}`, exactly one of them (400 `campaign or new_campaign`).

- `new_campaign` is created first, with the checks of `POST /campaigns`
  (400 `name is required`, 409 `campaign exists`), audited as
  `campaign.create`. An unknown `campaign` is 404 `unknown campaign`.
- A name outside the watchlist is added in the campaign with the default
  interval of 300 seconds (`domain.import`); a watched name is moved to it
  (`domain.update`), or left as it is when it already belongs to it.

The answer is `{"fqdn", "campaign": {"id", "name"}, "action":
"added"|"moved"|"unchanged", "created_campaign"}`.

The "Link to campaign" button of the domain page (`analyst`, next to
"Enrich") opens a dialog with three choices: the current campaign (that of
the name, absent when it has none), another campaign, or a new one (name,
description). The page reloads once the name is linked.
`web/static/link.js` drives the dialog on the domain and graph pages.

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
GET    /api/campaigns/{id}/analytics[?days=30|90]   analytics of a campaign, see Campaign analytics
GET    /api/events?since=&until=&kind=&campaign=&domain=&limit=
GET    /api/pivots/{fqdn}[?limit=]  names sharing an A/AAAA value or the whole NS set, with overlap, see below
GET    /api/graph/domain/{fqdn}[?depth=&subs=0]   graph around a name, see Graph view
GET    /api/graph/campaign/{id}[?subs=0]   graph of a campaign, 404 if unknown, see Graph view
GET    /api/graph/ip/{ip}           graph of an address, 400 if not one, see Graph view
GET    /api/graph/ns/{set}          domains with exactly this NS set (comma-separated), see Graph view
GET    /api/search?q=&limit=        watchlist, pdns names and pdns values, see below
GET    /api/correlations[?min_score=&kinds=&since=]   links between campaigns, see Cross-campaign correlation
GET    /api/correlations/{a}/{b}[?kinds=]   links of a pair of campaigns, 404 if one is unknown
GET    /api/correlations/graph[?min_score=&kinds=&expand=a,b]   graph of the campaigns and their links
GET    /api/vt/ip/{ip}              names VirusTotal saw on an address, cache only, see below
GET    /api/vt/budget               VirusTotal lookups of the UTC day
POST   /api/vt/enrich/domain/{fqdn}[?depth=]   analyst, enrichment job, see VirusTotal passive DNS
GET    /api/vt/enrich/domain/{fqdn} state of the job
POST   /api/vt/enrich/campaign/{id} analyst, enrichment job, 404 if unknown
GET    /api/vt/enrich/campaign/{id} state of the job
POST   /api/vt/enrich/ip/{ip}[?depth=]   analyst, enrichment job of an address, 400 if not one
GET    /api/vt/enrich/ip/{ip}       state of the job
POST   /api/enrich/domain/{fqdn}    analyst, domain enrichment job, see Domain enrichment
GET    /api/enrich/domain/{fqdn}    state of the job
GET    /api/domains/{fqdn}/enrich   last enrichment and its graph, 404 if none
POST   /api/domains/{fqdn}/link     analyst, {"campaign"} or {"new_campaign": {"name", "description"}}, see Link to campaign
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

`POST /api/enrich/domain/{fqdn}`, `GET /api/enrich/domain/{fqdn}`, `GET
/api/domains/{fqdn}/enrich` and `POST /api/domains/{fqdn}/link` are the
bearer token routes of `/domains/{fqdn}/enrich`, `/domains/{fqdn}/enrich/data`
and `/domains/{fqdn}/link`, and share their jobs.

`POST /api/vt/enrich/domain/{fqdn}[?depth=]` and `POST
/api/vt/enrich/campaign/{id}` (`analyst`) start the enrichment of
`POST /graph/.../vt`, and `POST /api/vt/enrich/ip/{ip}[?depth=]` that of
`POST /rdata/{ip}/vt`; they answer `202` with the state of the job. `GET`
(`viewer`) answers that state, or `{"state": "none"}`. Both families share
the jobs: `/api/vt/enrich/ip/{ip}` and `/rdata/{ip}/vt` see the same one.

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
domain or IP node expands it in place: the page reads its graph
(`/graph/domain/{fqdn}/data`, depth 1, or `/graph/ip/{ip}/data`, with
`?vt=1` when the page shows VirusTotal or the node was enriched from its
menu) and adds the nodes and edges it lacks around the node, at most 50 new
nodes ("+N not shown" beyond, "no neighbours" when nothing is new). A domain
node also brings the graph of its last enrichment
(`/domains/{fqdn}/enrich/data`, none before the first one). Clicking
an NS set node expands it the same way with the domains whose current NS
set is identical (`/graph/ns/{set}/data`). An expanded node gets a thicker
border and is not read again. A group node opens the list of its members
(see below); other nodes do nothing on click. The context
menu (right click) of a domain or IP node has "Open page" (`/domains/{fqdn}`
or `/rdata/{ip}`). For an `analyst`, that of a domain node also has
"Enrich", which starts the domain enrichment, follows it in the graph bar
and adds the graph of the enrichment around the node, and "Link to
campaign", which opens the dialog of the domain page, its current campaign
being that of a campaign graph or of the name of a domain graph; a linked
node is drawn watched, and a campaign created there is offered at once in
the dialog. The graph opens
simplified: nodes with the same neighbours are grouped into one, which the
Simplify panel of the side rail turns off or combines with its other rules.

An edge that runs through a grouped node is drawn by Pivotick as a synthetic
edge standing for the real ones. It keeps the colour of their kind when they
share one; when their kinds differ it is dashed grey (`MIXED`). Its tooltip,
and the properties panel, give the real path, one line per edge: `from → to
(KIND)`, with the first and last day seen of a `VT` edge. Every edge kind of
Heimdall has its own colour (`A`/`AAAA` as addresses, `CNAME` grey,
`NS_SET` as NS sets, `MX`, `CERT`, `SUB` teal, `REDIRECT` brown, `TRACKER`
orange as `tracker` nodes, `VT`), none the default Pivotick blue. Between
two nodes joined by edges of several kinds, the strongest is drawn: `SUB`,
`TRACKER`, `CNAME`, `REDIRECT`, `A`/`AAAA`, `MX`, `NS_SET`, `CERT`, `VT`.

Clicking a group node opens a side panel over the graph, which stays usable:
the label of the group and its number of members, a filter on the labels
(case-insensitive, as one types), and the members sorted by type then
label, each with its type (`domain`, `ip`, `nsset`, `vt`), a red dot when
watched, and a "page" link to its page in a new tab. Clicking a member
opens the groups that hide it, selects it and centres the graph on it (its
page opens instead if that fails). The × button or Escape closes the panel.

The "VirusTotal" box is remembered per graph page (its path, as
`/graph/campaign/4`) in the browser's `localStorage`. A page opened without
`vt` in its URL reloads once with `vt=1` when the box was last checked
there; a `vt` in the URL wins and becomes the remembered choice. Without
`localStorage`, nothing is remembered.

The browser reads the graph from `/graph/domain/{fqdn}/data` and
`/graph/campaign/{id}/data`, which return the
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

Both then add, for each domain of the graph with a stored enrichment, a
`TRACKER` edge to each tracker of its Lookyloo captures: two domains sharing
an identifier meet on its `tracker` node.

Both then add subdomains, unless `?subs=0`:

- each domain of the graph with a stored enrichment (read in one Postgres
  query) adds the names strictly below it from that enrichment: its passive
  DNS subdomains, last seen first, then the names of its certificates, a
  wildcard as its base name; at most 50 per domain (`"truncated": true` when
  more are left out), within the 500 nodes of the graph. A name whose
  registrable domain lies above the enriched domain is left out;
- each domain node, new ones included, gets one `SUB` edge from its closest
  ancestor among the domain nodes, climbing label by label up to its
  registrable domain (public suffix list), never above it: `a.b.x.example`
  hangs from `b.x.example` when present, else from `x.example`.

The pages have a "Subdomains" box, checked by default, which reloads the
graph with `subs=0` when unchecked; a domain node expanded on click then
reads its graph with `subs=0` too, and the `SUB` edges of an expansion are
kept like the others. The VirusTotal enrichment of a graph ("Enrich with
VT") looks up the graph without them.

`/graph/ip/{ip}` (data at `/graph/ip/{ip}/data`, `/api/graph/ip/{ip}` under
a bearer token), linked as "Graph" from `/rdata/{ip}` and from the context
menu of IP nodes, centres on an address: its node first, then the names
Heimdall's passive DNS saw resolve to it (edges `A`/`AAAA`, at most 1000
records read). 400 if `{ip}` is not an address. A CDN address is not
drawn: the page says "CDN address" and the JSON is empty with
`"excluded_cdn": 1`. Its "Enrich with VT" enriches the address at depth 2.

`/api/graph/ns/{set}` (`/graph/ns/{set}/data` under the session cookie)
centres on an NS set: `{set}` is its nameservers separated by commas, as in
the id of an `nsset` node after `ns:`, read lowercased, without a final dot,
sorted and unique. 400 `invalid NS set` unless it holds 2 to 16 valid names.
The graph holds the `nsset` node (`href` empty), then the names whose current
NS set (NS records seen in the last 7 days) is exactly that one, each with an
`NS_SET` edge to it, at most 500 names read (`"truncated": true` at 500).

All but the NS set graph take `?vt=1` for the cached VirusTotal resolutions,
see VirusTotal passive DNS; on an IP graph, the names VirusTotal saw on the
address.

A node is `{"id", "kind", "label", "watched", "campaign", "href",
"source"}`:

| kind     | id                  | label         | href              |
|----------|---------------------|---------------|-------------------|
| `domain` | `d:<fqdn>`          | the name      | `/domains/<fqdn>` |
| `ip`     | `ip:<value>`        | the value     | `/rdata/<value>`  |
| `nsset`  | `ns:<ns1>,<ns2>`    | `ns1, ns2`    | `/domains/<zone>` |
| `tracker`| `t:<kind>:<id>`     | `<kind> <id>` | empty             |

The nameservers of an `nsset` are sorted. `watched` and `campaign` come from
the watchlist. An edge is `{"from", "to", "kind"}`, `kind` being `A`, `AAAA`,
`CNAME`, `NS_SET`, `SUB` (parent to subdomain), `TRACKER` or, with
`first_seen` and `last_seen`, `VT`; the graph of an enrichment adds `MX`,
`CERT` (dashed) and `REDIRECT`.
Nodes and edges are unique. CDN addresses are left out
and counted in `excluded_cdn`. A graph stops at 500 nodes, the domains of the
request first, with `"truncated": true`; it is also set when a pivot query
reaches its limit of 500 rows.

## Campaign analytics

`/campaigns/{id}/analytics`, linked as "Analytics" from the campaign page,
is a dense workspace over the last 30 or 90 days (`?days=`, 30 unless
90): indicator tiles with a daily sparkline, a stacked timeline of events by
kind (click a kind in the legend to hide it, drag across the chart to select
a range), a liveness matrix of every domain per day, shared addresses and NS
sets, the latest events and, with VirusTotal, leads from its cache. A range
selected on the timeline filters the events and new addresses and dims the
matrix columns outside it. Hovering a shared address or NS set highlights its
domains in the matrix; clicking a domain, an address or a zone opens a side
panel (Escape closes it). The matrix renders only its visible rows past 300
domains. The page draws SVG from JSON with `web/static/analytics.js` and
`web/static/analytics.css`, under the same CSP as the other pages.

The browser reads `/campaigns/{id}/analytics/data?days=` (session, `viewer`),
which returns the same JSON as `/api/campaigns/{id}/analytics?days=` (Bearer,
`viewer`), 404 for an unknown campaign. Each ClickHouse query is bounded by
the window and the campaign's domains, about ten queries in all. Days are UTC
dates, `YYYY-MM-DD`, oldest first.

- `days`: 30 or 90.
- `header`: `{"campaign": {"id", "name", "family", "description"},
  "domains", "enabled", "last_measured_at", "vt"}`; `last_measured_at` is
  the latest A/AAAA observation of the window, `vt` is `{"budget",
  "used_today", "remaining"}`, `null` without a VirusTotal key.
- `kpis`: `resolving`, `nxdomain`, `failing`, `unmeasured` (domains in each
  liveness state), `active_ips` (distinct non-CDN addresses answered),
  `cdn_share` (share of CDN addresses among those answered, 0 to 1),
  `ns_sets` (distinct current NS sets of at least 2 nameservers among the
  zones of the campaign, counted on the days their period covers) and
  `events_7d` (events of the last 7 days), each `{"value", "series"}`: one
  value per day of the window, `value` being that of today.
- `timeline`: `{"kinds", "days": [{"day", "counts": {"<kind>": n}}]}`.
- `liveness`: `{"days", "rows": [{"fqdn", "enabled", "first_seen",
  "cells"}]}`, one cell per day: the last A or AAAA observation of the domain
  that day, answers without data aside, gives `ok` (NOERROR), `nx`
  (NXDOMAIN), `fail` (TIMEOUT, SERVFAIL, REFUSED, NETERR or another error)
  or `none` (no observation). Rows are sorted by today's state (`ok`,
  `fail`, `nx`, `none`), then `first_seen`, the first passive DNS record of
  the name, `null` if none.
- `clusters`: `{"ips", "ns_sets", "new_ips_per_day", "excluded_cdn"}`.
  `ips` are the addresses answered for at least two domains in the window,
  `{"ip", "domains", "first_seen", "last_seen"}` (days), most shared first,
  at most 30. `ns_sets` are the current NS sets (at least 2 nameservers)
  held by at least two zones of the campaign, `{"ns", "zones", "domains"}`.
  `new_ips_per_day` lists for each day `{"day", "ips"}` the addresses of the
  window first seen in passive DNS that day, under any owner. CDN addresses
  are left out of all of them and of `active_ips`, and counted in
  `excluded_cdn`.
- `events`: the 200 latest events of the window tagged with the campaign or
  about one of its domains, as in `/api/events`.
- `vt_leads`: the names VirusTotal saw on the campaign's non-CDN addresses
  that are not in the watchlist, `{"host_name", "ips", "last_seen"}`, most
  shared addresses then most recent first, at most 50, from the cache only;
  `null` without a VirusTotal key. An `analyst` adds one to the campaign
  with "Add to campaign" (`POST /campaigns/{id}/domains`, which now returns
  to the page it was posted from).

The side panel reads `/entity/domain/{fqdn}` (session, `viewer`):
`{"fqdn", "domain", "first_seen", "last_seen", "current", "events", "vt",
"href", "graph"}`, with `domain`, `current` and `vt` as in
`/api/domains/{fqdn}/detail`, the first and last passive DNS sighting of
the name and its 20 latest events of the last 90 days; and
`/entity/ip/{ip}`: `{"ip", "cdn", "names", "truncated", "vt", "href"}`,
`names` being the passive DNS owners of the address as in `/api/search`,
`vt` as `/api/vt/ip/{ip}` (`null` without a VirusTotal key), 400 if `{ip}`
is not an IP address.

## Cross-campaign correlation

A link joins two watched domains of two different campaigns through a piece
of infrastructure they share. Domains outside any campaign and pairs within
one campaign give no link. Only what Postgres and ClickHouse already hold is
read; nothing is looked up.

| Kind     | Weight   | Evidence |
|----------|----------|----------|
| `cert`   | 1.0      | the same `cert_sha256` among the certificates of the stored enrichments (`domain_enrich.ct`); the value is the full SHA-256, the period the validity of the certificate |
| `tracker`| 0.6–1.0  | the same tracker (kind, id) among the Lookyloo trackers of the stored enrichments (`domain_enrich.lookyloo`); the value is `<kind>:<id>`, the period when both were captured with it. 1.0 for `gads`, `fbpixel`, `bing_uet` and a `payment` with merchant id, 0.9 for `gtm`, `ga4`, `ua`, 0.6 for the other analytics (`clarity`, `crazyegg`, `hotjar`, `yandex`); a `payment` without merchant id is left out |
| `ns_set` | 0.9      | the same current NS set (at least 2 nameservers, strictly equal) of two different zones |
| `ip`     | 0.8 / n  | the same non-CDN A or AAAA value in passive DNS over overlapping periods; n counts the watched domains, of any campaign or none, that held the address during the overlap, and the link is dropped past n = 20 (shared hosting) |
| `cname`  | 0.7      | the same CNAME target, unless a known CDN suffix or its chain in passive DNS ends on a CDN address |
| `mx`     | 0.5      | the same MX exchange, unless a large mail provider |
| `soa`    | 0.4      | the same SOA (mname, rname) of two different zones, unless the default of a large DNS provider |
| `rdap`   | 0.3      | the same registrar (IANA id, else name) and registrations less than 48 h apart, of two different registrable domains (`domain_enrich.rdap`) |
| `vt`     | 0.3      | a domain VirusTotal saw (`vt_resolutions`) on a non-CDN address another domain held in passive DNS, unless more than 20 watched domains held it |

The weights are constants (`WeightTracker*` and `TrackerWeight` for the
trackers) and the exclusions Go variables at the top of
`internal/correlate/correlate.go`: `CNAMEProviders` (cloudfront.net,
fastly.net, akamaiedge.net, edgekey.net, b-cdn.net, azureedge.net, cdn77.org,
cloudflare.net…), `MXProviders` (google.com, googlemail.com, outlook.com,
zoho.\*, yandex.\*, mail.ru, icloud.com…) and `SOADefaults`
(ns.cloudflare.com, dns.cloudflare.com, awsdns-\*, azure-dns.\*,
domaincontrol.com, registrar-servers.com…). A pattern matches a name by
suffix or, ending in `.*`, by the first label of its registrable domain.
A value held by more than 100 watched domains is left out as too common.

The score of a pair of campaigns is 1 − Π(1 − w) over the distinct values
(kind, value) its links share, each at the highest weight of its links,
at most 1: a certificate gives 1, an NS set and an MX 0.95.

`heimdall-api` computes the links a minute after start-up, then every hour,
within 2 minutes: a longer run is abandoned and logged, leaving the history
and the previous result. Postgres table `correlation_links` keeps the
history, one row per (kind, value, domain_a, domain_b), `domain_a <
domain_b`: a new link gets `first_seen`, every run that finds it again sets
`last_seen` and its campaigns, and a link no longer found keeps its
`last_seen`. Scores and weights are those of the last run, kept in memory:
until the first run after a restart, `computed_at` is `null` and there is no
pair.

`/api/correlations` returns `{"campaigns": [{"id", "name"}], "pairs": [{"a",
"b", "score", "counts", "first_seen", "last_seen"}], "new_links",
"computed_at"}`: pairs with `a < b`, highest score first, `counts` the
distinct values shared per kind, `first_seen` the first sighting of their
oldest current link; `new_links` the links of the history first seen since
`since` (7 days ago by default, same syntax as `/api/events`), at most 500,
as `{"kind", "value", "domain_a", "campaign_a", "domain_b", "campaign_b",
"first_seen", "last_seen"}`. `min_score` (0 to 1) keeps the pairs scoring at
least that much, `kinds` (comma-separated) the links of those kinds, for the
score too. A bad parameter is a 400.

`/api/correlations/{a}/{b}` returns `{"a", "b", "score", "counts",
"evidence", "past", "computed_at"}`: `evidence` the current links of the
pair, highest weight then latest `first_seen` first, as `{"kind", "value",
"domain_a", "campaign_a", "domain_b", "campaign_b", "weight", "period",
"first_seen", "last_seen"}`, `period` (`{"first", "last"}`) being when both
domains held the value, the validity of the certificate or the two
registration dates, `null` otherwise; `past` the links of the history no
longer found, latest `last_seen` first.

`/api/correlations/graph` is a graph as in Graph view: a `campaign` node per
linked campaign and an edge per kind of link between two of them, `kind`
being the kind of link. `expand=a,b` adds the domains of the links between
`a` and `b` (`member` edges to their campaign) and the values they share
(`ip`, `nsset`, `domain` for a CNAME target or an MX exchange, `cert` labelled
with the full SHA-256, `tracker` as in Graph view, `soa`, `registrar`), 404
if a campaign is unknown.

`/correlations`, linked as "Correlations" in the navigation (`viewer`), shows
the matrix of the linked campaigns (each cell coloured by score, with the
values per kind; click one for the links of the pair, `?a=&b=` opens it), a
Pivotick graph tab (edge colour per kind, click an edge to expand its pair),
filters on the minimum score and the kinds, and the links first seen in the
last 7 days. The browser reads `/correlations/data`,
`/correlations/{a}/{b}/data` and `/correlations/graph/data` (session), which
return the same JSON as the `/api/correlations` routes. The analytics page of
a campaign has a "Linked campaigns" card with the 5 campaigns of highest
score and a link to each pair.

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
   options or callbacks used by `graph.js` (`UI.mode`, `UI.editors`,
   `UI.notes`, `UI.simplify.rules`, `simulation.useWorker`,
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
