# S.T.A.R.E architecture

## Backend

```
server/
  cmd/
    stare-api/        HTTP API (main.go, handlers, middleware)
    stare-cli/        interactive terminal scanner
    stare-diag/       source diagnostics
  people/             human-OSINT pipeline
    people.go         detect → collectors → normalize → Actor
    profile.go        profile URL parsing + OpenGraph metadata
    match.go          semantic matching (name/bio/avatar/links)
    free_profiles.go  GitHub, GitLab, Keybase, Gravatar
    free_breach.go    XposedOrNot, Hudson Rock, GitHub name search
    emailrep.go       EmailRep free tier
    collectors.go     Sherlock/Maigret/Holehe/Blackbird/Phone
    extra_collectors.go Blackbird JSON, GHunt, PhoneInfoga, WhatsMyName
  scanner/            network/domain scanning
    engine.go         RunFullScan orchestration
    source.go         Source registry + batch enrichment + limiter
    pd_tools.go       subfinder/httpx/naabu/tlsx/katana adapters
    threat_feeds.go   OpenPhish, Spamhaus DROP, Tor exits, KEV/EPSS, buckets
    wildcard.go       wildcard DNS detection
    ports.go/dns.go   fallback scanners
  tests/              external Go tests (package tests)
  Dockerfile          lean runtime
  Dockerfile.osint    full OSINT runtime (CLI tools; PD tools via WITH_PD_TOOLS=1)
```

## Scan pipeline (`RunFullScan`)

1. **Passive subdomains** (parallel): crt.sh, crt.name, RapidDNS, HackerTarget,
   OTX, URLScan, TLSCC, subfinder. Each subdomain stores `subdomain_sources`
   and `subdomain_confidence`.
2. **DNS/WHOIS/technology** in parallel.
3. **Wildcard DNS**: three random labels; resolved answers form `wildcard_ips`.
4. **Resolution**: parallel DNS for all subdomains, dedupe IPs. A name whose
   addresses are entirely inside `wildcard_ips` gets `subdomain_wildcard=true`;
   `high` confidence requires 2+ sources **and** a non-wildcard resolution.
   Private/bogon addresses stay in `ips` but are listed in `private_ips` and are
   never passed to active checks (SSRF barrier).
5. **Enrichment sources** (`Source` registry): abuse.ch, IPinfo, OSV, Shodan,
   GreyNoise, AbuseIPDB — batch by public IPs only.
6. **Active checks** (ProjectDiscovery CLI, optional; public hosts only):
   - `httpx`: HTTP status/title/tech/TLS/CDN/favicon → `http[]`
   - `tlsx`: certificate CN/SAN/expiry → `tls[]`; runs over **all hosts with
     open 443**, not just the apex, then merges TLS from httpx
   - `katana`: crawl endpoints → `endpoints[]`
   - `naabu`: top-1000 TCP ports, merged with fallback 7 ports; fallback scans
     IPs in parallel (8 IPs × 40 workers)
   - banners: real TCP/TLS read (HTTP request for web ports, first line only)
   - cloud buckets: S3/GCS/Azure name checks → `cloud_buckets[]`
   - threat feeds: OpenPhish/Spamhaus/Tor exits → `threat_hits[]`
7. **Host model**: `hosts[]` joins IPs, wildcard/private flags, ports, best HTTP
   probe and TLS certs into one record.
8. **Nuclei** (parallel, optional) + CISA KEV/EPSS enrichment.

Subdomains are normalized/validated (`normalizeSubdomain`), endpoints are
filtered to in-scope HTTP(S) URLs (`filterEndpoints`), and `CheckEmailDNS`
queries SPF/DMARC/CAA/DNSSEC over DoH. `artifacts` falls back from HTTPS to
HTTP and parses `Disallow`/`Allow`/`Sitemap`. `findings[]` is the unified
reporting layer: Nuclei (local/high), Shodan CVEs (observed/medium), DNS hygiene
and public buckets, each with severity/confidence/evidence; `vulnerabilities[]`
remains the raw Nuclei output. All parallel slices are sorted
before output: subdomains, sources, IPs, observations, HTTP/TLS,
vulnerabilities, buckets and errors.

`RunFullScan` returns `scan_id`, `schema_version` and `scan_meta`:
`tools` (`ran|missing|error|skipped`, duration, input/items, truncation) and
`coverage` (attempted/succeeded/failed/skipped per stage). This makes an empty
`vulnerabilities`/`tls` block distinguishable from “not checked”. The People
pipeline exposes the same idea via `collectors[]`, CLI `versions`, `scan_id`
and `duration_ms`.

People scoring is evidence-based: source weights + `confirmed/blocked/unknown`
+ profile completeness; `Actor` is a handle cluster with `signals[]`
(`same_name`, `same_avatar`, `shared_link`, `profile_match`) and becomes `high`
only with 2+ independent signals. Sensitive platforms are flagged, hidden by
default and excluded from the actor tier.

Coverage is extended by a declarative registry (`data/platforms.json`:
status/json_path/body_contains detectors), `{handle}.<host>` pattern checks and
variant expansion. `PEOPLE_DEEP=1` switches Maigret to `--all-sites`, removes
the WhatsMyName slice and verification limit; `PEOPLE_ALLOW_NSFW=1` is a
separate opt-in for adult platforms. Discovery adds `mentions[]` (urlscan,
HN Algolia, grep.app, optional Brave/SerpAPI) without turning them into
accounts. Post-processing adds Wayback snapshots (`archived_url`) and sha256
avatar hashes for actor correlation; both only fetch public URLs.

All external tools are optional: missing binary = source skipped, scan continues.
Paths: `SUBFINDER_BIN`, `HTTPX_BIN`, `NAABU_BIN`, `TLSX_BIN`, `KATANA_BIN`.

## Frontend

```
client/src/assets/
  features/graph/     GraphVisualizer, DataTable, observations.js, benchData.js
  features/people/    client-side input type detection
  pages/              Login, Start, Main screens
tests/frontend/
  unit/               Node test runner for pure JS
  e2e/                Playwright scenarios
```

Graph renderer: canvas by default, optional WebGL (`VITE_GRAPH_RENDERER`),
fcose layout, progressive disclosure, confidence/verified filters, minimap.
