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
   and `subdomain_confidence` (high = 2+ sources).
2. **DNS/WHOIS/technology** in parallel.
3. **Resolution**: parallel DNS for all subdomains, dedupe IPs.
4. **Enrichment sources** (`Source` registry): abuse.ch, IPinfo, OSV, Shodan,
   GreyNoise, AbuseIPDB — batch by all IPs.
5. **Active checks** (ProjectDiscovery CLI, optional):
   - `httpx`: HTTP status/title/tech/TLS/CDN/favicon → `http[]`
   - `tlsx`: certificate CN/SAN/expiry → `tls[]`
   - `katana`: crawl endpoints → `endpoints[]`
   - `naabu`: top-1000 TCP ports, merged with fallback 7 ports
   - cloud buckets: S3/GCS/Azure name checks → `cloud_buckets[]`
   - threat feeds: OpenPhish/Spamhaus/Tor exits → `threat_hits[]`
6. **Nuclei** (parallel, optional) + CISA KEV/EPSS enrichment.
7. **Wildcard DNS** detection before trusting subdomain brute results.

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
