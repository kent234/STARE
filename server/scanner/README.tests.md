# Internal tests: `server/scanner`

Запуск: `cd server && go test ./scanner -count=1`.

## `abusech_test.go`

| Тест | Сценарий | Ожидание |
|---|---|---|
| `TestAbuseCHSources_Mock` | Мок-ответы URLhaus CSV / ThreatFox array&object / Feodo (subdomain, IP, hostname, no-match) | Нужное число Observation, корректные source/confidence, валидный JSON payload |
| `TestAbuseCHSource_PostAuthHeader` | Мок ThreatFox API | POST, заголовок `Auth-Key`, тело `{"query":"get_iocs","days":7}`, 1 finding |
| `TestIndicatorMatches` | Домен/IP/URL/порт/пустая цель | Совпадение только для цели и её поддоменов; IPv6/порт обрабатываются корректно |

## `enrich_test.go`

| Тест | Сценарий | Ожидание |
|---|---|---|
| `TestIPinfoSource_Mock` | IP, домен→2 IP, ошибка DNS, HTTP 500 | 1/2 observation, ASN `AS15169`; ошибки изолируются |
| `TestOSVSource_Mock` | CVE, пакет с версией, пустой ответ, домен | 1/1/0/0 observation и 0 запросов для неподдерживаемого домена |
| `TestParseOSVTarget` | CVE/GHSA/npm/PyPI/bare/пусто | Корректный разбор, без неоднозначных целей |

## `p1_test.go`

| Тест | Сценарий | Ожидание |
|---|---|---|
| `TestShodanSource_Mock` | IP/домен/404/500, проверка ключа | 1/2/0 observation; ключ в query; ошибка изолируется |
| `TestGreyNoiseSource_Mock` | Классификация/404/429 | 1/0 observation; 429 → ошибка источника |
| `TestAbuseIPDBSource_Mock` | IP/домен→2 IP/429 | 1/2 observation; заголовок `Key`; 429 → ошибка |

## `truth_test.go`

| Тест | Сценарий | Ожидание |
|---|---|---|
| `TestIsPublicIP` | публичные IPv4/IPv6, RFC1918, loopback, CGNAT, TEST-NET, benchmark, ULA | приватные и bogon отсекаются |
| `TestDetectWildcard` | одинаковые/ротирующиеся ответы, NXDOMAIN, IP-цель | wildcard + отсортированный `wildcard_ips`; для IP проверка не запускается |
| `TestSubdomainConfidence` | 2/1/0 источников, нет резолва, wildcard | high только 2+ источника + резолв + не wildcard |
| `TestActiveProbeTargets` | публичный/приватный/смешанный/нерезолвящийся поддомен | активные проверки только без приватных адресов |
| `TestUniqueSortedIsSorted` / `TestSortHelpersDeterministic` | неотсортированные входы | стабильный порядок между прогонами |

## `hosts_test.go`

| Тест | Сценарий | Ожидание |
|---|---|---|
| `TestBuildHosts` | IP/ports/HTTP/TLS/wildcard | единая host-модель собирается без потерь |
| `TestBestHTTPProbePrefersHTTPS200` | http 403 + https 200 | выбран https/200 |
| `TestCertsForHostSAN` | сертификат с `*.example.com` | привязан к поддомену |
| `TestTLSCandidateHosts` | 443 только у части хостов | tlsx получает только релевантные |
| `TestGrabBannerPlain` / `TestIsTLSPort` | SSH-баннер, порты 443/8443 | первая строка без склейки, TLS-порты распознаны |

## `hygiene_test.go`

| Тест | Сценарий | Ожидание |
|---|---|---|
| `TestNormalizeSubdomain` | схема/порт/wildcard/`u003e`/чужой домен | валидные нормализуются, мусор отброшен |
| `TestFilterEndpoints` | in-scope, static, `$%7B...%7D`, w3.org, дубли | остаются только рабочие API-URL |
| `TestParseRobots` / `TestFetchArtifactsBase` | robots с Allow/Sitemap, favicon | поля и MD5 заполнены |
| `TestCheckEmailDNS` | 2×SPF, DMARC p=none, CAA, DNSSEC off | PermError и issues корректны |

## `meta_test.go`

| Тест | Сценарий | Ожидание |
|---|---|---|
| `TestNewScanID` | два вызова | 24 hex-символа, значения различаются |
| `TestNewScanMetaMaps` | tools/coverage | карты инициализированы, JSON содержит статусы и счётчики |
| `TestToolStatusJSONOmitsZeroes` | `ToolStatus{ran, items:3}` | пустые duration/error не попадают в JSON |

## `source_test.go`

| Тест | Сценарий | Ожидание |
|---|---|---|
| `TestFetchBatchDeduplicates` | targets: дубль IP, пустая строка, второй IP | Ровно 2 вызова и 2 observation |

## `temp_test.go` (build tag `integration`)

Сетевые smoke-тесты (`crt.sh`, DNS, brute, ports). Не входят в обычный CI.
