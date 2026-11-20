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

## `source_test.go`

| Тест | Сценарий | Ожидание |
|---|---|---|
| `TestFetchBatchDeduplicates` | targets: дубль IP, пустая строка, второй IP | Ровно 2 вызова и 2 observation |

## `temp_test.go` (build tag `integration`)

Сетевые smoke-тесты (`crt.sh`, DNS, brute, ports). Не входят в обычный CI.
