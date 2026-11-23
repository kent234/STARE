# Internal tests: `server/people`

Эти тесты остаются в пакете `people`, потому что проверяют unexported-функции.

## `people_test.go` (перенесён в `server/tests`) — см. `server/tests/README.md`

## `profile_test.go`

| Тест | Сценарий | Ожидание |
|---|---|---|
| `TestParseProfileURL` | Разбор ссылок VK/Instagram/GitHub/X/Telegram/YouTube/Reddit/OK | platform+handle, отсев `/p/`, доменов и текста |
| `TestDetectProfileURL` | `https://vk.com/durov` | `KindProfileURL` |
| `TestProfileMetaParsing` | HTML с OG-тегами и внешней ссылкой | Title/bio/avatar извлечены, HTML-entity раскодированы, ссылка сохранена |
| `TestNormalizeProfileFields` | Observation профиля с name/bio/avatar/links | Все поля попадают в Account |

## `match_test.go`

| Тест | Сценарий | Ожидание |
|---|---|---|
| `TestSemanticScoreNameAndHandle` | Одинаковые имя/bio/ссылка, verified | score ≥70 |
| `TestSemanticScoreRejectsDifferentPerson` | Тот же handle, но другое имя/bio | score <50 (не склеивать) |

## `quality_test.go`

| Тест | Сценарий | Ожидание |
|---|---|---|
| `TestNormalizeCanonicalAndRegistrations` | `GitHub` + `GitHub (user)`, Holehe registration | Один канонический github-аккаунт, 2 source; регистрация отдельно |
| `TestVerifiedScoresHigher` | verified vs unverified | verified score выше |
| `TestNormalizeVerificationAndCanonicalURL` | API-ссылка пришла раньше профиля; page markers | canonical = `/member/...`, API в `evidence_urls`, existence ещё `unknown` |
| `TestNormalizeProviderIsConfirmed` | Microsoft provider observation | `provider=true`, `existence=confirmed`, без HTTP |
| `TestCanonicalURLRanking` | профиль vs API | профиль побеждает независимо от порядка |

## `meta_test.go`

| Тест | Сценарий | Ожидание |
|---|---|---|
| `TestRunEmptyTargetHasMeta` | `Run("")` без сети | `schema_version`/`scan_id`/`duration_ms`, ошибка пустой цели |
| `TestCollectorRequirement` | CLI/HTTP коллекторы | только CLI требуют бинарник, HTTP — всегда доступны |
| `TestCollectorVersionsMissingBinary` | пустой PATH | карта версий не заполняется пустышками |
| `TestBinaryVersion` | скрипт `tool 1.2.3` | версия из первой строки |

## `verify_test.go`

| Тест | Сценарий | Ожидание |
|---|---|---|
| `TestVerifyAccountURLs` | 200 title/og, page marker, soft-404, login-wall, 403, 404, 500, provider | confirmed/http, blocked/low, removed[], provider без HTTP |
| `TestVerifyNetworkErrorIsUnknown` | закрытый порт | `unknown`, `http_error`, не verified |
| `TestEvaluateProfilePage` | og:title, JSON API, soft-404 body, negative marker, login redirect | корректное existence без ложного подтверждения |

## `extra_collectors_test.go`

| Тест | Сценарий | Ожидание |
|---|---|---|
| `TestParseJSONAccounts` | JSON-массив / `{results:[...]}` / мусор | 2/1/0 аккаунтов, source/confidence корректны |
| `TestParseGHunt` | JSON GHunt с name/avatar | 1 verified google-аккаунт |
| `TestWMNProfileExists` | httptest: e_string есть / нет | true только при совпадении e_string и отсутствии m_string |


## `email_mvp_test.go`

| Тест | Сценарий | Ожидание |
|---|---|---|
| `TestParseMicrosoftExists` | `IfExistsResult` 0/5/6/1, throttle, мусор | 0/5/6 → exists, 1 → нет, throttle/битый JSON → unknown |
| `TestParseDisify` | JSON Disify с format/dns/mx | Поля и MX корректно извлечены |
| `TestExtractEmailIntel` | Observation `kind=email_intel` | `EmailIntel` найден и заполнен |
