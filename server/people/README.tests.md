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

## `extra_collectors_test.go`

| Тест | Сценарий | Ожидание |
|---|---|---|
| `TestParseJSONAccounts` | JSON-массив / `{results:[...]}` / мусор | 2/1/0 аккаунтов, source/confidence корректны |
| `TestParseGHunt` | JSON GHunt с name/avatar | 1 verified google-аккаунт |
| `TestWMNProfileExists` | httptest: e_string есть / нет | true только при совпадении e_string и отсутствии m_string |
