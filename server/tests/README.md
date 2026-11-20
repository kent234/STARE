# Server external tests

Запуск: `cd server && go test ./tests -count=1`.

## `quality_test.go`

| Тест | Сценарий | Ожидаемый результат |
|---|---|---|
| `TestParseProfileURL` | VK/Instagram/GitHub/X/Telegram/YouTube/Reddit/OK, пост Instagram, домен и текст | Для профилей возвращаются платформа+handle; `instagram.com/p/...`, `example.com`, `not a url` → `ok=false` |
| `TestApplyProfileMatchUsesProfileSemantics` | Профиль GitHub `torvalds` + кандидат с той же страницей (httptest) | Источник получает `match_score=100`/`input profile`; кандидат совпадает по имени/bio (`score≥50`) и становится `verified` |

## `people_test.go`

| Тест | Сценарий | Ожидаемый результат |
|---|---|---|
| `TestDetect` | username/email/phone/real name/пусто | Корректный `Kind`, пустой ввод → пустой тип |
| `TestNormalizeDedupAndConfidence` | GitHub от Sherlock + Maigret и Twitter | Один GitHub-аккаунт, `multi_source=true`, sources=2, confidence=high |
| `TestNormalizeBreachAndPhone` | Breach + phone observations | Breach сохранён, phone содержит страну |
| `TestBuildActorConfidence` | Аккаунты medium + high | Actor.confidence=high, оба аккаунта в связях |

## `nuclei_test.go` (build tag `!nuclei`)

| Тест | Сценарий | Ожидаемый результат |
|---|---|---|
| `TestRunNucleiExec` | Фейковый бинарник печатает JSONL | 1 finding с template/name/severity/matched-at |
| `TestRunNucleiMissingBinary` | Бинарник отсутствует | `nil` ошибки, 0 findings — скан не падает |
