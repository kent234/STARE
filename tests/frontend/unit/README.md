# Frontend unit tests

Запуск: `cd client && npm run test:unit` (Node test runner, без внешних зависимостей).

## `observations.test.mjs`

| Тест | Сценарий | Ожидаемый результат |
|---|---|---|
| `normalizeIndicator extracts host and strips IPv4 port` | URL с путём/query и IPv4 с портом | `https://Example.COM/... → example.com`; `1.2.3.4:443 → 1.2.3.4` |
| `normalizeIndicator keeps IPv6 intact` | Чистый IPv6 и IPv6 в скобках с портом | Адрес IPv6 не обрезается по последнему `:`; `[2a00:...::1]:443 → 2a00:...::1` |
| `classifies sources and builds labels` | Наблюдения `ipinfo` и `urlhaus` | `info`/`threat`, подпись содержит индикатор, summary содержит `malware_download` |

## `detect.test.mjs`

| Ввод | Ожидаемый тип |
|---|---|
| `john_doe` | `username` |
| `john@example.com` | `email` |
| `+7 (900) 123-45-67` | `phone` |
| `John Doe` | `real_name` |
| `https://vk.com/durov`, `github.com/torvalds` | `profile_url` |
| `example.com`, пустая строка | `null` (это домен/пустой ввод, не People-OSINT) |
