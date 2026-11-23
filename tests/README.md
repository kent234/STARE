# S.T.A.R.E — тесты

| Каталог | Что внутри | Запуск |
|---|---|---|
| `server/tests/` | Go external tests: People/Profile URL, Nuclei | `cd server && go test ./tests` |
| `server/people/*_test.go` | Внутренние тесты People (unexported) | `cd server && go test ./people` |
| `server/scanner/*_test.go` | Внутренние тесты источников/парсеров | `cd server && go test ./scanner` |
| `tests/frontend/unit/` | Node test runner: чистые JS-функции | `cd client && npm run test:unit` |
| `tests/frontend/e2e/` | Playwright: граф, фильтры, People | `npm run test:e2e` (из корня) |

Описания сценариев и ожидаемых результатов:
- [`server/tests/README.md`](../server/tests/README.md)
- [`server/scanner/README.tests.md`](../server/scanner/README.tests.md)
- [`server/people/README.tests.md`](../server/people/README.tests.md)
- [`tests/frontend/unit/README.md`](frontend/unit/README.md)
- [`tests/frontend/e2e/README.md`](frontend/e2e/README.md)
