# Frontend E2E tests (Playwright)

Запуск из корня: `npm run test:e2e`. Vite поднимается автоматически на `127.0.0.1:5174`.

## `graph.spec.js` — benchmark

| Сценарий | Ожидаемый результат |
|---|---|
| Открыть `/?bench=5000`, показать весь граф, 3 с прогрева | В графе >4 000 узлов и >4 000 рёбер; рендерер `CANVAS`/`WEBGL` |
| Drag/zoom 2 с в режиме 1-hop | `defaultDragFps > 30`; в отчёт пишутся `fullDragFps`, `defaultDragFps`, `filterMs`, DOM/canvas |
| Фильтрация узлов `ip` | Время операции фиксируется, результат сохраняется в `client/bench/optimized.json` |

## `graph-ui.spec.js`

| Тест | Сценарий | Ожидаемый результат |
|---|---|---|
| `renders nodes and edges` | Открыть синтетический граф 300 элементов | Узлы/рёбра > 200, бейдж рендерера виден |
| `progressive disclosure reveals neighbors` | Клик по узлу `bench.local` | Видимых узлов не меньше, чем до клика; скрытые соседи раскрываются |
| `filters hide node types` | Открыть Filters, снять `IP` | Видимых IP-узлов ровно 0 |
| `search focuses a node` | Ввести `host5.bench.local` + Enter | Панель деталей содержит `host5.bench.local` |
| `observation panel shows source and confidence` | Изолировать observation-узел и кликнуть | Панель содержит источник (`ipinfo`) и `confidence` |

## `people.spec.js`

| Тест | Сценарий | Ожидаемый результат |
|---|---|---|
| `profile URL enriches account with public metadata` | Ввести `https://vk.com/test` (API замокан) | Есть Account-узел, label содержит имя, панель показывает `Test Profile` и bio |
| `username investigation renders accounts and details` | Ввести `test` (API замокан, 3 аккаунта) | ≥3 Account-узлов, клик показывает `account/source/confidence` |
| `email MVP shows Microsoft account and email intelligence` | Ввести `test@example.com` (API замокан: Microsoft + Disify + Holehe) | Account `microsoft`, секция `EMAIL INTELLIGENCE` с MX, регистрация `office365.com` |

## `history.spec.js`

| Тест | Сценарий | Ожидаемый результат |
|---|---|---|
| `bulk delete and delete-all saved graphs` | Открыть `[ SAVED.GRAPHS ]` (API замокан, 3 скана), выбрать 2 чекбоксами, затем `DEL.ALL` | `POST /api/scans/delete` получает `{ids:[...]}` и `{all:true}`, история очищается |
