
<div align="center">

# S.T.A.R.E

### **S**urface **T**racking **A**nd **R**econ **E**ngine

*OSINT-инструмент нового поколения для управления поверхностью атаки с интерактивной визуализацией*

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://reactjs.org)
[![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)
[![Cytoscape.js](https://img.shields.io/badge/Cytoscape.js-FF6600?style=for-the-badge&logo=cytoscape&logoColor=white)](https://js.cytoscape.org)

</div>

---

## О проекте

**S.T.A.R.E** — это веб-приложение для автоматизированной разведки (OSINT) и анализа периметра безопасности. Инструмент собирает данные из открытых источников, сканирует сетевую инфраструктуру и визуализирует связи в виде интерактивного графа.

Проект сочетает в себе мощность сетевых сканеров на Go и эстетику хакерского терминала 90-х на React.

---

## Ключевые возможности

*   **Пассивная разведка**: Поиск поддоменов через Certificate Transparency (crt.sh, crt.name), RapidDNS, HackerTarget, AlienVault OTX, ThreatMiner, URLScan и TLSCC.
*   **Активная разведка**: DNS-резолвинг, сканирование портов, сбор баннеров сервисов (Nginx, OpenSSH, IIS).
*   **Сбор контекста**: WHOIS/RDAP данные, ASN-принадлежность IP, технологический стек (Wappalyzer), заголовки серверов, robots.txt.
*   **Интерактивный граф**: Визуализация связей `Домен -> Поддомен -> IP -> Порт` с помощью Cytoscape.js.
*   **Детализация узлов**: При наведении отображаются краткие подсказки, при клике — выезжает панель с полными данными (в формате красивого JSON).
*   **Стильный UI**: Терминальный интерфейс с CRT-эффектами (сканлайны, глитчи) и выводом логов в реальном времени.

---

## Архитектура

*   **Backend**: Go (REST API, параллельное сканирование через горутины).
*   **Frontend**: React (Vite), Cytoscape.js, ванильный CSS.
*   **Deployment**: Docker и Docker Compose.

---

## Быстрый запуск (Docker)

Самый простой способ запустить проект — использовать Docker. Вам не нужно устанавливать Go или Node.js на вашу машину.

1. Убедитесь, что у вас установлен и запущен **Docker Desktop**.
2. Клонируйте репозиторий:
   ```bash
   git clone https://vcs.uni-dubna.ru/DAAG.24/stare.git
   cd stare
   ```
3. Запустите сборку и старт контейнеров:
   ```bash
   docker compose up --build
   ```
4. Дождитесь окончания установки (первый запуск может занять несколько минут).
5. Откройте браузер и перейдите по адресу: **http://localhost:5173**

---

## Локальный запуск (для разработки)

Если вы хотите вносить изменения в код, запускать проект лучше локально.

### 1. Запуск Бэкенда (Go)
```bash
cd server
set -a && . ../.env && set +a   # ключи источников из корневого .env
go mod tidy
go run ./cmd/stare-api/main.go
```
*(Сервер запустится на `http://localhost:8080`)*

### 2. Запуск Фронтенда (React)
Откройте **второй терминал**:
```bash
cd client
npm install
npm run dev
```
*(Клиент запустится на `http://localhost:5173`)*

### 3. API-ключи и проверка источников
Скопируйте шаблон и заполните ключи (пустой ключ = источник пропускается):
```bash
cp .env.example .env
```
Проверить, какие источники реально подключились и отвечают:
```bash
cd server
set -a && . ../.env && set +a
go run ./cmd/stare-diag -target example.com
```
Диагностика печатает список зарегистрированных источников, число наблюдений по каждому и ошибки. URLhaus/ThreatFox требуют бесплатный `ABUSECH_AUTH_KEY` с https://auth.abuse.ch/.

### 4. Nuclei (уязвимости)
Веб-сканер вызывает Nuclei, если в системе доступен бинарник `nuclei`:
```bash
export NUCLEI_BINARY=nuclei            # или абсолютный путь
export NUCLEI_TEMPLATES=~/nuclei-templates
export NUCLEI_SEVERITY=critical,high
export NUCLEI_TIMEOUT=5m
```
Без бинарника скан работает, а раздел `VULNERABILITIES (NUCLEI)` в графе/таблице остаётся пустым, но в `scan_meta.tools.nuclei` будет `missing` — пустота больше не маскируется под «чисто». `scan_meta.coverage` показывает attempted/succeeded/failed/skipped по DNS, HTTP, портам, TLS и Nuclei; `scan_id`/`schema_version`/`duration_ms` делают прогон аудируемым.

### Гигиена данных

- Поддомены нормализуются (lowercase, срез схемы/порта/`*.`/точки) и валидируются по label и суффиксу домена; мусор вида `u003ewww...` отбрасывается, число отброшенных — `subdomains_rejected`.
- `endpoints[]` фильтруются по scope: только HTTP(S), без шаблонов `$%7B...%7D`, статики, `w3.org`/schema-URL; есть `endpoints_by_host` и лимит с флагом `truncated`.
- `dns_checks`: SPF (несколько записей → PermError), DMARC (policy), CAA, DNSSEC через DoH (без ключей), с человекочитаемыми `issues`.
- `artifacts`: fallback HTTPS→HTTP, разбор `Disallow`/`Allow`/`Sitemap`, `server_header` с реальных хостов (`server_headers` по хостам).
- `hosts[]` объединяет IP, wildcard/private, порты, лучший HTTP-probe и TLS-сертификаты в одну запись.
- `findings[]` — единая модель отчёта: `{severity, source: local|observed, confidence, host, cve, evidence}`; Nuclei, Shodan CVE, DNS-проблемы и публичные bucket'ы больше не разбросаны по разным полям. KEV/EPSS обогащают и observed-CVE.
- Cloud buckets: `403` больше не считается существующим; публичность подтверждается `200` + маркером листинга, есть `confidence`/`evidence` и варианты `-backup/-dev/-prod/-data`. Docker-образ уже содержит `nuclei` v3.11.1 и официальные шаблоны (`/root/nuclei-templates`); переменные `NUCLEI_*` можно переопределить в `docker-compose.yml`/`.env`. Альтернатива — сборка с библиотекой: `go build -tags nuclei` (потребует вернуть зависимости Nuclei в `go.mod`).

---

## 📖 Как пользоваться

1. Откройте веб-интерфейс.
2. Нажмите **`[ EXECUTE ]`** (или введите `http://localhost:5173` в браузере, если запускаете через Docker).
3. Введите целевой домен (например, `uni-dubna.ru`) или IP-адрес в поле ввода и нажмите **ENTER**.
4. Дождитесь окончания сканирования (время зависит от размера домена, обычно 1–3 минуты). В правой панели будут появляться логи процесса.
5. Изучайте граф:
   * **Наведите** курсор на узел, чтобы увидеть краткую сводку.
   * **Кликните** на узел (домен, IP или порт), чтобы открыть боковую панель с полными деталями (WHOIS, порты, технологии, баннеры).
   * Перетаскивайте узлы и используйте колесико мыши для зума.
6. **История сканов** (`[ SAVED.GRAPHS ]` слева): клик загружает сохранённый граф, `[ x ]` удаляет один скан, чекбоксы + `DEL N` — пакетное удаление выбранных, `DEL.ALL` — очистка всей истории.

---

## Graph performance

Граф оптимизирован для больших сканов: `fcose`, `pixelRatio: 1`, `hideEdgesOnViewport`, упрощённые стили и progressive disclosure (1 hop). Замеры и методика — в [BENCHMARK.md](BENCHMARK.md).

```bash
# из корня репозитория
npm run test:graph    # Playwright: рендер, фильтры, поиск, раскрытие соседей
npm run test:people   # Playwright: People-OSINT
npm run bench:graph   # FPS/layout/filter на 5 000+ узлов
cd client && npm run test:unit   # Node unit-тесты фронтенда
```

Рендерер: `VITE_GRAPH_RENDERER=canvas` (по умолчанию), `auto` или `webgl`; при ошибке WebGL автоматически откатывается на canvas.

## People-OSINT (бесплатные источники)

Одна строка ввода: `username`, `email`, `phone`, `real_name` или **ссылка на профиль** (VK, Instagram, GitHub, X/Twitter, Telegram, Reddit, YouTube, OK и др.) — тип определяется автоматически. Конвейер: detect → collectors → normalize/dedup → Actor → граф/таблица.

- **Ссылка на профиль:** извлекается платформа и handle, забираются OpenGraph/`<title>`/bio/avatar/внешние ссылки, затем handle проверяется по всем остальным платформам.
- **Username:** Sherlock, Maigret, Blackbird (CLI), WhatsMyName (встроенный чекер по JSON-списку).
- **Email:** Holehe (регистрации), Gravatar (профиль и привязанные аккаунты), **Microsoft GetCredentialType** (существование аккаунта), **PGP keyserver** (подтверждённый email), **Disify** (формат/disposable/MX), GHunt (Google, нужны cookies), **XposedOrNot** и **Hudson Rock** (утечки, без ключей).
- **Phone:** локальный парсер + PhoneInfoga (если установлен).
- **Real name:** GitHub Users API (бесплатный поиск по `fullname`).
- **Верифицированные обогатители:** GitHub API, GitLab API, Keybase proofs (даёт подтверждённые twitter/github/reddit/hackernews и др.), Gravatar.
- Holehe больше не считается «аккаунтом»: факты регистрации выносятся в отдельную таблицу `EMAIL REGISTRATIONS`, чтобы не засорять граф.
- URL-фильтрация отсекает search-страницы, корневые URL, сторонние трекеры и ссылки без handle; платформы канонизируются (`Chess`/`Chess.com` → `chess.com`).
- Верификация разделена на два независимых поля: `verification` (`none|collector|http`) и `existence` (`confirmed|blocked|unknown|absent`). Коллекторский `verified` — только evidence, HTTP-проверку он не отменяет.
- HTTP-верификация: 404/410 → `removed[]`, 401/403/429/login-wall → `blocked` и `low`, timeout/5xx/soft-404 → `unknown` и `low`; `confirmed` только по странице с handle в title/og:title или site-specific `e_string`.
- `http_attempted`, `http_status`, `http_error`, `url_reachable` показывают, что именно произошло; `PEOPLE_VERIFY_MAX` ограничивает число проверок (по умолчанию 200).
- Canonical URL выбирается по рангу: профиль > обычная страница > API; все варианты сохраняются в `evidence_urls` (например, `api.chess.com` остаётся evidence, а не ссылкой профиля).
- Наблюдаемость: `schema_version`, `scan_id`, `duration_ms`, `collectors[]` (`ran/missing/error`, observations/kept/duration) и `versions` установленных CLI. «Не установлен» и «ничего не нашёл» различимы в JSON и UI.
- Score прозрачен: веса источников (API > CLI > эвристики), бонус `confirmed`/`url_reachable`/полноты профиля, штрафы `blocked/unknown`; формула описана в `computeAccountScore`.
- `Actor` — кластер хэндла, не «человек»: `high` только при 2+ независимых сигналах (`same_name`, `same_avatar`, `shared_link`, `profile_match`); `actor.id` нормализован (profile URL → handle, real name → slug).
- Top-N подтверждённых аккаунтов обогащаются OG-метаданными (name/bio/avatar/links) — без этого кросс-сигналы невозможны.
- `sensitive`-платформы (Pornhub, OnlyFans, dating и т.п.) скрыты по умолчанию, не входят в Actor и показываются отдельной секцией только по чекбоксу.
- **Реестр платформ** (`server/people/data/platforms.json`): декларативные keyless-детекторы `status|json_path|body_contains|body_absent` для GitHub, GitLab, Keybase, Reddit, HN, Chess, Lichess, Steam, npm, PyPI, Docker Hub, Telegram, Mastodon, YouTube, TikTok, Minecraft, Roblox, Bluesky.
- **Поддомен-паттерны**: `{handle}.github.io`, gitlab.io, wordpress, blogspot, vercel, netlify, pages.dev и т.п. — с отсевом parked/404-заглушек.
- **Variant expansion**: производные ника (`yami_kuru`, `yami-kuru`, `yamikuru`, `_official`) проверяются только по реестру, помечаются `variant_of` и пониженным confidence.
- **Deep mode** (`PEOPLE_DEEP=1`): Maigret `--all-sites`, WhatsMyName без среза, снятие лимита верификации; `--nsfw` — только при отдельном `PEOPLE_ALLOW_NSFW=1`.
- **Maigret по умолчанию работает без лимита сайтов**; `MAIGRET_MAX_SITES=0` (или пусто) = весь список, число — ограничение для быстрого режима.
- Дедупликация канонизирует платформы (`GitHub (user)` → `github`), мержит источники и считает `score`. По умолчанию показываются только `existence=confirmed`; остальное — через `show low-confidence / unverified`.

Демо без внешних инструментов:
```bash
PEOPLE_FIXTURE=1 docker compose up -d --build backend
# в UI введите: test
```
Переменные: `SHERLOCK_BIN`, `MAIGRET_BIN`, `MAIGRET_MAX_SITES`, `BLACKBIRD_BIN`, `BLACKBIRD_DIR`, `HOLEHE_BIN`, `GHUNT_BIN`, `PHONEINFOGA_BIN`, `WMN_MAX_SITES`, `PEOPLE_VERIFY_MAX`, `GITHUB_TOKEN`.

Семантическое совпадение: при вводе ссылки на профиль берутся имя/bio/avatar/ссылки источника, затем кандидаты проверяются по этим признакам (`match_score`, `match_reason`), а не только по совпадению handle. По умолчанию для profile URL показываются только совпадения ≥50; остальное — через `show unverified`.

Ограничения: GHunt требует предварительного `ghunt login` (Google-cookies) и работает только для Google-аккаунтов; PhoneInfoga без API-ключа не определяет оператора; WhatsMyName проверяет первые `WMN_MAX_SITES` платформ и даёт `low` confidence; Maigret ограничен `MAIGRET_MAX_SITES`. Сырые пароли/токены из утечек не сохраняются — только `breach_name`, `email`, `date`, `data_classes`.

### Docker: полный OSINT-образ по умолчанию

`docker compose up -d --build` теперь использует `server/Dockerfile.osint`: все CLI + Nuclei уже внутри, ничего не нужно ставить на хост. GHunt дополнительно требует `ghunt login`.

Если нужен лёгкий образ без внешних инструментов:

```bash
docker compose -f docker-compose.yml -f docker-compose.lite.yml up -d --build backend
```

Файл `docker-compose.osint.yml` оставлен для совместимости и указывает на тот же `Dockerfile.osint`.

Чтобы добавить ProjectDiscovery CLI (subfinder/httpx/naabu/tlsx/katana) в образ:

```bash
docker compose -f docker-compose.yml -f docker-compose.pdtools.yml up -d --build backend
```

Без этих бинарей сканер работает, просто пропускает активные PD-проверки.

## Tests и CI/CD

Структура тестов:

```
server/tests/              # Go: external tests (people/scanner)
server/people/*_test.go    # Go: internal unit tests (unexported-функции)
server/scanner/*_test.go   # Go: internal unit tests (парсеры источников)
tests/frontend/unit/       # Node test runner (чистые JS-функции)
tests/frontend/e2e/        # Playwright (граф, фильтры, People-OSINT)
```

Запуск:
```bash
cd server && go test ./... -count=1
cd client && npm run lint && npm run test:unit && npm run build
npm ci && npm run test:e2e        # из корня, Playwright
```

GitLab CI (`.gitlab-ci.yml`) выполняет:
- `test:backend` — gofmt, vet, тесты + coverage;
- `test:frontend-unit` — eslint, unit-тесты, production build;
- `test:e2e` — Playwright в официальном образе;
- `package:*` — сборка и пуш Docker-образов в GitLab Registry (main/tags);
- `package:backend-osint` — полный OSINT-образ, manual;
- `deploy:production` — manual, SSH-деплой.

Для деплоя задайте CI/CD variables: `SSH_PRIVATE_KEY`, `DEPLOY_HOST`, `DEPLOY_USER`, `DEPLOY_PATH`.

### GitLab Runner

Если у проекта нет активного runner, он поднимается локально в Docker:

1. GitLab → проект `stare` → **Settings → CI/CD → Runners → New project runner**.
2. Скопируйте токен `glrt-...`.
3. Запустите:
   ```bash
   RUNNER_TOKEN="glrt-..." ./scripts/register-gitlab-runner.sh
   ```
4. Проверьте: https://vcs.uni-dubna.ru/DAAG.24/stare/-/settings/ci_cd

Runner использует Docker executor, `privileged=true` (нужно для docker-in-docker в package jobs), `run_untagged=true`, теги `docker,stare`. Конфиг хранится в `secrets/gitlab-runner/config.toml` (gitignored).

## 📁 Структура проекта

```text
stare/
├── client/              # React Frontend (Vite, Cytoscape.js)
├── server/              # Go Backend
│   ├── cmd/             # Точки входа (stare-api, stare-cli)
│   ├── scanner/         # Ядро сканера (сбор данных, парсинг)
│   └── go.mod
├── docker-compose.yml   # Оркестрация контейнеров
└── README.md

