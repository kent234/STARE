
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
Без бинарника скан работает, а раздел `VULNERABILITIES (NUCLEI)` в графе/таблице остаётся пустым. Docker-образ уже содержит `nuclei` v3.11.1 и официальные шаблоны (`/root/nuclei-templates`); переменные `NUCLEI_*` можно переопределить в `docker-compose.yml`/`.env`. Альтернатива — сборка с библиотекой: `go build -tags nuclei` (потребует вернуть зависимости Nuclei в `go.mod`).

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

---

## Graph performance

Граф оптимизирован для больших сканов: `fcose`, `pixelRatio: 1`, `hideEdgesOnViewport`, упрощённые стили и progressive disclosure (1 hop). Замеры и методика — в [BENCHMARK.md](BENCHMARK.md).

```bash
cd client
npm run test:graph    # Playwright: рендер, фильтры, поиск, раскрытие соседей
npm run bench:graph   # FPS/layout/filter на 5 000+ узлов
```

Рендерер: `VITE_GRAPH_RENDERER=canvas` (по умолчанию), `auto` или `webgl`; при ошибке WebGL автоматически откатывается на canvas.

## People-OSINT (бесплатные источники)

Одна строка ввода: `username`, `email`, `phone`, `real_name` или **ссылка на профиль** (VK, Instagram, GitHub, X/Twitter, Telegram, Reddit, YouTube, OK и др.) — тип определяется автоматически. Конвейер: detect → collectors → normalize/dedup → Actor → граф/таблица.

- **Ссылка на профиль:** извлекается платформа и handle, забираются OpenGraph/`<title>`/bio/avatar/внешние ссылки, затем handle проверяется по всем остальным платформам.
- **Username:** Sherlock, Maigret, Blackbird (CLI), WhatsMyName (встроенный чекер по JSON-списку).
- **Email:** Holehe (регистрации), Gravatar (профиль и привязанные аккаунты), GHunt (Google, нужны cookies), **XposedOrNot** и **Hudson Rock** (бесплатно, без ключей).
- **Phone:** локальный парсер + PhoneInfoga (если установлен).
- **Real name:** GitHub Users API (бесплатный поиск по `fullname`).
- **Верифицированные обогатители:** GitHub API, GitLab API, Keybase proofs (даёт подтверждённые twitter/github/reddit/hackernews и др.), Gravatar.
- Holehe больше не считается «аккаунтом»: факты регистрации выносятся в отдельную таблицу `EMAIL REGISTRATIONS`, чтобы не засорять граф.
- Дедупликация канонизирует платформы (`GitHub (user)` → `github`), мержит источники, считает `score` и `verified`. По умолчанию показываются verified / multi-source / score ≥ 70; остальное — через `Filters → show unverified`.

Демо без внешних инструментов:
```bash
PEOPLE_FIXTURE=1 docker compose up -d --build backend
# в UI введите: test
```
Переменные: `SHERLOCK_BIN`, `MAIGRET_BIN`, `MAIGRET_MAX_SITES`, `BLACKBIRD_BIN`, `BLACKBIRD_DIR`, `HOLEHE_BIN`, `GHUNT_BIN`, `PHONEINFOGA_BIN`, `WMN_MAX_SITES`, `EMAILREP_API_KEY`, `GITHUB_TOKEN`.

Семантическое совпадение: при вводе ссылки на профиль берутся имя/bio/avatar/ссылки источника, затем кандидаты проверяются по этим признакам (`match_score`, `match_reason`), а не только по совпадению handle. По умолчанию для profile URL показываются только совпадения ≥50; остальное — через `show unverified`.

Ограничения: GHunt требует предварительного `ghunt login` (Google-cookies) и работает только для Google-аккаунтов; PhoneInfoga без API-ключа не определяет оператора; WhatsMyName проверяет первые `WMN_MAX_SITES` платформ и даёт `low` confidence; Maigret ограничен `MAIGRET_MAX_SITES`. Сырые пароли/токены из утечек не сохраняются — только `breach_name`, `email`, `date`, `data_classes`.

### Docker: полный OSINT-образ по умолчанию

`docker compose up -d --build` теперь использует `server/Dockerfile.osint`: все CLI + Nuclei уже внутри, ничего не нужно ставить на хост. GHunt дополнительно требует `ghunt login`.

Если нужен лёгкий образ без внешних инструментов:

```bash
docker compose -f docker-compose.yml -f docker-compose.lite.yml up -d --build backend
```

Файл `docker-compose.osint.yml` оставлен для совместимости и указывает на тот же `Dockerfile.osint`.

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

