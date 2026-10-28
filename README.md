
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

