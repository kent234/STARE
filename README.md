<div align="center">

# STARE

*OSINT-инструмент для управления поверхностью атаки*

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?style=for-the-badge&logo=postgresql&logoColor=white)](https://postgresql.org)
[![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)

[![Status](https://img.shields.io/badge/status-in%20development-yellow?style=flat-square)]()
[![License](https://img.shields.io/badge/license-TBD-lightgrey?style=flat-square)]()

</div>

---

## О проекте

**STARE** — это OSINT-инструмент, который автоматизирует разведку интернет-периметра: находит поддомены, IP-адреса, открытые порты и сервисы, строит граф связей и показывает **только изменения** между сканами.

## Что делает STARE

| # | Действие |
|:---:|:---|
| 1️ | **Сканирует** домен или IP-диапазон (CIDR) |
| 2️ | **Находит** поддомены, IP, порты, сервисы |
| 3️ | **Строит** граф связей: домен → IP → порт → сервис |
| 4️ | **Сохраняет** историю сканов |
| 5️ | **Показывает diff** — что изменилось |
| 6️ | **Уведомляет** через Telegram-бот |

---

## Технологический стек

| Слой | Технология |
|:---|:---|
| **Ядро** | Go 1.22+, `net/http`, `net`, горутины, `context` |
| **БД** | PostgreSQL |
| **Обогащение** | Python 3.11+, FastAPI, httpx, BeautifulSoup |
| **Веб** | HTML, CSS, JavaScript, Cytoscape.js, SSE |
| **Бот** | Go (`go-telegram-bot-api`) |
| **Тесты** | Go testing, Pytest |
| **Развёртывание** | Docker Compose |
| **VCS** | GitLab |

---

## Источники данных (все бесплатные)

| Источник | Что даёт |
|:---|:---|
| **crt.sh** | Поддомены через Certificate Transparency logs |
| **RDAP / WHOIS** | Информация о домене, CIDR-блоки |
| **DNS** | A, AAAA, MX, TXT, PTR-записи |
| **Team Cymru** | ASN, принадлежность IP |
| **Перебор словарей** | `dev`, `test`, `api`, `vpn`, `staging` |

---


## 🚀 Запуск

```bash
# Клонировать репозиторий
git clone https://gitlab.com/your-username/stare.git
cd stare

# Запустить через Docker Compose
docker compose up --build
