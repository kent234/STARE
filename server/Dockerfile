# Этап сборки
FROM golang:1.27.3-alpine AS builder

WORKDIR /app
ENV GOPROXY=https://goproxy.ru,direct
ENV GOSUMDB=off
# Копируем только файлы зависимостей для кэширования
COPY go.mod go.sum ./
RUN go mod download

# Копируем весь остальной код и собираем
COPY . .
RUN go build -o stare-api ./cmd/stare-api/main.go

# Этап запуска (легкий образ)
FROM alpine:latest

ARG TARGETARCH
ARG NUCLEI_VERSION=3.11.1

WORKDIR /app

# Nuclei + официальные шаблоны прямо в образе.
RUN apk add --no-cache ca-certificates curl unzip \
 && case "${TARGETARCH:-$(uname -m)}" in \
      amd64|x86_64) narch=amd64 ;; \
      arm64|aarch64) narch=arm64 ;; \
      *) echo "unsupported architecture: ${TARGETARCH:-$(uname -m)}" >&2; exit 1 ;; \
    esac \
 && curl -fsSL --retry 3 -o /tmp/nuclei.zip \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${narch}.zip" \
 && unzip -q /tmp/nuclei.zip nuclei -d /usr/local/bin \
 && chmod +x /usr/local/bin/nuclei \
 && rm -f /tmp/nuclei.zip \
 && nuclei -update-templates \
 && apk del curl unzip

ENV NUCLEI_BINARY=/usr/local/bin/nuclei \
    NUCLEI_TEMPLATES=/root/nuclei-templates \
    NUCLEI_SEVERITY=critical,high \
    NUCLEI_TIMEOUT=5m

# Копируем готовый бинарник из этапа сборки
COPY --from=builder /app/stare-api .

# Открываем порт
EXPOSE 8080

# Запускаем сервер
CMD ["./stare-api"]