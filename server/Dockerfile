# Этап сборки
FROM golang:1.27.3-alpine AS builder

WORKDIR /app

# Копируем только файлы зависимостей для кэширования
COPY go.mod go.sum ./
RUN go mod download

# Копируем весь остальной код и собираем
COPY . .
RUN go build -o stare-api ./cmd/stare-api/main.go

# Этап запуска (легкий образ)
FROM alpine:latest

WORKDIR /app
# Копируем готовый бинарник из этапа сборки
COPY --from=builder /app/stare-api .

# Открываем порт
EXPOSE 8080

# Запускаем сервер
CMD ["./stare-api"]