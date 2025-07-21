FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod tidy

COPY . .
RUN go build -o /app/service ./cmd/main.go

FROM alpine:latest

WORKDIR /service

COPY --from=builder /app/service .
COPY --from=builder /app/.env .

CMD ["./service"]