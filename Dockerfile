FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git

RUN go install github.com/pressly/goose/v3/cmd/goose@latest

WORKDIR /app

COPY go.mod ./
ENV GOPROXY=https://proxy.golang.org,direct
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main ./cmd/app

FROM alpine:latest

RUN apk add --no-cache postgresql-client bash

WORKDIR /app

COPY --from=builder /go/bin/goose /usr/local/bin/goose
COPY --from=builder /app/.env /app
COPY --from=builder /app/migrations /app/migrations
COPY --from=builder /app/wait-for-it.sh /app

COPY --from=builder /app/main /app/main


CMD ["/bin/sh", "-c", "/app/wait-for-it.sh -- goose up && /app/main"]