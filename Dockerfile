# syntax=docker/dockerfile:1

FROM golang:1.22-bullseye AS builder
ENV GOTOOLCHAIN=auto
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/node ./cmd/node
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/mockapp ./cmd/mockapp

FROM debian:12-slim AS runtime
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*

COPY config/dev.yaml /app/config/container.yaml
COPY --from=builder /out/node /usr/local/bin/node
COPY --from=builder /out/mockapp /usr/local/bin/mockapp

RUN adduser --system --uid 10001 hermes
RUN mkdir -p /app/data && chown -R hermes /app
USER hermes

EXPOSE 50051 8080
ENTRYPOINT ["/usr/local/bin/node"]
CMD ["--config", "/app/config/container.yaml"]
