GO ?= go
PROTOC ?= protoc
PROTO_SRC := proto/app_router.proto

.PHONY: all proto fmt lint test build check integration

all: build

proto:
	$(PROTOC) --go_out=. --go-grpc_out=. --go_opt=module=github.com/hermes-proxy/hermes-proxy --go-grpc_opt=module=github.com/hermes-proxy/hermes-proxy $(PROTO_SRC)

fmt:
	$(GO) fmt ./...

lint:
	$(GO) vet ./...

test:
	$(GO) test ./...

build:
	$(GO) build ./...

check: fmt lint test

integration:
	@set -e; \
	trap 'docker compose -f docker-compose.dev.yaml down --remove-orphans' EXIT; \
	docker compose -f docker-compose.dev.yaml up -d --build; \
	docker compose -f docker-compose.dev.yaml wait app1 app2
