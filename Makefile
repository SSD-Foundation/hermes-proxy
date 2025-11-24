GO ?= go
PROTOC ?= protoc
PROTO_SRC := proto/app_router.proto proto/nodemesh.proto

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
	ids=$$(docker compose -f docker-compose.dev.yaml ps -a -q app1 app2); \
	if [ -z "$$ids" ]; then \
		echo "integration containers missing (app1/app2)"; \
		docker compose -f docker-compose.dev.yaml ps; \
		exit 1; \
	fi; \
	statuses=$$(docker wait $$ids); \
	echo "$$statuses" | awk '{print "exit status:", $$0}'; \
	if echo "$$statuses" | grep -Ev '^0$$' >/dev/null; then \
		echo "integration containers exited with failure"; \
		docker compose -f docker-compose.dev.yaml logs app1 app2; \
		exit 1; \
	fi
