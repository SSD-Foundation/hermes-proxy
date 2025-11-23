GO ?= go
PROTOC ?= protoc
PROTO_SRC := proto/app_router.proto

.PHONY: all proto fmt lint test build check

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
