# HERMES Nodes (Phase 1)

This repository tracks the Phase 1 implementation of HERMES router nodes: a gRPC-based service that connects Apps, manages encrypted 1:1 chats on a single node, and prepares the groundwork for later mesh, payments, and NAT features. Platform target is Ubuntu Linux.

## Getting started
- Read the MVP scope in `docs/hermes-mvp-revised.md`.
- Review the Phase 1 plan and iteration prompts in `docs/plan/phase-1/`.
- The gRPC contract lives in `proto/app_router.proto` with generated Go stubs in `pkg/api/approuterpb`.
- The node binary entrypoint is `cmd/node` and hosts the `AppRouter.Open` bidirectional stream for connect/start chat/send/delete flows.

## Development workflow
- Install Go 1.24+ and ensure `protoc` with the Go plugins is available if regenerating protobufs.
- Set `HERMES_KEYSTORE_PASSPHRASE` (or another env set in config) so the keystore backend can initialize/unlock.
- Common tasks:
  - `make fmt` – format the Go sources.
  - `make lint` – run `go vet`.
  - `make test` – run unit + component tests (in-process gRPC chat flow).
  - `make build` – build all packages.
  - `make proto` – regenerate gRPC stubs from `proto/app_router.proto`.
  - `go test ./internal/server` – component tests for connect/start chat/send/delete happy path and signature failure.

## Running the node
The binary wires config, structured logging, keystore initialization, and the `AppRouter` gRPC service.

```bash
export HERMES_KEYSTORE_PASSPHRASE=change-me
go run ./cmd/node --config config/dev.yaml
```

If the keystore file does not exist, it is initialized automatically at the configured path.

## Configuration
Configuration is read from a file plus environment overrides (`HERMES_` prefix). Example:

```yaml
grpc_address: "0.0.0.0:50051"
log_level: "info"
shutdown_grace_period: "10s"
keystore:
  path: "data/keystore.json"
  passphrase_env: "HERMES_KEYSTORE_PASSPHRASE"
```

## Project structure
- `cmd/node`: Node entrypoint wiring config, logging, keystore, registry, and gRPC server.
- `proto/app_router.proto`: AppRouter protobuf contract; generated code in `pkg/api/approuterpb`.
- `internal/config`: Config loader with env overrides.
- `internal/keystore`: Argon2id-derived file backend (placeholder encryption) with tests.
- `internal/registry`: In-memory chat/tieline registry.
- `internal/server`: gRPC server wiring and `AppRouter` implementation (connect handshake, chat routing, teardown).
- `docs/hermes-mvp-revised.md`: Revised MVP specification.
- `docs/plan/phase-1/`: Implementation plan and iteration prompts for nodes.
- `docs/wiki/core-node-functionality.md`: Core behavior and operational notes (kept current as features land).
- `AGENT.md`: Mandatory guardrails for testing, deployment, and docs maintenance.
- `release-notes.md`: Latest user-visible changes.

## AppRouter chat flow (single node)
- Connect: app sends `Connect` with ed25519 identity pubkey and signature over node ID + metadata; node replies with `ConnectAck` and registers the session.
- StartChat: each peer sends `StartChat` with `chat_id` and a signed ephemeral pubkey. When both are present the node relays the peer ephemeral key via a `StartChat` frame and acknowledges with `StartChatAck`.
- SendChatMessage: AEAD ciphertext envelopes are relayed across the in-memory tieline; per-sender sequence numbers must be monotonic and are acknowledged with `ChatMessageAck`.
- DeleteChat: caller triggers teardown and key erasure; both peers receive `DeleteChatAck` (`deleted` / `deleted_by_peer`).
- Heartbeat: echoed to keep the stream warm and track liveness.

## Contributing
- Follow the iteration prompts; do not skip milestones.
- Keep tests, Docker workflows, and documentation in sync with code changes as enforced by `AGENT.md`.
