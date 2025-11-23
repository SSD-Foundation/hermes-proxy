# HERMES Nodes (Phase 1 delivered; Phase 2 planning)

This repository tracks the HERMES router nodes. Phase 1 delivers a gRPC-based service that connects Apps, manages encrypted 1:1 chats on a single node, and prepares the groundwork for the mesh, payments, and NAT features that follow. Platform target is Ubuntu Linux. Phase 2 planning (multi-node mesh and discovery) lives under `docs/plan/phase-2/`.

## Getting started
- Read the MVP scope in `docs/hermes-mvp-revised.md`.
- Review the Phase 1 plan and iteration prompts in `docs/plan/phase-1/` and the Phase 2 plan in `docs/plan/phase-2/`.
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
  - `make integration` – build the Docker image and run the Compose harness (node + two mock apps).
  - `make proto` – regenerate gRPC stubs from `proto/app_router.proto`.
  - `go test ./internal/server` – component tests for connect/start chat/send/delete happy path and signature failure.

## Running the node
The binary wires config, structured logging, keystore initialization, and the `AppRouter` gRPC service.

```bash
export HERMES_KEYSTORE_PASSPHRASE=change-me
go run ./cmd/node --config config/dev.yaml
```

If the keystore file does not exist, it is initialized automatically at the configured path. A small admin HTTP server (default `:8080`) serves `GET /healthz`, `GET /readyz`, and Prometheus metrics at `GET /metrics` for container readiness.

## Configuration
Configuration is read from a file plus environment overrides (`HERMES_` prefix). Example:

```yaml
grpc_address: "0.0.0.0:50051"
log_level: "info"
shutdown_grace_period: "10s"
keystore:
  path: "data/keystore.json"
  passphrase_env: "HERMES_KEYSTORE_PASSPHRASE"
admin:
  address: "0.0.0.0:8080"
  read_header_timeout: "5s"
cleanup:
  sweep_interval: "30s"
  session_idle_timeout: "5m"
  chat_idle_timeout: "10m"
grpc_server:
  max_recv_msg_size: 4194304
  max_send_msg_size: 4194304
  keepalive_time: "2m"
  keepalive_timeout: "20s"
  max_connection_idle: "0s" # 0 defers to cleanup.session_idle_timeout
```

## Docker & integration harness
- `docker-compose.dev.yaml` builds/runs the node plus two `mockapp` clients that exercise the happy-path chat flow. Run `make integration` to build the image, start the stack, wait for both apps to exit, and tear everything down.
- The image produced by `Dockerfile` contains both binaries (`node` and `mockapp`), listens on `50051` for gRPC and `8080` for health/metrics, and persists the keystore to `/app/data` (Compose mounts a named volume).
- The admin endpoints exposed in the container are the same as local runs: `/healthz`, `/readyz`, `/metrics`.

## Project structure
- `cmd/node`: Node entrypoint wiring config, logging, keystore, registry, and gRPC server.
- `cmd/mockapp`: Lightweight integration client used by the Compose harness.
- `proto/app_router.proto`: AppRouter protobuf contract; generated code in `pkg/api/approuterpb`.
- `internal/config`: Config loader with env overrides and server tuning defaults.
- `internal/keystore`: Argon2id-derived file backend (sealed storage with tamper detection) with tests.
- `internal/registry`: In-memory chat/tieline registry.
- `internal/server`: gRPC server wiring and `AppRouter` implementation (connect handshake, chat routing, teardown, metrics, housekeeping).
- `docs/hermes-mvp-revised.md`: Revised MVP specification.
- `docs/plan/phase-1/`: Implementation plan and iteration prompts for the delivered single-node scope.
- `docs/plan/phase-2/`: Implementation plan and iteration prompts for the mesh/discovery scope.
- `docs/wiki/core-node-functionality.md`: Core behavior and operational notes (kept current as features land).
- `AGENT.md`: Mandatory guardrails for testing, deployment, and docs maintenance.
- `release-notes.md`: Latest user-visible changes.

## AppRouter chat flow (single node)
- Connect: app sends `Connect` with ed25519 identity pubkey and signature over node ID + metadata; node replies with `ConnectAck` and registers the session.
- StartChat: each peer sends `StartChat` with `chat_id` and a signed ephemeral pubkey. When both are present the node relays the peer ephemeral key via a `StartChat` frame and acknowledges with `StartChatAck`.
- SendChatMessage: AEAD ciphertext envelopes are relayed across the in-memory tieline; per-sender sequence numbers must be monotonic and are acknowledged with `ChatMessageAck`.
- DeleteChat: caller triggers teardown and key erasure; both peers receive `DeleteChatAck` (`deleted` / `deleted_by_peer`).
- Housekeeping: idle chats are expired by the server (`cleanup.chat_idle_timeout`) and return `DeleteChatAck` with `expired`; per-chat secrets and ephemeral keys are wiped from memory and the keystore.
- Heartbeat: echoed to keep the stream warm and track liveness.

## Contributing
- Follow the iteration prompts; do not skip milestones.
- Keep tests, Docker workflows, and documentation in sync with code changes as enforced by `AGENT.md`.
