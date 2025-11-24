# HERMES Nodes (Phase 2 – mesh bootstrap)

This repository tracks the HERMES router nodes. Phase 1 delivers a gRPC-based service that connects Apps, manages encrypted 1:1 chats on a single node, and prepares the groundwork for the mesh, payments, and NAT features that follow. Phase 2 layers NodeMesh membership, peer discovery, and cross-node routing (implemented) on top of the existing chat plumbing. Phase 3 (per-chat PFS with signed X25519 exchange, HKDF-derived session keys, and ratcheting) is now planned in `docs/plan/phase-3/` while implementation is in progress. Platform target is Ubuntu Linux; the Phase 2 plan lives under `docs/plan/phase-2/`.

## Getting started
- Read the MVP scope in `docs/hermes-mvp-revised.md`.
- Review the Phase 1 plan and iteration prompts in `docs/plan/phase-1/`, the Phase 2 plan in `docs/plan/phase-2/`, and the Phase 3 PFS plan in `docs/plan/phase-3/`.
- The gRPC contracts live in `proto/app_router.proto` and `proto/nodemesh.proto` with generated Go stubs in `pkg/api/approuterpb` and `pkg/api/nodemeshpb`.
- The node binary entrypoint is `cmd/node` and hosts both `AppRouter.Open` (app connect/start chat/send/delete) and the new `NodeMesh` service for join/gossip/route envelopes.

## Development workflow
- Install Go 1.24+ and ensure `protoc` with the Go plugins is available if regenerating protobufs.
- Set `HERMES_KEYSTORE_PASSPHRASE` (or another env set in config) so the keystore backend can initialize/unlock node identity + chat secrets.
- Common tasks:
  - `make fmt` – format the Go sources.
  - `make lint` – run `go vet`.
  - `make test` – run unit + component tests (AppRouter flows + NodeMesh join/membership).
  - `make build` – build all packages.
  - `make integration` – build the Docker image and run the Compose harness (node + two mock apps).
  - `make proto` – regenerate gRPC stubs from `proto/app_router.proto` and `proto/nodemesh.proto`.
  - `go test ./internal/server` – component tests for connect/start chat/send/delete happy path, signature failure, and cross-node routing.

## Running the node
The binary wires config, structured logging, keystore initialization, and the `AppRouter` gRPC service.

```bash
export HERMES_KEYSTORE_PASSPHRASE=change-me
go run ./cmd/node --config config/dev.yaml
```

If the keystore file does not exist, it is initialized automatically at the configured path. A small admin HTTP server (default `:8080`) serves `GET /healthz`, `GET /readyz`, Prometheus metrics at `GET /metrics`, and a membership dump at `GET /mesh/members` for mesh debugging. Mesh metrics include node counts, join/app sync counters, and churn visibility (`hermes_mesh_suspected_peers`, `hermes_mesh_evicted_peers_total`).

## Configuration
Configuration is read from a file plus environment overrides (`HERMES_` prefix). Example:

```yaml
grpc_address: "0.0.0.0:50051"
log_level: "info"
shutdown_grace_period: "10s"
keystore:
  path: "data/keystore.json"
  passphrase_env: "HERMES_KEYSTORE_PASSPHRASE"
mesh:
  node_id: "hermes-dev"
  public_address: "127.0.0.1:50051" # what other nodes should dial
  identity_secret: "mesh_identity"   # keystore key used for node identity
  wallet: ""                         # placeholder until staking/payments land
  bootstrap_peers: []
  tls:
    enabled: false
    cert_path: ""
    key_path: ""
    ca_path: ""
    insecure_skip_verify: false
  gossip:
    dial_interval: "3s"
    heartbeat_interval: "15s"
admin:
  address: "0.0.0.0:8080"
  read_header_timeout: "5s"
cleanup:
  sweep_interval: "30s"
  session_idle_timeout: "5m"
  chat_idle_timeout: "10m"
crypto:
  hkdf_hash: "sha256"
  hkdf_info_label: "hermes-chat-session"
  max_key_lifetime: "24h"
grpc_server:
  max_recv_msg_size: 4194304
  max_send_msg_size: 4194304
  keepalive_time: "2m"
  keepalive_timeout: "20s"
  max_connection_idle: "0s" # 0 defers to cleanup.session_idle_timeout
crypto:
  hkdf_hash: "sha256"              # sha256 or sha512
  hkdf_info_label: "hermes-chat-session"
  max_key_lifetime: "24h"          # bounds validated at startup
```

Crypto parameters govern the HKDF hash/info label used for per-chat derivation and the maximum key lifetime before rekey; invalid values are rejected at startup.

## Mesh bootstrap
- Node identity (ed25519) is stored in the sealed keystore under `mesh.identity_secret` and advertised during `NodeMesh.Join` alongside the node ID, wallet placeholder, and public endpoint.
- Bootstrap peers are configured under `mesh.bootstrap_peers`; the dialer signs Join requests, validates peer signatures, merges membership snapshots, and opens a heartbeat `Gossip` stream with backoff plus SWIM-like suspicion/eviction. Periodic AppSync frames propagate app presence updates.
- When a peer is declared failed (gossip `FAIL` event or heartbeat timeout), gossip/route streams to that node are closed, routing/app entries are purged, and AppRouter tears down chats involving that node with a `route_unavailable` status.
- Connected apps are registered in an in-memory discovery map keyed by app identity; the routing table merges local registrations with mesh AppSync/state for discovery and target resolution.
- Node-to-node `RouteChat` streams are pooled per peer (TLS optional) to relay `SetupTieline`/`RelayMessage`/`TeardownTieline` envelopes with ACKs and backpressure handling.
- TLS between nodes is configurable under `mesh.tls` (disabled by default for dev/test); when enabled the gRPC server uses the provided cert/key and optional CA for peer auth and the dialer/route pool reuse the same materials for outbound streams.

## Docker & integration harness
- `docker-compose.dev.yaml` builds/runs the node plus two `mockapp` clients that exercise the happy-path chat flow. Run `make integration` to build the image, start the stack, wait for both apps to exit, and tear everything down.
- The image produced by `Dockerfile` contains both binaries (`node` and `mockapp`), listens on `50051` for gRPC and `8080` for health/metrics, and persists the keystore to `/app/data` (Compose mounts a named volume).
- The admin endpoints exposed in the container are the same as local runs: `/healthz`, `/readyz`, `/metrics`.

## Project structure
- `cmd/node`: Node entrypoint wiring config, logging, keystore, registry, and gRPC server.
- `cmd/mockapp`: Lightweight integration client used by the Compose harness.
- `proto/app_router.proto`: AppRouter protobuf contract; generated code in `pkg/api/approuterpb`.
- `proto/nodemesh.proto`: NodeMesh protobuf contract (Join/Gossip/RouteChat envelopes); generated code in `pkg/api/nodemeshpb`.
- `internal/config`: Config loader with env overrides and server tuning defaults.
- `internal/keystore`: Argon2id-derived file backend (sealed storage with tamper detection) with tests.
- `internal/crypto/pfs`: X25519 helpers (key IDs, shared secret) and HKDF derivation for send/recv/mac/ratchet material with deterministic vectors.
- `internal/registry`: In-memory chat/tieline registry and app presence map.
- `internal/mesh`: NodeMesh membership store, gRPC server, and bootstrap dialer.
- `internal/server`: gRPC server wiring, `AppRouter` implementation (connect handshake, chat routing, teardown, metrics, housekeeping), NodeMesh service, and admin endpoints.
- `docs/hermes-mvp-revised.md`: Revised MVP specification.
- `docs/plan/phase-1/`: Implementation plan and iteration prompts for the delivered single-node scope.
- `docs/plan/phase-2/`: Implementation plan and iteration prompts for the mesh/discovery scope.
- `docs/plan/phase-3/`: Implementation plan and iteration prompts for per-chat PFS (key exchange, HKDF, ratcheting, erasure).
- `docs/wiki/core-node-functionality.md`: Core behavior and operational notes (kept current as features land).
- `AGENT.md`: Mandatory guardrails for testing, deployment, and docs maintenance.
- `release-notes.md`: Latest user-visible changes.

## AppRouter chat flow (single + cross-node)
- Connect: app sends `Connect` with ed25519 identity pubkey and signature over node ID + metadata; node replies with `ConnectAck`, registers the session, and syncs app presence into the routing table.
- StartChat: each peer sends `StartChat` with `chat_id`, `target_app_id` (optional `target_node_hint`), and a signed ephemeral pubkey. The node resolves the target via the routing table (local registry + mesh AppSync) and opens/joins a `RouteChat` tieline if the target lives on another node. `StartChatAck` is sent once accepted; the peer’s ephemeral key is delivered via a server-initiated `StartChat` frame once both keys are present. `FindApp` frames return the hosting node for a target app identity.
- SendChatMessage: AEAD ciphertext envelopes are relayed locally or over `RouteChat`; per-sender sequence numbers must be monotonic. `ChatMessageAck` is emitted after the remote hop ACKs to preserve end-to-end backpressure across nodes.
- DeleteChat: caller triggers teardown and key erasure; both peers receive `DeleteChatAck` (`deleted` / `deleted_by_peer`). Route loss or remote teardown returns `DeleteChatAck` with `route_closed`/`route_unavailable` as appropriate.
- Housekeeping: idle chats are expired by the server (`cleanup.chat_idle_timeout`), propagate a remote teardown, and return `DeleteChatAck` with `expired`; per-chat secrets and ephemeral keys are wiped from memory and the keystore.
- Heartbeat: echoed to keep the stream warm and track liveness.

## Contributing
- Follow the iteration prompts; do not skip milestones.
- Keep tests, Docker workflows, and documentation in sync with code changes as enforced by `AGENT.md`.
