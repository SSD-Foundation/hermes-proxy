# Core Node Functionality (Phase 2 bootstrap)

## Overview
The node hosts both the `AppRouter` (app-facing chat stream) and `NodeMesh` (node-facing join/gossip/routing) services. Nodes authenticate each other with signed `Join` requests, exchange membership snapshots, sync app presence, and route chats across nodes over `RouteChat` streams with the same ordering/teardown semantics as single-node ties.

Phase 3 will extend this behavior with per-chat PFS (signed X25519 exchange, HKDF-derived session keys, symmetric ratchets, deterministic erasure); the plan lives in `docs/plan/phase-3/` and implementation is pending.

## Key behaviors
- **Connection handling**: Node accepts App connections over gRPC, verifies `Connect` signatures (ed25519 over node ID + metadata), assigns a session ID, and echoes `Heartbeat` frames. Backpressure on the send buffer is treated as fatal; keepalives and message size limits bound resource use. Connected apps are recorded in an in-memory discovery map keyed by app identity (hex-encoded ed25519 pubkey) and pushed into the routing table and mesh AppSync frames.
- **Chat lifecycle**: `StartChat` frames carry `chat_id`, `target_app_id`, and a signed ephemeral public key. The node validates signatures against the identity key, resolves the target via the routing table (local app registry + mesh AppSync), and, once both keys are present, relays the peer ephemeral key via a server-initiated `StartChat` frame and acknowledges with `StartChatAck`. `SendChatMessage` enforces monotonic per-sender sequence numbers and relays ciphertext envelopes locally or across nodes; `ChatMessageAck` is emitted after the remote hop ACKs to preserve backpressure. `DeleteChat` tears down the tieline, sends a remote teardown when applicable, and notifies peers (`deleted` / `deleted_by_peer` or `route_closed`/`route_unavailable`); idle chats expire automatically (`expired` status) and wipe their secrets.
- **RouteChat streams**: NodeMesh `RouteChat` carries `SetupTieline`/`RelayMessage`/`TeardownTieline` with `RelayAck` responses. Outbound route streams are pooled per peer (TLS optional), and `RouteError` frames surface deterministic failures (unknown target, bad sequence, route loss) back to the initiating app via AppRouter errors/teardowns.
- **NodeMesh join/gossip**: `NodeMesh.Join` validates the peer’s signature over its descriptor (node ID, endpoint, identity key, metadata), persists the peer with a heartbeat timestamp, merges the membership snapshot, and syncs app presence. The outbound dialer signs Join requests to bootstrap peers with backoff, opens heartbeat `Gossip` streams, periodically app-syncs, and runs SWIM-style suspicion/eviction (membership deltas are gossiped on eviction). When a peer is marked failed, gossip/route streams to it are closed, routing/app entries are dropped, and AppRouter is notified to tear down chats involving that node.
- **Key management**: A file-based keystore (Argon2id-derived master key via Argon2id + XChaCha20-Poly1305) stores node identity material (`mesh.identity_secret`) and per-chat combined ephemeral secrets. Secrets are sealed with tamper detection and zeroed on overwrite/delete; chat participant and remote ephemeral keys are zeroed when chats end or expire.
- **Observability**: Structured logs for connect/disconnect, chat creation, routing, join attempts, and gossip heartbeats. Prometheus metrics cover router counts/errors/latency plus mesh gauges/counters (`hermes_mesh_nodes`, join success/failure, heartbeats, app sync, `hermes_mesh_suspected_peers`, `hermes_mesh_evicted_peers_total`). Admin HTTP exposes `/healthz`, `/readyz`, `/metrics`, and `/mesh/members` for membership debugging.

## Testing expectations
- Unit tests cover keystore helpers, message framing, config parsing, membership store merges, and mesh identity validation.
- Component tests run in-process gRPC flows for connect/start chat/send/delete (happy path + invalid signature) plus idle chat expiry; mesh component tests exercise `NodeMesh.Join` (snapshot merge + signature failure) and bootstrap dialer flows.
- Integration tests use Docker Compose (`docker-compose.dev.yaml`) to spin up the node plus two `mockapp` containers executing the full happy path and teardown (`make integration`).

## Deployment notes
- Docker image is built via multi-stage Dockerfile (node + mockapp binaries); Compose orchestrates local/integration runs (`make integration`).
- Admin endpoints on `:8080` expose health, mesh membership, and Prometheus metrics; mount a persistent volume for `/app/data` to retain the keystore and inject the passphrase via secrets manager.
- NodeMesh TLS is configurable (`mesh.tls.*`); when enabled, the gRPC server uses the provided cert/key (optional CA for client auth), and the dialer uses the same materials for peer verification.

Keep this page synchronized with behavior changes and deployment/test workflow updates.
