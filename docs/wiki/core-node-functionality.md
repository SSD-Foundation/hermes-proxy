# Core Node Functionality (Phase 2 bootstrap)

## Overview
The node now hosts both the `AppRouter` (app-facing chat stream) and `NodeMesh` (node-facing join/gossip/routing) services. Nodes authenticate each other with signed `Join` requests, exchange membership snapshots, and track connected apps for discovery ahead of cross-node routing. RouteChat envelopes exist in the proto but are stubbed until the routing iteration lands.

## Key behaviors
- **Connection handling**: Node accepts App connections over gRPC, verifies `Connect` signatures (ed25519 over node ID + metadata), assigns a session ID, and echoes `Heartbeat` frames. Backpressure on the send buffer is treated as fatal; keepalives and message size limits bound resource use. Connected apps are recorded in an in-memory discovery map keyed by app identity (hex-encoded ed25519 pubkey) for mesh sharing.
- **Chat lifecycle**: `StartChat` frames carry a signed ephemeral public key; the node validates the signature against the identity key and, once both peers register the same `chat_id`, relays the peer ephemeral key via a server-initiated `StartChat` frame and acknowledges with `StartChatAck`. `SendChatMessage` enforces monotonic per-sender sequence numbers and relays ciphertext envelopes, acknowledging each hop. `DeleteChat` tears down the tieline and notifies both peers (`deleted` / `deleted_by_peer` statuses); idle chats expire automatically (`expired` status) and wipe their secrets.
- **NodeMesh join/gossip**: `NodeMesh.Join` validates the peer’s signature over its descriptor (node ID, endpoint, identity key, metadata), persists the peer with a heartbeat timestamp, merges the membership snapshot, and syncs app presence. The outbound dialer signs Join requests to bootstrap peers with backoff and opens a `Gossip` stream that sends periodic heartbeats; app sync frames merge remote app presence for future routing.
- **Key management**: A file-based keystore (Argon2id-derived master key via Argon2id + XChaCha20-Poly1305) stores node identity material (`mesh.identity_secret`) and per-chat combined ephemeral secrets. Secrets are sealed with tamper detection and zeroed on overwrite/delete; chat participant ephemeral keys are zeroed when chats end or expire.
- **Observability**: Structured logs for connect/disconnect, chat creation, routing, join attempts, and gossip heartbeats. Prometheus metrics cover router counts/errors/latency plus mesh gauges/counters (`hermes_mesh_nodes`, join success/failure, heartbeats, app sync). Admin HTTP exposes `/healthz`, `/readyz`, `/metrics`, and `/mesh/members` for membership debugging.

## Testing expectations
- Unit tests cover keystore helpers, message framing, config parsing, membership store merges, and mesh identity validation.
- Component tests run in-process gRPC flows for connect/start chat/send/delete (happy path + invalid signature) plus idle chat expiry; mesh component tests exercise `NodeMesh.Join` (snapshot merge + signature failure) and bootstrap dialer flows.
- Integration tests use Docker Compose (`docker-compose.dev.yaml`) to spin up the node plus two `mockapp` containers executing the full happy path and teardown (`make integration`).

## Deployment notes
- Docker image is built via multi-stage Dockerfile (node + mockapp binaries); Compose orchestrates local/integration runs (`make integration`).
- Admin endpoints on `:8080` expose health, mesh membership, and Prometheus metrics; mount a persistent volume for `/app/data` to retain the keystore and inject the passphrase via secrets manager.
- NodeMesh TLS is configurable (`mesh.tls.*`); when enabled, the gRPC server uses the provided cert/key (optional CA for client auth), and the dialer uses the same materials for peer verification.

Keep this page synchronized with behavior changes and deployment/test workflow updates.
