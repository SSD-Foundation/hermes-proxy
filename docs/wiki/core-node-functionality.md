# Core Node Functionality (Phase 1)

## Overview
Phase 1 targets a single-node deployment of the HERMES router. The node exposes a gRPC `AppRouter` service that accepts bidirectional streams from Apps, authenticates them with identity keys, and routes encrypted chat frames between two Apps connected to the same node. No NodeMesh, blockchain, or NAT helpers are present in this phase. Iteration 03 hardens key storage, observability, and delivery (Docker/Compose + CI integration) on top of the chat plumbing.

## Key behaviors
- **Connection handling**: Node accepts App connections over gRPC, verifies `Connect` signatures (ed25519 over node ID + metadata), assigns a session ID, and echoes `Heartbeat` frames. Backpressure on the send buffer is treated as fatal; keepalives and message size limits are set to bound resource use.
- **Chat lifecycle**: `StartChat` frames carry a signed ephemeral public key; the node validates the signature against the identity key and, once both peers register the same `chat_id`, relays the peer ephemeral key via a server-initiated `StartChat` frame and acknowledges with `StartChatAck`. `SendChatMessage` enforces monotonic per-sender sequence numbers and relays ciphertext envelopes, acknowledging each hop. `DeleteChat` tears down the tieline and notifies both peers (`deleted` / `deleted_by_peer` statuses); idle chats expire automatically (`expired` status) and wipe their secrets.
- **Key management**: A file-based keystore (Argon2id-derived master key via Argon2id + XChaCha20-Poly1305) stores node identity material and per-chat combined ephemeral secrets. Secrets are sealed with tamper detection and zeroed on overwrite/delete; chat participant ephemeral keys are zeroed when chats end or expire.
- **Observability**: Structured logs for connect/disconnect, chat creation, routing, and errors; Prometheus metrics (`hermes_sessions_active`, `hermes_chats_active`, router errors/latency) plus `/healthz` and `/readyz` probes exposed on the admin HTTP listener.

## Testing expectations
- Unit tests cover keystore helpers, message framing, and config parsing.
- Component tests run in-process gRPC flows for connect/start chat/send/delete (happy path + invalid signature) plus idle chat expiry.
- Integration tests use Docker Compose (`docker-compose.dev.yaml`) to spin up the node plus two `mockapp` containers executing the full happy path and teardown (`make integration`).

## Deployment notes
- Docker image is built via multi-stage Dockerfile (node + mockapp binaries); Compose orchestrates local/integration runs (`make integration`).
- Admin endpoints on `:8080` expose health and Prometheus metrics; mount a persistent volume for `/app/data` to retain the keystore and inject the passphrase via secrets manager.

Keep this page synchronized with behavior changes and deployment/test workflow updates.
