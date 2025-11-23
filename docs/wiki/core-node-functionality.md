# Core Node Functionality (Phase 1)

## Overview
Phase 1 targets a single-node deployment of the HERMES router. The node exposes a gRPC `AppRouter` service that accepts bidirectional streams from Apps, authenticates them with identity keys, and routes encrypted chat frames between two Apps connected to the same node. No NodeMesh, blockchain, or NAT helpers are present in this phase. Iteration 02 delivers chat plumbing end-to-end (connect → start chat → send → delete) with in-memory tielines.

## Key behaviors
- **Connection handling**: Node accepts App connections over TLS gRPC, verifies `Connect` signatures (ed25519 over node ID + metadata), assigns a session ID, and echoes `Heartbeat` frames. Backpressure on the send buffer is treated as fatal to protect the node.
- **Chat lifecycle**: `StartChat` frames carry a signed ephemeral public key; the node validates the signature against the identity key and, once both peers register the same `chat_id`, relays the peer ephemeral key via a server-initiated `StartChat` frame and acknowledges with `StartChatAck`. `SendChatMessage` enforces monotonic per-sender sequence numbers and relays ciphertext envelopes, acknowledging each hop. `DeleteChat` tears down the tieline and notifies both peers (`deleted` / `deleted_by_peer` statuses).
- **Key management**: A file-based keystore (Argon2id-derived master key) stores the node identity key and active per-chat secrets (combined ephemeral keys). Deletion wipes chat-specific secrets from memory and storage.
- **Observability**: Structured logs for connect/disconnect, chat creation, routing, and errors; lightweight metrics and health probes exposed locally for testing and container readiness.

## Testing expectations
- Unit tests cover keystore helpers, message framing, and config parsing.
- Component tests run in-process gRPC flows for connect/start chat/send/delete (happy path + invalid signature).
- Integration tests use Docker Compose to spin up the node plus two mock apps executing the full happy path and teardown.

## Deployment notes
- Docker image is built via multi-stage Dockerfile; Compose orchestrates local/integration runs.
- Production guidance: deploy the container with a persistent volume for the keystore, inject passphrase via secrets manager, and expose health/metrics endpoints for orchestration probes.

Keep this page synchronized with behavior changes and deployment/test workflow updates.
