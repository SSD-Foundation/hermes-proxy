# Core Node Functionality (Phase 1)

## Overview
Phase 1 targets a single-node deployment of the HERMES router. The node exposes a gRPC `AppRouter` service that accepts bidirectional streams from Apps, authenticates them with identity keys, and routes encrypted chat frames between two Apps connected to the same node. No NodeMesh, blockchain, or NAT helpers are present in this phase.

Iteration 01 scaffolding is in place: Go module with structured logging/config loader, Argon2id-derived file keystore skeleton (placeholder encryption), in-memory chat registry, and a stubbed `AppRouter.Open` handler wired through the node binary.

## Key behaviors
- **Connection handling**: Node accepts App connections over TLS gRPC, performs identity key verification, and maintains session metadata with keep-alives/heartbeats.
- **Chat lifecycle**: StartChat validates signed ephemeral keys, allocates an in-memory tieline keyed by `chat_id`, and relays encrypted payload envelopes. DeleteChat tears down the tieline and triggers key erasure hooks.
- **Key management**: A file-based keystore (Argon2id-derived master key) stores the node identity key and active per-chat secrets. Deletion wipes chat-specific secrets from memory and storage.
- **Observability**: Structured logs for connect/disconnect, chat creation, routing, and errors; lightweight metrics and health probes exposed locally for testing and container readiness.

## Testing expectations
- Unit tests cover keystore helpers, message framing, and config parsing.
- Component tests run in-process gRPC flows for connect/start chat/send/delete, including failure paths.
- Integration tests use Docker Compose to spin up the node plus two mock apps executing the full happy path and teardown.

## Deployment notes
- Docker image is built via multi-stage Dockerfile; Compose orchestrates local/integration runs.
- Production guidance: deploy the container with a persistent volume for the keystore, inject passphrase via secrets manager, and expose health/metrics endpoints for orchestration probes.

Keep this page synchronized with behavior changes and deployment/test workflow updates.
