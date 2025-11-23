# Iteration 03 – Hardening & Delivery

## Objective
Solidify security, observability, and delivery for the Phase 1 node; ship Docker/CI artifacts and documentation for repeatable testing and operation.

## Key work
- Complete keystore encryption (Argon2id-derived master key, sealed storage, tamper detection) and memory hygiene for per-chat keys.
- Add metrics/logging for sessions, active chats, errors, and latency; expose health/readiness probes for container use.
- Implement cleanup routines for idle chats and disconnected apps.
- Optimize server configuration (gRPC keep-alives, limits, backpressure) and validate error budget handling.
- Add integration test harness via Docker Compose: node + two mock app containers executing chat happy path and teardown.
- Finalize Dockerfile (multi-stage), compose file for local dev/test, and GitHub Actions workflow for build/test/publish image.
- Refresh documentation: README quickstart, release-notes update, AGENT guardrails confirmation, wiki additions for core behaviors.

## Exit criteria
- Integration tests pass locally and in CI via Dockerized harness.
- Keystore stores encrypted keys at rest; deletion flow wipes chat-specific secrets.
- Health and metrics endpoints function inside container.
- Release notes and wiki reflect the delivered Phase 1 node; AGENT requirements remain satisfied.
