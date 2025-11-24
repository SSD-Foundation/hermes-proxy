# Release Notes

## Unreleased
- 2025-11-28: Added keystore-backed chat resume (restores ratchet counters), enforced rekey flag/version validation with per-chat/app throttling and new config knobs, surfaced `hermes_rekeys_total` + `resumed`/`expired` fields in `/crypto/ratchets`, and taught mockapp to drive rekey attempts.
- 2025-11-27: Implemented per-message symmetric ratcheting with persisted send/recv counters, teardown on sequence divergence or expired key lifetimes, new Prometheus ratchet/erasure metrics, admin `/crypto/ratchets` dump, and multi-message mockapp/in-process tests to exercise the ratchet flow.
- 2025-11-26: Wired StartChat/RouteChat to carry key versions + HKDF info/salt and signed X25519 material, deriving and sealing per-chat session keys (local + cross-node) with deterministic replay/mismatch errors; updated mockapp, protos, and component tests to cover the new handshake.
- 2025-11-26: Upgraded keystore to versioned chat-secret records (HKDF metadata, send/recv/mac/ratchet seeds, zeroization, legacy migration), added X25519/HKDF helper library with deterministic key IDs/vectors, crypto config knobs (hash/info label/max key lifetime) with validation, and wired AppRouter to the new chat-secret API.
- 2025-11-25: Added Phase 3 (per-chat PFS) plan with iteration prompts, refreshed AGENT guardrails/README/wiki for PFS scope and testing/deployment expectations.
- 2025-11-24: Hardened integration harness: `make integration` now waits on mock app containers with `docker wait` and fails on missing/failed services; removed obsolete Compose version field to silence CI warnings.
- 2025-11-24: Added churn/failover handling for NodeMesh: membership `FAIL` events and heartbeat evictions now remove peers, stop gossip/route streams, notify AppRouter to tear down remote chats (`route_unavailable`), and expose new mesh metrics for suspected/evicted peers with fresh unit tests.
- 2025-11-24: Delivered cross-node chat routing: StartChat now carries a target app identity (plus FindApp helper), NodeMesh `RouteChat` relays setup/message/teardown with acks, outbound route client pool with TLS, SWIM-style gossip suspicion/eviction and app sync, mockapp flag for target routing, and new two-node component tests (happy path + unknown target/route loss). README/wiki/docs refreshed accordingly.
- 2025-11-23: Landed NodeMesh bootstrap (proto/stubs, signed Join handler + bootstrap dialer/gossip heartbeats), mesh membership/app discovery store, admin `/mesh/members` dump, mesh metrics, app presence tracking in AppRouter, and config for mesh identity/TLS/bootstrap peers with new unit/component coverage.
- 2025-11-23: Added Phase 2 (mesh/discovery) implementation plan, refreshed AGENT guardrails for new testing/deployment expectations, and pointed README to the new plan.
- 2025-11-24: Hardened keystore sealing (Argon2id + XChaCha20-Poly1305 with zeroization), added admin health/metrics endpoints and idle chat cleanup with Prometheus counters, shipped Dockerfile + Compose harness (node + mock apps) and CI integration coverage.
- 2025-11-23: Implemented AppRouter chat plumbing (connect/start chat/send/delete with signed keys), added in-process component tests, aligned CI/docs to Go 1.24+.
- Added Phase 1 node implementation plan, iteration prompts, and AGENT guardrails.
- Established documentation pattern with README and core wiki stub.
- 2025-11-23: Added Go scaffolding for the node (AppRouter proto/stub, config/logging, keystore skeleton, Makefile + CI).
