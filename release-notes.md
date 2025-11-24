# Release Notes

## Unreleased
- 2025-11-24: Delivered cross-node chat routing: StartChat now carries a target app identity (plus FindApp helper), NodeMesh `RouteChat` relays setup/message/teardown with acks, outbound route client pool with TLS, SWIM-style gossip suspicion/eviction and app sync, mockapp flag for target routing, and new two-node component tests (happy path + unknown target/route loss). README/wiki/docs refreshed accordingly.
- 2025-11-23: Landed NodeMesh bootstrap (proto/stubs, signed Join handler + bootstrap dialer/gossip heartbeats), mesh membership/app discovery store, admin `/mesh/members` dump, mesh metrics, app presence tracking in AppRouter, and config for mesh identity/TLS/bootstrap peers with new unit/component coverage.
- 2025-11-23: Added Phase 2 (mesh/discovery) implementation plan, refreshed AGENT guardrails for new testing/deployment expectations, and pointed README to the new plan.
- 2025-11-24: Hardened keystore sealing (Argon2id + XChaCha20-Poly1305 with zeroization), added admin health/metrics endpoints and idle chat cleanup with Prometheus counters, shipped Dockerfile + Compose harness (node + mock apps) and CI integration coverage.
- 2025-11-23: Implemented AppRouter chat plumbing (connect/start chat/send/delete with signed keys), added in-process component tests, aligned CI/docs to Go 1.24+.
- Added Phase 1 node implementation plan, iteration prompts, and AGENT guardrails.
- Established documentation pattern with README and core wiki stub.
- 2025-11-23: Added Go scaffolding for the node (AppRouter proto/stub, config/logging, keystore skeleton, Makefile + CI).
