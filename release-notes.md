# Release Notes

## Unreleased
- 2025-11-23: Added Phase 2 (mesh/discovery) implementation plan, refreshed AGENT guardrails for new testing/deployment expectations, and pointed README to the new plan.
- 2025-11-24: Hardened keystore sealing (Argon2id + XChaCha20-Poly1305 with zeroization), added admin health/metrics endpoints and idle chat cleanup with Prometheus counters, shipped Dockerfile + Compose harness (node + mock apps) and CI integration coverage.
- 2025-11-23: Implemented AppRouter chat plumbing (connect/start chat/send/delete with signed keys), added in-process component tests, aligned CI/docs to Go 1.24+.
- Added Phase 1 node implementation plan, iteration prompts, and AGENT guardrails.
- Established documentation pattern with README and core wiki stub.
- 2025-11-23: Added Go scaffolding for the node (AppRouter proto/stub, config/logging, keystore skeleton, Makefile + CI).
