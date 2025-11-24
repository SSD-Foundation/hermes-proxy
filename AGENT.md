# AGENT Guardrails

This file defines the mandatory operating rules for contributors and automation. Do not merge changes unless these requirements remain satisfied and updated.

## Scope
- Phase 3 focuses on **nodes only**: per-chat perfect forward secrecy (X25519 + HKDF), signed key exchange, symmetric ratcheting, and deterministic key erasure across single-node and mesh routing per `docs/plan/phase-3/overview.md`.
- Any change to protocols, state machines, deployment, or testing must update this file, the plan files, and the docs listed below.

## Delivery process
- Follow the Phase 3 iterations in `docs/plan/phase-3/*.md`; do not skip milestones or re-order without updating the plan/overview.
- Every PR must:
  - Update `release-notes.md` with a short entry describing the change and date.
  - Update `README.md` if developer workflows, commands, or entrypoints change (including mesh bootstrap/TLS flags and PFS/ratchet knobs).
  - Update `docs/wiki/core-node-functionality.md` when core behavior, flows, or operational assumptions change (including crypto lifecycle and teardown semantics).
  - Keep `docs/plan/phase-3/overview.md` and iteration prompts current with any plan adjustments or reprioritizations.
- Require a test plan section in PR descriptions, referencing unit/component/integration coverage touched.

## Testing and coverage strategy
- **Unit tests**: pure functions and small components (keystore crypto helpers, chat-secret record migrations, config parsing/validation for crypto knobs, membership state machine, routing table updates). Target ≥80% coverage for these packages. Fast, no network/filesystem side effects beyond temp dirs.
- **Component tests**: in-process gRPC servers for AppRouter and NodeMesh; cover connect/auth, StartChat with target app identity and signed X25519 keys, replay/mismatch errors, rekey attempts, gossip/join flows, RouteChat setup/teardown, message relay ordering, and ratchet-triggered teardowns.
- **Integration tests**: Dockerized multi-node harness (see deployment schemes) spinning up at least two node containers and two mock apps exercising StartChat → messaging with ratchets → rekey → restart/resume → teardown/churn (bounce a node) with sealed keystore reload. Must run locally via `docker compose`/`scripts/run-restart-resume.sh` and in CI.
- Any new feature or bug fix must add or update tests in the relevant tier. Do not remove tests without replacements. If a test cannot be added, document why in the PR and the backlog item to close the gap. Keep this strategy updated when coverage expectations shift.

## Deployment schemes (must stay current)
- **Local testing (Dockerized)**:
  - Multi-stage `Dockerfile` builds a slim runtime image.
  - Compose stack runs multiple node containers (with TLS materials), two mock app containers, and optionally a metrics sink. Integration tests orchestrate PFS flows (handshake, ratchet, rekey, restart/resume, teardown/churn) via `docker-compose.rekey-resume.yaml` and `scripts/run-restart-resume.sh` (forces SIGKILL restart and sealed keystore reload).
  - Compose must support running unit/component tests inside a node container for parity with CI.
- **CI/CD (GitHub Actions)**:
  - Workflow stages: checkout → lint → unit tests → component tests → build container → multi-node integration tests via the restart/resume Compose harness (`docker-compose.rekey-resume.yaml` + `make integration`) → (optional) push image on main tags.
  - Cache proto/toolchain artifacts where possible; fail fast on lint or tests.
- **Production deployment**:
  - Deploy the container image with env-configured secrets (keystore passphrase injected via secret manager) and TLS assets for node↔node/authenticated app↔node traffic.
  - Prefer orchestration (Kubernetes or systemd service) with health/readiness probes exposed; include mesh-specific readiness (e.g., bootstrap success thresholds) and crypto lifecycle health (e.g., ratchet freshness, keystore mount).
  - Require persistent volume for keystore file; logs to stdout/stderr with structured format; optional metrics endpoint scraping for mesh health and key lifecycle counters.
- Any change to tooling, images, orchestration, trust bundles, or environment variables must update this section and the supporting files.

## Security and key management
- Keystore uses Argon2id-derived master key; enforce sealed storage and tamper detection. Persisted ratchet state (keys + send/recv counters) must be reloaded on resume; rekey attempts must bump key versions and are throttled per chat/app with deterministic errors. On DeleteChat, rekey/ratchet teardown, expiry, or churn cleanup, erase per-chat secrets from memory and disk on all affected nodes.
- PFS primitives: identity keys remain Ed25519; per-chat keys use X25519 with HKDF-derived send/recv/mac/ratchet material and versioning. Reject unsigned or replayed key material; throttle retries.
- TLS is required for node↔node; prefer TLS (or mTLS) for app↔node when hardening lands. Validate peer identity keys before allocating state; reject malformed frames deterministically.
- Never log private keys or ciphertexts. Redact identifiers where necessary.

## Documentation pattern enforcement
- Files that must stay fresh:
  - `release-notes.md`: append latest user-visible change.
  - `README.md`: include quickstart, commands, mesh bootstrap/TLS/PFS guidance, and pointers to plan/wiki.
  - `docs/wiki/core-node-functionality.md`: describe current behaviors, flows, and operational notes (single-node + mesh + crypto lifecycle).
  - `docs/plan/phase-3/overview.md` and `docs/plan/phase-3/*.md`: keep the plan and iteration prompts in sync with decisions.
- Do not merge changes that affect behavior or workflows without updating these documents.

## Non-negotiable checks before merge
- All linters, unit tests, component tests, and integration tests must pass locally and in CI.
- Docker build must succeed; multi-node Compose harness must spin up successfully for integration tests.
- Plan, AGENT, README, wiki, and release notes updated as required above.
