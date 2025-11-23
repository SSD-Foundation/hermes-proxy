# AGENT Guardrails

This file defines the mandatory operating rules for contributors and automation. Do not merge changes unless these requirements remain satisfied and updated.

## Scope
- Phase 2 focuses on **nodes only**: multi-node mesh membership, discovery, and cross-node chat routing per `docs/plan/phase-2/overview.md`.
- Any change to protocols, state machines, deployment, or testing must update this file, the plan files, and the docs listed below.

## Delivery process
- Follow the Phase 2 iterations in `docs/plan/phase-2/*.md`; do not skip milestones or re-order without updating the plan/overview.
- Every PR must:
  - Update `release-notes.md` with a short entry describing the change and date.
  - Update `README.md` if developer workflows, commands, or entrypoints change (including mesh bootstrap/TLS flags).
  - Update `docs/wiki/core-node-functionality.md` when core behavior, flows, or operational assumptions change.
  - Keep `docs/plan/phase-2/overview.md` and iteration prompts current with any plan adjustments or reprioritizations.
- Require a test plan section in PR descriptions, referencing unit/component/integration coverage touched.

## Testing and coverage strategy
- **Unit tests**: pure functions and small components (keystore crypto helpers, config parsing, membership state machine, routing table updates). Target ≥80% coverage for these packages. Fast, no network/filesystem side effects beyond temp dirs.
- **Component tests**: in-process gRPC servers for AppRouter and NodeMesh; cover connect/auth, StartChat with target app identity, gossip/join flows, RouteChat setup/teardown, message relay ordering, and error cases (bad signatures, unknown targets, backpressure).
- **Integration tests**: Dockerized multi-node harness (see deployment schemes) spinning up at least two node containers and two mock apps exercising cross-node chat, teardown, and a churn scenario (bounce a node). Must run locally via `docker compose` and in CI.
- Any new feature or bug fix must add or update tests in the relevant tier. Do not remove tests without replacements. If a test cannot be added, document why in the PR and the backlog item to close the gap. Keep this strategy updated when coverage expectations shift.

## Deployment schemes (must stay current)
- **Local testing (Dockerized)**:
  - Multi-stage `Dockerfile` builds a slim runtime image.
  - Compose stack runs multiple node containers (with TLS materials), two mock app containers, and optionally a metrics sink. Integration tests orchestrate cross-node chat and churn.
  - Compose must support running unit/component tests inside a node container for parity with CI.
- **CI/CD (GitHub Actions)**:
  - Workflow stages: checkout → lint → unit tests → component tests → build container → multi-node integration tests via Compose → (optional) push image on main tags.
  - Cache proto/toolchain artifacts where possible; fail fast on lint or tests.
- **Production deployment**:
  - Deploy the container image with env-configured secrets (keystore passphrase injected via secret manager) and TLS assets for node↔node/authenticated app↔node traffic.
  - Prefer orchestration (Kubernetes or systemd service) with health/readiness probes exposed; include mesh-specific readiness (e.g., bootstrap success thresholds).
  - Require persistent volume for keystore file; logs to stdout/stderr with structured format; optional metrics endpoint scraping for mesh health.
- Any change to tooling, images, orchestration, trust bundles, or environment variables must update this section and the supporting files.

## Security and key management
- Keystore uses Argon2id-derived master key; enforce sealed storage and tamper detection. On DeleteChat or churn cleanup, erase per-chat secrets from memory and disk on all affected nodes.
- TLS is required for node↔node; prefer TLS (or mTLS) for app↔node when hardening lands. Validate peer identity keys before allocating state; reject malformed frames deterministically.
- Never log private keys or ciphertexts. Redact identifiers where necessary.

## Documentation pattern enforcement
- Files that must stay fresh:
  - `release-notes.md`: append latest user-visible change.
  - `README.md`: include quickstart, commands, mesh bootstrap/TLS guidance, and pointers to plan/wiki.
  - `docs/wiki/core-node-functionality.md`: describe current behaviors, flows, and operational notes (single-node + mesh).
  - `docs/plan/phase-2/overview.md` and `docs/plan/phase-2/*.md`: keep the plan and iteration prompts in sync with decisions.
- Do not merge changes that affect behavior or workflows without updating these documents.

## Non-negotiable checks before merge
- All linters, unit tests, component tests, and integration tests must pass locally and in CI.
- Docker build must succeed; multi-node Compose harness must spin up successfully for integration tests.
- Plan, AGENT, README, wiki, and release notes updated as required above.
