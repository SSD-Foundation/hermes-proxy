# AGENT Guardrails

This file defines the mandatory operating rules for contributors and automation. Do not merge changes unless these requirements remain satisfied and updated.

## Scope
- Focus is **nodes only** for Phase 1 per `docs/plan/phase-1/overview.md`.
- Any change to protocols, state machines, deployment, or testing must update this file, the plan files, and the docs listed below.

## Delivery process
- Follow the Phase 1 iterations in `docs/plan/phase-1/*.md`; do not skip milestones.
- Every PR must:
  - Update `release-notes.md` with a short entry describing the change and date.
  - Update `README.md` if developer workflows, commands, or entrypoints change.
  - Update the wiki page `docs/wiki/core-node-functionality.md` when core behavior, flows, or assumptions change.
  - Keep `docs/plan/phase-1/overview.md` current with any plan adjustments.
- Require a test plan section in PR descriptions, referencing unit/component/integration coverage touched.

## Testing and coverage strategy
- **Unit tests**: pure functions and small components (keystore crypto helpers, config parsing, message framing). Target ≥80% coverage for these packages. Fast, no network/filesystem side effects beyond temp dirs.
- **Component tests**: in-process gRPC server with mock apps; cover connect/auth, StartChat, SendChatMessage, DeleteChat, error cases. Validate logging/metrics emission where practical.
- **Integration tests**: Dockerized harness (see deployment schemes) spinning up a node container and two mock app clients executing the happy path + teardown. Must run locally via `docker compose` and in CI.
- Any new feature or bug fix must add or update tests in the relevant tier. Do not remove tests without replacements. If a test cannot be added, document why in the PR and the backlog item to close the gap.

## Deployment schemes (must stay current)
- **Local testing (Dockerized)**:
  - Multi-stage `Dockerfile` builds a slim runtime image.
  - `docker-compose.dev.yaml` (name tbd) runs: node container, two mock app containers, and optionally a metrics sink. Integration tests orchestrate chat flows.
  - Compose must support running unit/component tests inside the node container for parity with CI.
- **CI/CD (GitHub Actions)**:
  - Workflow stages: checkout → lint → unit tests → component tests → build container → integration tests via Compose → (optional) push image on main tags.
  - Cache proto/toolchain artifacts where possible; fail fast on lint or tests.
- **Production deployment**:
  - Deploy the container image with env-configured secrets (keystore passphrase injected via secret manager). Prefer orchestration (Kubernetes or systemd service) with health/readiness probes exposed.
  - Require persistent volume for keystore file; logs to stdout/stderr with structured format; optional metrics endpoint scraping.
- Any change to tooling, images, orchestration, or environment variables must update this section and the supporting files.

## Security and key management
- Keystore uses Argon2id-derived master key; enforce sealed storage and tamper detection. On DeleteChat, erase per-chat secrets from memory and disk.
- Never log private keys or ciphertexts. Redact identifiers where necessary.
- gRPC endpoints must validate signatures before allocating state; reject malformed frames deterministically.

## Documentation pattern enforcement
- Files that must stay fresh:
  - `release-notes.md`: append latest user-visible change.
  - `README.md`: include quickstart, commands, and pointers to plan/wiki.
  - `docs/wiki/core-node-functionality.md`: describe current behaviors, flows, and operational notes.
- Do not merge changes that affect behavior without updating these documents.

## Non-negotiable checks before merge
- All linters, unit tests, component tests, and integration tests must pass locally and in CI.
- Docker build must succeed; Compose harness must spin up successfully for integration tests.
- Plan, AGENT, README, wiki, and release notes updated as required above.
