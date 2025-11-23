# Iteration 01 – Foundations

## Objective
Stand up the node development scaffold with gRPC contracts, keystore interface, and basic tooling to compile, lint, and test. No chat routing yet.

## Key work
- Draft `app_router.proto` with envelope frames for connect/auth, chat control, messaging, and errors; generate server stubs.
- Establish project layout (cmd/node, internal/*, pkg/*) and dependency management.
- Implement config loading (env + file), structured logging, and graceful shutdown for the node process.
- Define `KeyBackend` interface and file-based keystore skeleton (Argon2id master key derivation, versioned file format, placeholder encrypt/decrypt).
- Add placeholder chat/tieline registry API and data models to unblock later handlers.
- Create `Makefile` (or scripts) for build, lint, and tests; wire linting/static analysis.
- Set up unit test harness and CI workflow stub that runs lint + unit tests.

## Exit criteria
- Proto compiles; gRPC server boots and exposes an empty `AppRouter.Open` handler.
- Keystore interface + file implementation compile with unit tests covering config parsing, key derivation scaffolding, and error handling.
- CI workflow green on lint + unit tests; Make targets documented in README.
