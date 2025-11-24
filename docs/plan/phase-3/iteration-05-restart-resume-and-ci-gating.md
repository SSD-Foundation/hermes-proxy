# Iteration 05 – Restart/Resume, Cross-Node Rekey, and CI Gating

## Objective
Prove rekey/resume correctness under real restart/churn and make it a CI gate: multi-node Compose runs must pass handshake → messaging → forced rekey → restart/resume → teardown, with deterministic errors, metrics, and operator guidance.

## Key work
- Integration path: extend the Compose harness to drive rekey/resume with mockapp flags (`--rekey/--key-version`), force a node restart/churn, and verify sequence enforcement plus erasure on teardown.
- Cross-node validation: add component/integration tests for RouteChat rekey/resume (remote setup, replay/mismatch errors, per-chat/app throttling) and ensure persisted counters are honored after restart.
- Observability & runbook: document restart/resume expectations, `REKEY_THROTTLED`/`REPLAYED_KEY` handling, and how to watch `hermes_rekeys_total` + `/crypto/ratchets` (`resumed`/`expired`) with example alerts/dashboards.
- CI enforcement: wire the new Compose scenario into CI so Phase 3 merges require the restart/resume flow to pass; ensure Docker image + mockapp usage are pinned and cached.
- Docs/guardrails: update README/wiki/AGENT/release-notes/overview to reflect the restart/rekey workflow, new tests, and operational knobs.

## Exit criteria
- Multi-node Compose/CI scenario covers handshake → messaging → forced rekey → node restart → resume → teardown/churn and passes reliably (with backpressure/acks preserved).
- RouteChat rekey/resume tests (local + remote) verify version bumps, throttling (`REKEY_THROTTLED`), replay protection (`REPLAYED_KEY`), and persisted ratchet counters post-restart.
- Operators have clear instructions and signals (metrics/logs/endpoints) for rekey/resume health and alerting; documentation and guardrails are updated accordingly.
- CI gates on the new scenario; Docker build/test stages remain green with the added coverage.

## Status update (2025-11-29)
- Restart/resume harness shipped: `docker-compose.rekey-resume.yaml` plus `scripts/run-restart-resume.sh` drive handshake → message → forced rekey(version 2) → SIGKILL restart/resume → post-restart message, and `make integration`/CI now run this flow by default.
- Mockapp now supports restart-aware runs (`--expect-restart`, `--post-restart-messages`, `--start-delay`, `--target-node`, `--max-restarts`/`--rekey-version`) and exposes restart-ready markers for the harness to coordinate kills.
- AppRouter cross-node component tests seed resume state and cover rekey throttling/replay protection, ignoring stale resume records on version bumps and rejecting no-op rekeys that match the current derived version.
- README/wiki/AGENT/overview/release notes refreshed with restart/resume expectations, operator signals (`hermes_rekeys_total`, `/crypto/ratchets` resumed/expired), and CI workflow/Makefile updates pointing to the new harness.
