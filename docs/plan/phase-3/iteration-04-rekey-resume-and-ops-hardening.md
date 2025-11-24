# Iteration 04 – Rekey/Resume and Ops Hardening

## Objective
Close the remaining Phase 3 gaps by hardening rekey/resume flows, ratchet backpressure/rate limits, and CI/Compose coverage so nodes can recover cleanly after churn/restarts without weakening PFS guarantees.

## Key work
- Rekey/resume state machine: define how apps request rekey, validate rekey attempts (version bumps, signed X25519 keys), and refuse duplicates; ensure resumed chats load persisted ratchet counters and fail fast on mismatches.
- Backpressure and rate limits: bound rekey attempts per chat/app, throttle ratchet divergence retries, and expose config knobs/metrics for rejects/backoffs.
- Delivery and teardown: ensure rekey-required paths propagate deterministic errors/codes to apps and remote peers; wipe legacy key material on successful rekey or failure.
- Observability: add Prometheus metrics/logs for rekey attempts/success/failure, divergence recoveries, and rate-limit drops; extend `/crypto/ratchets` or a sibling endpoint to surface current key versions and rekey health (non-secret).
- Integration coverage: extend Compose/CI scenario to run handshake → messaging with ratchets → forced rekey → resume/teardown, including node restart/churn; update mockapp flags to drive rekey/resume flows.
- Docs/guardrails: refresh README/wiki/AGENT/release-notes/plan to describe rekey/resume commands, statuses, metrics, and operational knobs.

## Exit criteria
- Rekey/resume succeeds with signed X25519 material and versioned state persisted; stale/replayed/mismatched rekeys are rejected with deterministic errors.
- Ratchet counters reload correctly after restart; divergence/rekey-required paths tear down and erase secrets consistently across nodes/apps.
- Rate limits/backpressure for rekey/divergence are configurable and observable via metrics/logs.
- Integration (Compose + CI) exercises the rekey/resume path (including restart/churn) and passes; documentation and guardrails reflect the new workflows and knobs.

## Status update (2025-11-29)
- Restart/resume harness landed: `docker-compose.rekey-resume.yaml` plus `scripts/run-restart-resume.sh` force rekey → SIGKILL restart → sealed keystore resume and now gate `make integration` and CI.
- Cross-node RouteChat tests cover rekey/resume (remote setup, persisted counters, `REKEY_THROTTLED`/`REPLAYED_KEY` rejection) to prevent stale or repeated material after restarts.
- README/wiki/AGENT/overview/release notes refreshed with restart/resume expectations, rekey error handling, and operator signals (`hermes_rekeys_total`, `/crypto/ratchets` `resumed`/`expired`).
