# Iteration 03 – Ratcheting, Erasure, and Delivery

## Objective
Complete the PFS lifecycle with symmetric ratchets, deterministic erasure, and operational coverage so nodes survive churn/restarts without weakening secrecy and CI/Compose exercise the full flow.

## Key work
- Implement per-message symmetric ratcheting (send/recv) with counters/versioning; detect divergence and trigger rekey/teardown with clear errors delivered to apps.
- Enforce key erasure on DeleteChat, idle expiry, churn (lost RouteChat), and process shutdown; ensure keystore and in-memory material are zeroed and remote peers receive teardown notices.
- Add observability: metrics for key versions, ratchet advances, rekey attempts/failures, erasure counts, and recovery paths; structured logs for auditability without leaking key bytes.
- Harden operations: rate limits/backpressure for rekey attempts, bounded key lifetimes, and config for ratchet intervals; admin/debug endpoints for current key versions (non-secret) and ratchet health.
- Integration coverage: update Docker Compose harness and CI job to run a multi-node scenario that performs handshake → messaging with ratchets → rekey → teardown/expiry and verifies secrets are wiped; refresh README/wiki/AGENT/release-notes accordingly.

## Exit criteria
- Send/receive ratchets advance on each message with version tracking; divergence triggers deterministic rekey/teardown paths.
- Secrets are erased on all teardown paths (explicit delete, expiry, churn, shutdown) with metrics/logs confirming wipes; no plaintext or key material is logged.
- Integration (Compose + CI) runs the PFS + ratchet flow across two nodes and mock apps, including rekey and teardown; documentation and guardrails describe the new workflows and operational knobs.

## Status update (2025-11-27)
- Ratchet state now persists and advances per message with teardown on divergence/expired lifetimes, Prometheus/HTTP visibility shipped, and mockapp/component coverage exercises multi-message flows; continue hardening rekey/backpressure where needed.
