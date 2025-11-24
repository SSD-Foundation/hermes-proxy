# Phase 3 (Nodes) – Per-Chat PFS Implementation Plan

## Goal
Deliver Stage 3 from `docs/hermes-mvp-revised.md` for **nodes only**: enforce per-chat perfect forward secrecy by standardizing X25519 key exchange, HKDF-derived session keys, symmetric ratcheting, and reliable key erasure on teardown/expiry across single-node and mesh-chat flows.

## Scope (nodes only)
- Upgrade `AppRouter` and `NodeMesh` flows so chats exchange signed X25519 ephemeral keys, derive session material deterministically, and rotate keys during message streams without leaking plaintext to nodes.
- Extend the keystore interface to persist per-chat secrets safely (versioned records, zeroization, tamper detection) and wipe them on teardown, expiry, churn, or process shutdown.
- Add deterministic rekey/resume handling: protect against replay/duplication, detect mismatched key versions, and recover cleanly after node restarts while preserving PFS guarantees.
- Expand observability, rate limits, and documentation to reflect the new crypto lifecycle, with developer tooling (mockapp, integration harness, CI) exercising PFS paths.

## Out of scope for Phase 3
- Blockchain integration (fees, faucet, staking) and NAT helpers (relays/UPnP/STUN) remain future phases.
- App UX and wallet flows beyond what mock clients need to exercise node-side contracts.
- Production HSM/backends beyond the existing file keystore abstraction (only hooks/refactors land here).

## Dependencies and assumptions
- Keep gRPC as the transport; TLS remains required for node↔node and ready for app↔node hardening.
- Reuse the Argon2id + XChaCha20-Poly1305 file keystore, expanding it for chat-secret records and zeroization guarantees.
- App identity remains Ed25519; per-chat ephemeral keys use X25519; HKDF derives send/recv/mac/ratchet keys with versioning baked into metadata.
- Mock app/client code must evolve with the handshake so component/integration tests can validate PFS behavior.

## Current status (Phase 3 restart/resume gated)
- Multi-node mesh, target-aware `StartChat`/`RouteChat`, SWIM-style gossip/churn handling, and sealed keystore storage for chat secrets are in place.
- Crypto foundations landed: versioned chat-secret records with HKDF metadata/migration, X25519/HKDF helper library, and validated crypto knobs. Protocol wiring + HKDF derivation and symmetric ratcheting/erasure/metrics are implemented. Rekey/resume loads sealed ratchet state, enforces version bumps + per-chat/app throttles, emits rekey metrics, and cross-node component tests cover replay/throttle/resume after restart.
- Integration/CI now gate on a restart/resume Compose scenario (handshake → messaging → forced rekey → SIGKILL restart/resume → teardown) via `docker-compose.rekey-resume.yaml` and `scripts/run-restart-resume.sh` (`make integration`). Remaining work is operational polish (alerting/dashboard examples, optional mTLS for app↔node) and backlog hardening captured in iteration notes.

## Workstreams
- **Protocols & envelopes:** Update `app_router.proto`/`nodemesh.proto` for X25519 key metadata, key versions, rekey/ratchet signals, and deterministic error codes.
- **Crypto & keystore:** Add X25519/HKDF helpers, chat-secret record formats, sealing/zeroization, and migration/backfill hooks in the keystore.
- **AppRouter & mesh integration:** Validate signed ephemeral keys, derive/rotate session material, propagate rekey/teardown across nodes, and ensure secrets wipe on expiry/churn.
- **Observability & safety:** Metrics/logs for key lifecycle, ratchet counters, and failure modes; rate limits/backpressure for handshake retries; admin/debug endpoints where needed.
- **Quality & delivery:** Unit/component/integration coverage for handshake, ratchet, replay/mismatch handling; Docker/CI harness updates; docs/readme/wiki/release-notes/AGENT kept current.

## Milestones & sequencing
1) **Crypto foundations & keystore upgrade:** Lock in primitives, record formats, and keystore behaviors for per-chat secrets with tests and zeroization.  
2) **Handshake + derivation bridge:** Wire updated protos, validate signatures, derive session material, and plumb PFS state through AppRouter/NodeMesh with mockapp/test updates.  
3) **Ratcheting, erasure, and delivery:** Implement symmetric ratchets/rekey, churn/expiry wiping, observability, Docker/CI harness coverage, and documentation/guardrail refresh.

## Acceptance criteria
- StartChat/rekey flows exchange signed X25519 keys, derive HKDF-based send/recv keys with versioning, and reject mismatched/replayed material with clear errors.
- Secrets are stored only in sealed, versioned keystore records while chats are active and are wiped on DeleteChat, expiry, churn, and shutdown; remote peers receive deterministic teardown notifications.
- Symmetric ratcheting advances on message send/recv; nodes/clients detect divergence and recover or fail closed.
- Component and multi-node integration tests cover happy path + replay/teardown/churn cases for the PFS lifecycle; Docker/CI harnesses run the same steps; README/wiki/release-notes/AGENT reflect Phase 3 expectations.
