# Iteration 02 – Handshake & Derivation Bridge

## Objective
Wire the upgraded protocols through AppRouter and NodeMesh so StartChat/rekey exchanges deliver signed X25519 material, derive HKDF session keys with versioning, and keep chat state consistent across local and cross-node routes without exposing plaintext to the nodes.

## Key work
- Update `app_router.proto`/`nodemesh.proto` to carry key version, HKDF salt/info labels, and rekey/ratchet signals; ensure errors surface deterministic codes for replay/mismatch/expiry.
- Validate identity-signed ephemeral public keys on StartChat and any rekey attempts; reject stale or replayed key material and throttle retries.
- Derive session keys (send/recv/mac/ratchet seeds) using the helpers from Iteration 01; persist the resulting chat-secret records in the keystore with version bumps and timestamps.
- Align chat lifecycle: pending → ready when both keys present; handle local vs. remote routing uniformly; propagate teardown on failed derivation or signature errors.
- Update mockapp and component tests to perform the new handshake, exercise invalid signatures, missing fields, replayed key versions, and remote node routing with PFS metadata attached.

## Exit criteria
- StartChat and remote SetupTieline exchanges include key versioning and signed X25519 metadata; invalid signatures or replays are rejected with deterministic errors.
- Derived session material is sealed in the keystore per chat with version tracking; chat state transitions account for local and cross-node flows.
- Component tests (single-node and two-node) cover happy-path handshake, invalid signature, replay/mismatch, and teardown on derivation failure.

## Status update (2025-11-25)
- Planned; awaiting keystore/crypto helpers from Iteration 01 before wiring protocols and handlers.
