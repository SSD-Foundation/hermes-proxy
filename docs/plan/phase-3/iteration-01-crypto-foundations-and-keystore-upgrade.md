# Iteration 01 – Crypto Foundations & Keystore Upgrade

## Objective
Lock in the cryptographic primitives and storage model for per-chat secrets: standardize X25519 key handling, HKDF-based derivation inputs/outputs, and a sealed, zeroizing keystore record format that can survive restarts without weakening PFS guarantees.

## Key work
- Define the per-chat secret record schema (chat_id, key_version, local/remote ephemeral pubkeys, optional local priv, HKDF salt/info, send/recv/ratchet seeds, created/rotated timestamps) with backward-compatible serialization and versioning.
- Add X25519/HKDF helpers and deterministic key identifiers; enforce Argon2id-derived master key reuse with stronger zeroization and tamper detection for chat records.
- Extend the keystore interface to support namespaced chat secrets (read/write/delete/list) and migrations from the existing `chatID -> combined keys` blob; add integrity checks and size limits.
- Introduce configuration toggles for crypto parameters (HKDF hash, info labels, max key lifetime) and validation of acceptable ranges.
- Unit-test coverage: keystore migrations, zeroization on overwrite/delete, corrupted file handling, deterministic HKDF outputs, and X25519 key generation/validation edge cases.

## Exit criteria
- Versioned chat-secret records can be written/read/removed via the keystore with sealed storage and zeroization on overwrite/delete; migration from the legacy format is covered.
- X25519/HKDF helpers exist with deterministic test vectors and validation for malformed inputs.
- Config accepts vetted crypto parameters; invalid values are rejected early with clear errors.

## Status update (2025-11-25)
- Implemented versioned chat-secret records with HKDF metadata, send/recv/mac/ratchet seeds, zeroization, and sealed storage; legacy combined blobs migrate automatically.
- Added X25519/HKDF helpers (deterministic key IDs, shared-secret + HKDF derivation with vectors) and crypto config validation (hash/info label/max key lifetime).
- Ready for protocol wiring and rekey flows in Iteration 02.
