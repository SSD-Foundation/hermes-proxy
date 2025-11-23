# Iteration 02 – Chat Plumbing (Single Node)

## Objective
Implement the end-to-end chat flow over a single node: connect, authenticate, start chat, send messages, and delete chat with per-chat key validation.

## Key work
- Implement Connect handshake in `AppRouter.Open`:
  - Verify identity public keys + signatures.
  - Register connected apps with session metadata and backpressure/heartbeat handling.
- Implement StartChat:
  - Validate signed ephemeral pubkey against the app identity key.
  - Create `chat_id`, allocate tieline state, and return remote ephemeral key once available.
- Implement SendChatMessage and relay to the paired app via in-memory tieline; enforce AEAD ciphertext envelope schema and message ordering.
- Implement DeleteChat:
  - Tear down tieline, remove chat state, and trigger key erasure hooks in keystore.
- Add component tests using in-process gRPC server and two mock app clients covering happy path, signature failure, and teardown.
- Extend CI to run component tests; document developer workflows.

## Exit criteria
- Two mock apps can connect to one node, start a chat with signed ephemeral keys, exchange encrypted payload bytes, and delete chat cleanly.
- Invalid signatures or malformed frames are rejected with clear error frames and no lingering state.
- Component test suite runs locally and in CI.
