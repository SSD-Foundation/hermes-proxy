# Iteration 01 – Mesh Protocols & Bootstrap

## Objective
Define the NodeMesh contracts and land the initial join/bootstrap path so nodes can authenticate peers, learn the membership snapshot, and register connected apps for later routing.

## Key work
- Draft `nodemesh.proto` with `Join`, `Gossip`, and `RouteChat` envelopes mirroring the MVP spec (membership events, routing frames, and tieline setup/teardown). Regenerate Go stubs and wire module paths.
- Extend config/keystore to supply the node identity (uid/wallet placeholder), public endpoint, TLS materials for node↔node, and a list of bootstrap peers.
- Implement NodeMesh server skeleton:
  - `Join` handler validating peer identity, returning membership snapshot, and persisting peer metadata (endpoint, identity key, last heartbeat).
  - Gossip stream stub that accepts heartbeats/membership events and updates the in-memory membership store.
  - Outbound dialer that attempts bootstrap peers with backoff and replays `Join` after disconnects.
- Track connected apps in the node registry for discovery (app identity → session/node mapping) and expose hooks for mesh routing to consume.
- Add observability for mesh bring-up: metrics for known nodes, join failures, and gossip heartbeats; admin endpoint to dump membership for debugging.
- Tests:
  - Unit tests for membership store merge logic and bootstrap config parsing.
  - Component test standing up two in-process nodes to verify Join succeeds, membership snapshots propagate, and TLS/identity validation gates peers.

## Exit criteria
- `nodemesh.proto` exists with generated stubs and is referenced by the codebase.
- A node can start with a bootstrap peer list, dial at least one peer, authenticate it, and populate membership state; peers accept and record joins.
- Connected apps are registered in a discovery map keyed by app identity for future routing.
- Metrics/logs expose membership counts and join outcomes; component tests cover the bootstrap/join path and membership merge behavior.

## Status update (2025-11-23)
- Added `proto/nodemesh.proto` + generated Go stubs; NodeMesh service validates signed Join requests, merges membership snapshots, syncs app presence, and exposes `/mesh/members` for debugging.
- Membership store tracks node descriptors (endpoint, identity key, wallet placeholder, last heartbeat) and app presence keyed by identity. Bootstrap dialer signs Join payloads with the node keystore identity, retries with backoff, and maintains heartbeat Gossip streams.
- AppRouter now records connected apps in an in-memory discovery map; the dialer and Join handler share that map with peers. Mesh metrics track known nodes, join success/failure, heartbeats, and app sync frames.
- TLS hooks exist for node↔node gRPC (disabled by default in dev); config grew `mesh.*` fields for identity secret, public endpoint, bootstrap peers, and TLS materials. Unit/component tests cover membership merge logic and Join success/failure.
