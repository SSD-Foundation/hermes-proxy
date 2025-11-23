# Iteration 02 – Cross-Node Routing & Discovery

## Objective
Enable chats to traverse multiple nodes by discovering the hosting node for a target app, establishing cross-node tielines, and relaying encrypted envelopes with the same ordering and teardown semantics as single-node flows.

## Key work
- Implement SWIM-like gossip: periodic heartbeats, suspicion timers, and eviction of unhealthy peers; propagate membership deltas over the Gossip stream.
- Maintain a routing table (app identity → node) fed by AppRouter session events and membership gossip; invalidate entries on peer loss.
- Extend `app_router.proto` to carry the target app identity (and optional routing hints) in `StartChat`/`FindApp` style frames; update server, mock app, and tests accordingly.
- Implement the `RouteChat` stream:
  - Setup/teardown frames to coordinate tieline creation between NodeA and NodeB for a given chat/app pair.
  - Forward `ChatMessage` envelopes and ACKs across nodes, preserving ordering and backpressure handling; propagate DeleteChat and idle expiry to both sides.
  - Persist chat secrets on both nodes and wipe them on teardown/expiry just like single-node flows.
- Add outbound mesh connection management (pool keyed by node ID/endpoint) with reconnect/backoff and TLS enforcement.
- Tests:
  - Component tests with two in-process nodes: StartChat from AppA@NodeA to AppB@NodeB succeeds, messages relay with correct sequencing, and DeleteChat/expiry tears down both ends.
  - Negative coverage: unknown target app → clear error; lost mesh link causes teardown or retryable error surfaced to the initiating app.

## Exit criteria
- Node-to-node RouteChat stream relays StartChat/ChatMessage/DeleteChat across nodes with proper ACKs and secret erasure.
- Routing table correctly resolves target apps and drops stale entries when peers disappear.
- AppRouter clients include the target app identity and receive deterministic errors if discovery fails.
- Tests cover happy-path cross-node chat plus error cases; mockapp and docs reflect the updated frames.
