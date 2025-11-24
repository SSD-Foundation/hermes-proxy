# Phase 2 (Nodes) – Implementation Plan

## Goal
Deliver the Stage 2 MVP outcomes from `docs/hermes-mvp-revised.md` for **nodes only**: a multi-node mesh that discovers peers, maintains membership, and routes chats across nodes via gRPC. Phase 2 upgrades the single-node router to participate in a resilient NodeMesh while keeping blockchain fees, faucet, staking, and NAT helpers out of scope for now.

## Scope (nodes only)
- Define and implement the **NodeMesh** gRPC service (`Join`, `Gossip`, `RouteChat`) with TLS between nodes and identity validation using the existing keystore material.
- Maintain cluster membership (SWIM-like heartbeats, suspicion, and pruning), a routing table for app locations, and bootstrap flows for new nodes.
- Bridge **AppRouter** sessions to the mesh: discover the hosting node for a target app, stand up cross-node tielines, and relay encrypted chat envelopes end-to-end.
- Persist and expose mesh state/telemetry (known nodes, routing entries, join failures) via metrics/logs and admin endpoints; tune backoff/keep-alives for long-lived node↔node streams.
- Expand developer ergonomics: config for bootstrap peers, multi-node Docker Compose harness, CI jobs that cover cross-node routing, and documentation updates that describe mesh behaviors and ops.

## Out of scope for Phase 2
- On-chain integration (fees, faucet, staking, NodeRegistry), relay/NAT helpers, and production HSM backends (left for later phases).
- App UX or wallet flows; only the node side of protocols is in view.
- Advanced ratcheting beyond the current per-chat ephemeral exchange (full PFS improvements land in the next phase).

## Dependencies and assumptions
- Reuse the existing keystore/file backend for node identity keys; add node ID/address metadata in config.
- Keep the AppRouter contract compatible but evolve it where needed to carry target app identity and mesh routing hints.
- All traffic remains gRPC-based; TLS is required for node↔node and prepared for app↔node in a later hardening pass.

## Current status (Phase 2 bootstrap)
- Single node routes chats between two connected apps over `AppRouter.Open`, validates ed25519 signatures, enforces sequence ordering, cleans up idle chats, and persists combined chat secrets to the keystore. Connected apps are registered in an in-memory discovery map keyed by app identity.
- NodeMesh proto and Go stubs exist; `Join` validates signed peer descriptors, merges membership snapshots, syncs app presence, and seeds the membership store. A bootstrap dialer signs Join requests to configured peers with backoff and maintains a heartbeat `Gossip` stream. Admin `/mesh/members` dumps membership/app state; mesh metrics track node counts, join success/failure, and heartbeats.
- Dockerfile + Compose harness exercise the happy-path chat flow with two mock apps; CI runs lint, unit/component tests, and the Compose integration job.
- Observability includes Prometheus metrics and `/healthz`/`/readyz`; AGENT guardrails enforce docs/release-note updates and test coverage expectations.

## Workstreams
- **Protocols & contracts:** Draft `nodemesh.proto`, update `app_router.proto` for target app identity and routing, and generate Go stubs.
- **Membership & discovery:** Track known nodes, SWIM-like health/suspicion, routing table for app→node, and bootstrap/rejoin logic.
- **Routing & state:** Connect AppRouter sessions to mesh routing, manage cross-node tielines, and ensure chat teardown/idle expiry works across nodes.
- **Operations & security:** TLS credentials distribution, metrics/logging for mesh health, rate limits/safeguards for node↔node traffic, and admin inspection endpoints.
- **Quality & delivery:** Unit/component/integration test coverage for mesh behaviors, multi-node Compose harness, CI workflow updates, and documentation/readme/wiki updates.

## Milestones & sequencing
1) **Mesh protocols & bootstrap:** Define NodeMesh proto/contracts, node identity/config, and first-pass membership store + join/gossip skeleton.  
2) **Cross-node routing & discovery:** Implement routing table + RouteChat bridge so chats traverse two nodes; align AppRouter frames with target app identity and persistence hooks.  
3) **Churn handling & ops hardening:** SWIM suspicion timers, reconnection/backoff, failover of chats on node loss, mesh metrics/observability, and multi-node CI/Compose harness.

## Acceptance criteria
- Two nodes can join via bootstrap, maintain membership via gossip/heartbeats, and expose metrics reflecting peer health and routing entries.
- An app connected to NodeA can start a chat with an app on NodeB; nodes coordinate tielines and relay encrypted payloads with the same ordering/ack guarantees as single-node flows.
- Idle/teardown semantics erase chat secrets on both nodes; membership churn removes stale routing entries and notifies affected app sessions.
- Docker Compose harness spins up at least two nodes + mock apps to exercise cross-node chat; CI mirrors the documented workflows; README/wiki/release-notes/AGENT stay current.
