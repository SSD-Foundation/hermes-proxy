# Phase 1 (Nodes) – Implementation Plan

## Goal
Deliver a single-node HERMES router that supports gRPC-based App connectivity and encrypted 1:1 chat routing without blockchain or multi-node mesh dependencies. This phase proves core node behavior, key handling, and developer ergonomics to enable later expansion to the mesh, payments, and NAT helpers.

## Scope (nodes only)
- gRPC `AppRouter` service: bidirectional stream for connect, chat control, and message relay.
- Local encrypted keystore for node identity + per-chat ephemeral keys (file-based, Argon2id-derived master key).
- In-memory chat/tieline state for a single node hosting both peers; no NodeMesh, staking, faucet, or fee validation.
- Basic node health/metrics endpoints (local-only) to aid testing.
- Developer tooling: build, lint, test harnesses, Dockerized local runs, CI workflows.
- Documentation and release process artifacts.

## Out of scope for Phase 1
- NodeMesh (Join/Gossip/RouteChat), SWIM membership, and multi-node routing.
- Blockchain integration (token, fee contract, faucet, staking).
- NAT traversal helpers and relays.
- Production-grade HSM/OS keyring backends (file backend only).

## Deliverables
- Running node binary/container exposing `AppRouter` and minimal health probe.
- Protobuf definitions and generated stubs for node-facing services.
- Keystore module with tests; command-line tooling to initialize keystore and start node with passphrase injection.
- In-memory chat router capable of StartChat, SendChatMessage, DeleteChat flows across two Apps connected to the same node.
- Test suite covering unit, component (gRPC service + in-memory state), and integration (happy path chat across two mock apps).
- Docker Compose for local testing (unit/component/integration) and GitHub Actions workflows for CI (lint+test+container build).
- Docs: README, release-notes entry, AGENT guardrails, wiki page for core node functionality, and iteration prompts.

## Current status
- AppRouter.Open implements connect/start chat/send/delete on a single node with sealed keystore storage, per-chat secret zeroization, housekeeping for idle chats, and admin health/metrics endpoints.
- Tests cover keystore sealing/tamper detection, chat routing (happy path + signature failure + idle expiry), and Dockerized integration (Compose harness with two mock apps). `make integration` exercises the container build + chat flow, and CI runs lint, tests, and the Compose integration job.

## Workstreams
- **Protocols & contracts**: define `app_router.proto`; draft message envelopes for connect, chat setup, messaging, deletion, errors.
- **State & storage**: keystore interface + file implementation; chat/tieline registry with lifecycle hooks and cleanup.
- **Service layer**: gRPC server setup, authentication using identity keys, per-chat key exchange verification (sign/verify of ephemeral keys).
- **Observability**: structured logging, request IDs, minimal metrics (connections, active chats, errors) exposed over a local endpoint or stdout.
- **Operations**: Dockerfile (dev + runtime), Compose for local multi-app harness, GitHub Actions workflows, production image guidance.
- **Quality**: testing strategy execution; static checks; schemas/contracts versioning; documentation updates.

## Milestones & sequencing
1) **Foundations**: repo structure, proto drafts, config + logging, keystore skeleton, CI lint/test scaffolding.  
2) **Chat plumbing**: implement AppRouter.Open stream handlers, connect/auth handshake, StartChat + SendChat + DeleteChat over single node, tie-in with keystore for key validation.  
3) **Hardening & delivery**: PFS key handling, cleanup/erasure on deletion, metrics, Docker/Compose flows, CI workflows, documentation + release-notes refresh.

## Acceptance criteria
- Apps can connect to a running node, perform StartChat with signed ephemeral keys, exchange encrypted payloads, and delete chats; all traffic stays within one node.
- Node rejects invalid signatures and malformed frames; chat teardown removes state and keys from memory and keystore.
- `docker compose up` runs node + two mock app containers executing integration chat test.
- `make test` (or equivalent) runs unit+component suites; CI workflow mirrors locally documented commands.
- Docs (README, release-notes, wiki) reflect the current Phase 1 state and instructions; AGENT.md enforces maintenance of tests, deployment schemes, and docs.
