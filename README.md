# HERMES Nodes (Phase 1)

This repository tracks the Phase 1 implementation of HERMES router nodes: a gRPC-based service that connects Apps, manages encrypted 1:1 chats on a single node, and prepares the groundwork for later mesh, payments, and NAT features. Platform target is Ubuntu Linux.

## Getting started
- Read the MVP scope in `docs/hermes-mvp-revised.md`.
- Review the Phase 1 plan and iteration prompts in `docs/plan/phase-1/`.
- Development workflow (in progress):
  - Build/lint/test commands will live in a `Makefile`.
  - Docker and Compose files will support local integration tests with mock apps.

## Project structure
- `docs/hermes-mvp-revised.md`: Revised MVP specification.
- `docs/plan/phase-1/`: Implementation plan and iteration prompts for nodes.
- `docs/wiki/core-node-functionality.md`: Core behavior and operational notes (kept current as features land).
- `AGENT.md`: Mandatory guardrails for testing, deployment, and docs maintenance.
- `release-notes.md`: Latest user-visible changes.

## Contributing
- Follow the iteration prompts; do not skip milestones.
- Keep tests, Docker workflows, and documentation in sync with code changes as enforced by `AGENT.md`.
