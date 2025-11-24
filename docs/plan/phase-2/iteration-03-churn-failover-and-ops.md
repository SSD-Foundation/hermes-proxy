# Iteration 03 – Churn, Failover, and Ops Hardening

## Objective
Make the mesh resilient to peer loss and operationally ready: detect churn quickly, recover or tear down affected chats cleanly, and ship the multi-node test/deploy tooling and documentation.

## Key work
- Finalize SWIM behaviors: indirect pings/probes, suspicion backoff, and pruning timers; emit membership/broadcast events that AppRouter can use to notify apps of peer loss.
- Add failover handling for chats:
  - When a hosting node disappears, invalidate routing entries, tear down impacted tielines, and inform local apps so they can reconnect or retry.
  - Ensure chat expiry/cleanup runs across nodes and keeps keystore/reg entries in sync.
- Operational hardening:
  - Mesh metrics (heartbeat RTTs, suspicion counts, routing table size, RouteChat failures) and structured logs for membership changes.
  - Rate limits/backpressure for node↔node streams and defensive defaults for keep-alives/reconnect backoff.
  - TLS lifecycle (cert reload or rotation hooks) and configuration docs for local vs. CI vs. production trust models.
- Tooling & delivery:
  - Expand Docker Compose harness to run at least two nodes + two mock apps exercising cross-node chat and a churn scenario (bounce one node).
  - Update GitHub Actions workflows to run the multi-node integration job after lint/unit/component stages.
  - Refresh README, release-notes, AGENT, and wiki with mesh operations, config knobs, and test/deploy instructions.

## Exit criteria
- Nodes detect dead peers, evict them from membership/routing tables, and surface clear errors/notifications to apps; chats clean up secrets/state on churn.
- Mesh metrics/logs provide visibility into membership health and routing behavior; TLS is enforced for node↔node traffic with documented trust setup.
- Multi-node Compose integration succeeds (including churn case), and CI runs the same harness; docs and guardrails describe the updated workflows and expectations.
