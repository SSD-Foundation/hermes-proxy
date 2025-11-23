# HERMES MVP Specification (Revised)

## 1. Purpose and scope

This document defines the revised MVP for **HERMES**, a secure P2P router network with chat user applications and router nodes.

The MVP must deliver:

- 1:1 end-to-end encrypted chat between Apps.
- Routing via a mesh of Nodes (router nodes).
- Token-based gas fees for chat and contact discovery on an existing blockchain.
- Revenue share and burn mechanics on-chain.
- Sybil- and spam-resistant faucet and network participation.
- Sophisticated NAT handling for Nodes and NAT-friendly connectivity for Apps.
- Production-grade key management design (implemented with local encrypted file storage in the MVP).
- Full Node auto-discovery and churn handling.
- A gRPC-based API for all App↔Node and Node↔Node interactions.
- Per-chat keypairs with perfect forward secrecy.
- Node hosts receiving their share of tokens directly on-chain and being able to withdraw/spend them normally.

Platforms:

- **Apps:** Ubuntu Linux.
- **Nodes:** Ubuntu Linux.

---

## 2. Actors and data models

### 2.1 Node

**Responsibility**

- Publicly accessible endpoint responsible for connecting client Apps and routing encrypted traffic between them.

**Composition**

- `node_uid`: Node wallet address (blockchain address; also the Node’s identity in the network).
- `identity_keypair`: Long-term identity key (Ed25519 or RSA).
- `known_nodes`: List of known Nodes (endpoints + metadata).
- `connected_apps`: Active App sessions (open gRPC streams).
- `tielines`: Per-chat routing state (chat_id → nodeA/nodeB/appA/appB).
- On-chain:
  - `node_wallet`: Wallet for HERMES tokens (same as `node_uid`).
  - `stake_amount`: Tokens locked in Node Registry contract.
  - Node’s on-chain HERMES balance.

### 2.2 App

**Responsibility**

- Provide the user interface and local storage for secure chatting and contacts.

**Composition**

- `app_uid`: App wallet address (blockchain address; also the App’s identity in the network).
- `identity_keypair`: Long-term identity key used to authenticate and sign ephemeral keys.
- `token_balance`: On-chain HERMES token balance (queried via RPC).
- `known_apps`: Contacts (AppUID + last known Node endpoint).
- `known_nodes`: Cached list of Nodes (for failover and re-selection).
- `connected_node`: Currently selected Node (gRPC stream).
- `active_chats`: Chats stored locally on device only.
- `per_chat_keys`: Ephemeral key state for each chat.

---

## 3. Cryptographic design and key management

### 3.1 Key types

Each App and Node maintains three key layers:

1. **Blockchain wallet key**
   - Type: secp256k1 (or chain-appropriate key type).
   - Purpose:
     - Holds HERMES tokens.
     - Signs on-chain transactions (faucet claim, fee payments, node staking).
   - `app_uid` and `node_uid` are this wallet’s address.

2. **Long-term identity key**
   - Type: Ed25519 (preferred) or RSA as required by the original brief.
   - Purpose:
     - Authenticate App↔Node sessions.
     - Authenticate Node↔Node sessions.
     - Sign per-chat ephemeral public keys to prevent man-in-the-middle attacks.

3. **Per-chat keypairs (perfect forward secrecy)**
   - Type: X25519 (ECDH).
   - For each chat `chat_id` and each participant:
     - Generate an ephemeral keypair: `chat_ephemeral_priv`, `chat_ephemeral_pub`.
   - Exchange signed ephemeral public keys via Nodes:
     - Each App signs its ephemeral pubkey with its identity key.
   - Key agreement:
     - `K_chat = ECDH(local_chat_priv, remote_chat_pub)`.
   - Derive session keys with HKDF:
     - E.g. `K_enc_send`, `K_enc_recv`, `K_mac`, `K_ratcheting`.
   - Optional symmetric ratchet:
     - After each message, update `K_enc_* = H(K_enc_*)`.

Messages are encrypted with an AEAD cipher (e.g., AES-GCM or ChaCha20-Poly1305) using these per-chat keys. Nodes never see plaintext.

### 3.2 Key storage and management

**MVP implementation: local encrypted keystore**

- A per-process keystore file on disk containing:
  - Encrypted wallet key.
  - Encrypted identity key.
  - Currently active per-chat ephemeral keys (can be pruned when chats end).
- Encryption:
  - Master key derived from a user/operator passphrase using Argon2id.
  - Keystore format is versioned for future migration.
- On startup:
  - Keystore is decrypted into memory.
  - Private keys remain in memory only for the lifetime of the process.

**Production-ready design hooks**

- Key backend is abstracted via `KeyBackend` interface:
  - MVP: `FileKeyBackend` (encrypted file).
  - Later: `SystemKeyBackend` (OS keyring / HSM).

When a chat is intentionally deleted, the per-chat secrets for that `chat_id` are also wiped from keystore and memory.

---

## 4. Network architecture and NAT traversal

### 4.1 Topology

- Apps connect to exactly one Node at a time.
- Nodes form a mesh and route traffic for apps through tielines:
  - App1 ↔ NodeA ↔ NodeB ↔ App2.

### 4.2 Transport and NAT

All protocol traffic uses **gRPC over TLS**:

- **App ↔ Node**
  - Long-lived bidirectional gRPC stream.
  - NAT-friendly: App initiates outbound connection; keep-alives prevent idle timeout.
  - Automatic reconnect logic with backoff and replay of pending control messages.

- **Node ↔ Node**
  - Nodes must expose a reachable public endpoint (host:port).
  - NAT helper for Nodes:
    - Attempts UPnP / NAT-PMP / PCP to open inbound ports.
    - Uses a STUN-like mechanism to detect public IP/port and NAT behavior.
    - If direct exposure fails, Node can register with one or more relay Nodes that forward gRPC streams for it.
  - Node Mesh connections are persistent bidirectional gRPC streams, with periodic heartbeats.

The goal is that Apps can always reach at least one Node even from behind restrictive NAT, and Nodes remain reachable from the mesh via either public IP or relay.

---

## 5. gRPC APIs

All previous HTTP/JSON endpoints are replaced with gRPC services.

### 5.1 App ↔ Node service (`AppRouter`)

Single bidirectional streaming RPC:

```proto
service AppRouter {
  rpc Open(stream AppFrame) returns (stream NodeFrame);
}
```

- `AppFrame` and `NodeFrame` are envelope messages carrying a `oneof` payload:
  - Connect / authentication frames.
  - Chat control:
    - CreateChat, DeleteChat, NodeChange.
  - Contact operations:
    - AddContact, FindApp.
  - Messaging:
    - SendChatMessage, IncomingChatMessage.
  - Token/faucet operations:
    - FaucetClaim, BalanceUpdate.
  - Errors and notifications.

Core flows:

- `ConnectApp`
  - App sends its `app_uid`, identity public key, and optional metadata.
  - Node authenticates and responds with:
    - Node’s identity public key.
    - Snapshot of node list (for failover).
    - Hint about user’s on-chain token balance (optional).

- `StartChat`
  - App provides:
    - `target_app_uid`.
    - `chat_ephemeral_pub` + signature under identity key.
    - Payment proof for the gas fee (on-chain tx hash or equivalent).
  - Node:
    - Verifies payment on-chain.
    - Runs Node Mesh discovery to find the Node hosting `target_app_uid`.
    - Sets up a tieline via Node Mesh.
    - Relays the key exchange to target App.
    - Returns `chat_id` and remote peer’s ephemeral pubkey.

- `SendChatMessage`
  - App sends ciphertext + metadata (chat_id, message_id, timestamp).
  - Node routes via Node Mesh to the remote Node and then to the remote App.

- `DeleteChat`
  - App requests deletion of chat_id.
  - Node tears down tieline and notifies the remote Node/App.
  - Apps erase local chat history and per-chat secrets.

- `FindApp`
  - App requests to locate a given `app_uid` (paying the same gas fee as chat).
  - Node performs discovery via Node Mesh.
  - Response includes last known Node endpoint for the App.

### 5.2 Node ↔ Node service (`NodeMesh`)

Two main responsibilities: **cluster membership** and **chat routing**.

```proto
service NodeMesh {
  rpc Join(JoinRequest) returns (JoinResponse);
  rpc Gossip(stream GossipMessage) returns (stream GossipMessage);
  rpc RouteChat(stream RouteFrame) returns (stream RouteFrame);
}
```

- `Join`
  - New Node announces itself (uid, endpoint, identity pubkey, stake info).
  - Receives an initial membership snapshot (list of nodes + their health).

- `Gossip`
  - Exchanged between peers to maintain cluster membership:
    - Heartbeats and health.
    - Join/leave/fail events.
    - Node metadata (stake, capabilities).

- `RouteChat`
  - Used to:
    - Set up tielines (`SetupTieline` frames).
    - Relay encrypted chat messages (`RelayMessage` frames).
    - Tear down tielines (`TeardownTieline` frames).

---

## 6. Node auto-discovery and churn handling

### 6.1 Joining the cluster

- Node starts with a list of bootstrap endpoints.
- On startup:
  1. Node dials `Join` on a bootstrap Node.
  2. Receives membership snapshot.
  3. Establishes `Gossip` streams to a subset of peers.

### 6.2 Membership protocol

- Nodes periodically send heartbeats to random peers (SWIM-like protocol).
- Suspect nodes are probed via indirect checks.
- Confirmed failed nodes are broadcast to the cluster via gossip.
- New nodes and leaving nodes are also announced via gossip.

Each Node maintains:

- `known_nodes`: reachable nodes (uid, endpoint, last heartbeat).
- `routing_table`: best-known Node for each AppUID (populated by discovery and chat traffic).

On churn:

- When a Node is marked dead:
  - Routing entries pointing to that Node are invalidated.
  - Active tielines involving that Node are torn down.
  - Apps with active chats through that Node are notified to re-establish or fail gracefully.

---

## 7. Chat security and perfect forward secrecy

### 7.1 Chat creation flow (simplified)

1. App1 user enters the target `app_uid`.
2. App1 requests `StartChat` on its connected Node (NodeA):
   - Includes signed `chat_ephemeral_pub_A`.
   - Includes payment proof for chat gas fee.
3. NodeA:
   - Verifies payment on-chain.
   - Uses Node Mesh to `find` the Node where App2 is connected (NodeB).
   - Establishes a tieline between NodeA and NodeB.
4. NodeB forwards the chat request to App2.
5. App2:
   - Generates `chat_ephemeral_pub_B`.
   - Signs it with its identity key.
   - Returns the signed ephemeral pubkey.
6. Both Apps:
   - Verify the other’s signature using long-term identity key.
   - Compute shared secret and derive per-chat session keys.
   - Store per-chat key state and begin encrypted messaging.

### 7.2 Deletion and key erasure

- If either App intentionally deletes the chat:
  - The App deletes:
    - Local chat history.
    - Associated per-chat key state.
  - The App informs its Node via `DeleteChat`.
  - Nodes tear down the tieline and notify the remote Node/App.
- Once deleted and keys erased, future compromise of identity or wallet keys does not reveal past chat contents (PFS).

---

## 8. Tokenomics and blockchain integration

The original supply and allocation are preserved but implemented on-chain:

- Total supply: `1,111,111,111` HERMES tokens.
- Dev allocation: `111,111,111` to a dev wallet.
- Faucet allocation: `1,000,000,000` to a Faucet contract.

### 8.1 HERMES token contract

- Standard fungible token (e.g. ERC-20-style).
- Deployed once; total supply minted at deployment.
- Dev and Faucet allocations assigned at deployment.

### 8.2 Fee contract

A `HermesFeeContract` enforces the fee split and burn for fee-based operations:

- Methods:
  - `payChatFee(address nodeA, address nodeB)`
  - `payFindFee(address nodeA, address nodeB)`
- Each method:
  - Pulls `FEE_AMOUNT` from the caller via `transferFrom`.
  - Splits fee:
    - 49.25% to NodeA.
    - 49.25% to NodeB.
    - 0.5% burned.
- The contract is the single source of truth for the split/burn; Nodes do not maintain an independent authoritative ledger.

### 8.3 Payment flow

**Simple on-chain per-operation model (MVP):**

1. App requests chat creation via `StartChat`.
2. Node responds with:
   - Fee details (`FEE_AMOUNT`).
   - NodeA and NodeB addresses to be used.
   - Method to call on `HermesFeeContract`.
3. App signs and broadcasts `payChatFee(nodeA, nodeB)`.
4. Once the transaction is mined:
   - App sends the transaction hash to NodeA via gRPC.
   - NodeA validates on-chain:
     - Transaction calls the correct method.
     - `msg.sender` equals `app_uid`.
     - Amount and Node addresses match expectation.
5. NodeA proceeds with chat setup.

Nodes receive their share of the fee directly into their on-chain wallets. Node hosts can withdraw or spend these tokens via standard wallet operations; no extra “withdraw from network” step is required.

---

## 9. Faucet and Sybil resistance

### 9.1 Faucet contract

- Holds the faucet allocation.
- Implements:
  - `claim()` for `msg.sender`.
- Enforces:
  - Per-address daily limit.
  - Global daily emission cap.

### 9.2 Faucet service

An off-chain faucet service sits in front of the faucet contract to add additional Sybil resistance:

- App calls service with:
  - Wallet address.
  - Signed nonce (proves control of the wallet).
  - CAPTCHA token.
  - Optional proof-of-work (e.g., hashcash-style challenge).
- Service enforces:
  - Per-wallet daily limit.
  - Per-IP daily limit.
  - Optional device fingerprint limit.
- If the request passes all checks, service either:
  - Calls `claim()` on the faucet contract on behalf of the user, or
  - Returns a ready-made `claim()` transaction for the user to sign and send.

This combination of on-chain rules and off-chain checks reduces faucet abuse and large-scale Sybil attacks.

---

## 10. Network-level Sybil and spam resistance

1. **Node staking**
   - Node operators must register in a `NodeRegistry` contract:
     - Stake a minimum HERMES amount.
     - Provide endpoint and identity key.
   - Nodes without stake or below minimum stake are not propagated in membership gossip and are not used for routing.
   - Future slashing logic can be added to penalize misbehavior.

2. **Economic cost for spam**
   - Chat and contact discovery require paying a token fee through the fee contract.
   - Large-scale spam becomes economically expensive.

3. **Local rate limiting**
   - Nodes apply local rate limits:
     - Max chats per App per time window.
     - Messages per second per App.
   - Abusive Apps can be temporarily blocked by individual Nodes.

---

## 11. Functional flows (summary)

### 11.1 Chat

1. App1 connects to NodeA via gRPC and authenticates.
2. App1 calls `StartChat` with `target_app_uid`, ephemeral key, and payment proof.
3. NodeA:
   - Verifies payment via the blockchain.
   - Uses Node Mesh to find NodeB hosting App2.
   - Sets up a tieline with NodeB.
4. NodeA and NodeB relay per-chat key exchange between Apps.
5. Apps derive per-chat keys and start exchanging encrypted messages via Nodes.
6. Messages are never stored or decrypted on Nodes; chats are stored only on each App.

### 11.2 Contacts

1. After chat creation:
   - Either App can add the peer to its contacts (free).
   - Contact entry stores `app_uid` and last known Node endpoint.
2. To add a contact without a chat:
   - App requests `FindApp` (same gas fee as chat).
   - Node executes discovery via Node Mesh.
   - Once found, App stores contact.

### 11.3 Chat deletion

1. User deletes the chat on one App.
2. App deletes local history and per-chat keys.
3. App sends `DeleteChat` to its Node.
4. Nodes tear down tieline and notify the remote App.
5. Remote App also deletes chat and per-chat keys.

### 11.4 Node change and failover

1. App detects that current Node is unavailable or chooses to switch.
2. App selects a new Node from its `known_nodes` list and opens a new `AppRouter.Open` stream.
3. App can:
   - Re-create chats with existing contacts (using the same counterpart UIDs).
   - Pay any new required fees if needed.
4. Node Mesh discovery and membership ensure chats can be re-routed via healthy Nodes.

---

## 12. Implementation stages (MVP plan)

1. **Stage 1 – Core gRPC and single-Node chat**
   - Implement AppRouter service.
   - Implement local encrypted keystore.
   - Support 1:1 encrypted chats on a single Node without blockchain integration.

2. **Stage 2 – Node Mesh and discovery**
   - Implement NodeMesh service (Join, Gossip, RouteChat).
   - Add tielines and multi-node routing.
   - Add SWIM-like membership and churn handling.

3. **Stage 3 – Per-chat keys and PFS**
   - Integrate X25519 per-chat keypairs and HKDF.
   - Implement key exchange and ratcheting.
   - Ensure key erasure on chat deletion.

4. **Stage 4 – Blockchain integration**
   - Deploy HERMES token, Fee contract, Faucet contract, Node Registry on a chosen chain.
   - Implement on-chain payment verification, faucet service, and node staking.

5. **Stage 5 – NAT helper and operational hardening**
   - Implement NAT helpers for Nodes (UPnP/NAT-PMP, STUN-like checks, relay support).
   - Add monitoring, logging, and tooling for node operators.
   - Tune rate limits and spam/Sybil defenses.

This specification is the final revised MVP definition for HERMES: a secure, token-incentivized P2P router network with end-to-end encrypted chat, gRPC APIs, per-chat PFS, blockchain-based tokenomics, and robust discovery and NAT handling.
