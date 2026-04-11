# ShieldNode — Implementation Plan: Review Remediation

## Context

The April 9, 2026 project review (`docs/PROJECT-REVIEW-2026-04-09.md`) identified issues across all layers. This plan organizes them into 8 work sections, ordered by dependency. Some review findings were inaccurate — receipt signing and control message parsing ARE implemented (verified in code). The real gaps are more specific.

**Goal:** Get ShieldNode to a state where real traffic flows end-to-end, contracts are hardened, and the project is ready for extended testnet operation and external re-audit.

**User decisions:**
- Private key security: **WalletConnect integration** (remove local key storage)
- NAT traversal: **Implement UPnP now** (via `igd` crate)
- Shared crate: **Extract first** before tunnel work

---

## Section 1: Smart Contract Fixes

**Why first:** Contract bugs are independent of everything else and several are critical. Fix them, test them, redeploy to Sepolia. Start in parallel with Section 2.

### 1A. SessionSettlement — Division-by-zero fix
- **File:** `contracts/src/SessionSettlement.sol` (~lines 338-340)
- **Change:** Guard against `cumulativeBytes == 0` in `_settle()`. Either `require(totalPaid > 0, ...)` or short-circuit: if all prices compute to 0, skip the proportional scaling branch and refund the full deposit
- **Test:** Add test in `contracts/test/SessionSettlement.t.sol` — settle with `cumulativeBytes = 0`, expect full refund with no revert

### 1B. SessionSettlement — Idle session cleanup
- **File:** `contracts/src/SessionSettlement.sol`
- **Change:** Add `cleanupSession(uint256 sessionId)` — callable by anyone after a timeout (e.g., 30 days). Marks session settled, decrements `openSessionCount` for all 3 nodes, refunds deposit to client via `pendingWithdrawals`
- **Test:** Open session, warp 30 days, call cleanup, verify node can unstake

### 1C. NodeRegistry — getActiveNodes optimization
- **File:** `contracts/src/NodeRegistry.sol` (~lines 249-282)
- **Change:** Maintain a separate `bytes32[] private _activeNodeIds` array. Update on register/deregister/heartbeat-miss/slash. `getActiveNodes()` paginates this array directly instead of scanning `_allNodeIds` twice
- **Test:** Register 100 nodes, deregister 50, verify correct results. Measure gas

### 1D. NodeRegistry — Reentrancy guard on slash()
- **File:** `contracts/src/NodeRegistry.sol` (~lines 298-318)
- **Change:** Add `ReentrancyGuard` (OpenZeppelin) or a simple lock on `slash()` which does an external ETH transfer
- **Test:** Existing slash tests pass. Add test confirming reentrant call reverts

### 1E. NodeRegistry — Commitment field setter
- **File:** `contracts/src/NodeRegistry.sol`
- **Change:** Add `setCommitment(bytes32 nodeId, bytes32 commitment) external onlyNodeOwner(nodeId)` for Phase 6 ZK eligibility
- **Test:** Register node, set commitment, verify stored, verify only owner can call

### 1F. ZKSettlement — Exit share verification
- **File:** `contracts/src/ZKSettlement.sol` (~lines 355-361)
- **Change:** Add: `require(amounts[2] == totalPayment - amounts[0] - amounts[1], "ZKSettlement: exit share mismatch")`
- **Test:** Manipulated exit share that sums correctly but doesn't match remainder formula

### 1G. Missing events
- **Files:** `contracts/src/SlashingOracle.sol`, `contracts/src/ChallengeManager.sol`
- **Changes:**
  - SlashingOracle: `event PermanentBan(bytes32 indexed nodeId)` — emit in `executeSlash()` when `fraudSlashCount >= 3`
  - ChallengeManager: `event ChallengeRetrySucceeded(uint256 indexed challengeId, bytes32 indexed nodeId)` — emit in `retrySlash()` success path
- **Test:** Verify events in existing slash/challenge flows

### 1H. Consistent error style
- **Files:** All contracts
- **Change:** Replace remaining `require(cond, "string")` with custom errors. Single pass after other fixes

### Verification
```bash
cd contracts && forge test -vv
```

---

## Section 2: Shared Types Crate Extraction

**Why second:** Before touching tunnel/crypto code on both sides, unify the duplicated logic into one place. Every subsequent section benefits from single-source-of-truth changes.

### 2A. Cargo workspace setup
- **Change:** Create a root `Cargo.toml` workspace with members: `node`, `client/src-tauri`, `packages/shieldnode-types`
- **New crate:** `packages/shieldnode-types/Cargo.toml` with dependencies shared by both (x25519-dalek, chacha20poly1305, hmac, sha2, hkdf, hex, k256, alloy-primitives)

### 2B. Extract EIP-712 receipt logic
- **From:** `node/src/network/receipts.rs` and `client/src-tauri/src/receipts.rs`
- **To:** `packages/shieldnode-types/src/receipts.rs`
- **Shared:** `compute_domain_separator()`, `compute_receipt_digest()`, `encode_settlement_receipt()`, EIP-712 constants
- **Keep in node:** `sign_receipt_digest()` (uses node's key)
- **Keep in client:** `sign_receipt()` (uses client's wallet key)

### 2C. Extract Sphinx MAC and packet types
- **From:** `node/src/crypto/sphinx.rs` and `client/src-tauri/src/sphinx.rs`
- **To:** `packages/shieldnode-types/src/sphinx.rs`
- **Shared:** `compute_mac()`, `SphinxPacket` struct, `to_bytes()`/`from_bytes()`, PQ types (`PqSphinxPacket`, `PqSessionKeys`, `PqHopKeys`, `pq_derive_layer_key()`, `pq_compute_mac()`, `pq_serialize()`)
- **Keep in node:** `peel_layer()` (node-only decrypt)
- **Keep in client:** `create_packet()` (client-only encrypt)

### 2D. Extract crypto utilities
- **From:** `node/src/crypto/kdf.rs` and `client/src-tauri/src/circuit.rs`
- **To:** `packages/shieldnode-types/src/crypto.rs`
- **Shared:** `hkdf_sha256()`, AEAD wrapper, `KeyExchange` and `Signer` traits, `X25519Kem`, `MlKem768Kem`, `HybridKem`

### 2E. Extract hop codec
- **From:** `node/src/network/hop_codec.rs` and `client/src-tauri/src/hop_codec.rs`
- **To:** `packages/shieldnode-types/src/hop_codec.rs`
- **Shared:** `encode_next_hop()`, `decode_next_hop()`, `endpoint_to_next_hop()`

### 2F. Extract scoring constants
- **To:** `packages/shieldnode-types/src/scoring.rs`
- **Shared:** Score weights, TEE bonus constant, formula parameters
- **Note:** TypeScript `scoring.ts` can't consume Rust, but document the canonical values in one place

### 2G. Update imports in node and client
- **Change:** Replace duplicated `mod` declarations with `use shieldnode_types::*` imports
- **Verify:** Both `cargo build` successfully, all existing tests pass

### Verification
```bash
cargo test --workspace
cd node && cargo test
cd client/src-tauri && cargo build
```

---

## Section 3: Relay Node Data Plane Completion

**Why third:** The relay node needs to handle real bidirectional traffic before the client tunnel can work.

### 3A. TUN return path (exit mode)
- **File:** `node/src/tunnel/listener.rs` (~line 280, currently stubbed)
- **Change:** Spawn a task that reads packets from TUN (`tun.read_packet().await`), WireGuard-encapsulates them via `wireguard.rs::handle_outgoing()`, wraps in Sphinx for the return path, sends back through the relay chain
- **Requires:** Extend `SessionState` in `node/src/network/relay.rs` with `return_addr: SocketAddr` so the exit node knows where to send return traffic
- **Reference:** `node/src/tunnel/tun_device.rs` — `AsyncTunDevice` already has read capability

### 3B. Wire batch reorder into relay loop
- **File:** `node/src/main.rs`
- **Change:** When `config.batch_reorder_enabled`, spawn `batch_flush_loop()` from `node/src/network/batch_reorder.rs`. Feed packets from relay_listener into the batch buffer instead of directly forwarding
- **Module:** `batch_reorder.rs` is complete — `BatchBuffer`, `enqueue()`, `flush()`, `batch_flush_loop()` all exist
- **Config:** `config.rs` already has `batch_reorder_enabled` and `batch_window_ms`

### 3C. Wire packet normalization into forward path
- **File:** `node/src/network/relay_listener.rs`
- **Change:** Before sending to next hop, pass through `packet_norm::normalize()`. On receive, `packet_norm::denormalize()` before Sphinx peel
- **Module:** `node/src/tunnel/packet_norm.rs` is fully implemented with fragmentation/reassembly and `MAX_PENDING_SEQUENCES = 256` eviction

### 3D. NAT traversal via UPnP
- **New file:** `node/src/network/nat.rs`
- **Change:** On startup, attempt UPnP port mapping for relay port (51821/UDP), WireGuard port (51820/UDP), and libp2p port (4001/TCP) using the `igd` crate. Log success/failure. Fall back gracefully if UPnP unavailable (log warning with manual port-forwarding instructions)
- **Config:** Add `upnp_enabled: bool` to `config.rs` (default: true)
- **Integration:** Call from `main.rs` during startup, before binding sockets

### 3E. NodeKeyPair zeroization
- **File:** `node/src/crypto/keys.rs` (~lines 26-27)
- **Change:** `impl Drop for NodeKeyPair` that calls `zeroize()` on secret key bytes. Use `zeroize` crate (already transitive dependency)

### 3F. Nonce overflow protection
- **File:** `node/src/crypto/ratchet.rs`
- **Change:** Before incrementing nonce counter, check proximity to `u64::MAX`. Force ratchet step if within threshold
- **Test:** Unit test with nonce near max

### 3G. Replace unwrap() in production paths
- **Files:** `node/src/tunnel/listener.rs:91`, `node/src/tunnel/packet_norm.rs:202`
- **Change:** Replace with `expect("invariant: ...")` documenting safety, or proper error propagation

### Verification
```bash
cd node && cargo test
# Manual: run 3 nodes locally, verify bidirectional packet flow
# Verify UPnP maps ports on a NAT'd network
```

---

## Section 4: Client Tunnel Implementation

**Why fourth:** With relay nodes handling bidirectional traffic and shared types extracted, the client can now send real packets through the circuit.

### 4A. Implement real tunnel
- **File:** `client/src-tauri/src/tunnel.rs` — replace the `start_tunnel()` stub
- **Change:** The tunnel loop:
  1. Create TUN device (`tun-rs`, same as `node/src/tunnel/tun_device.rs`)
  2. Read outbound packets from TUN
  3. Sphinx-wrap via shared `shieldnode_types::sphinx` (from Section 2)
  4. Send to entry node via existing `get_relay_socket()`
  5. Receive return packets from entry node
  6. Sphinx-unwrap (peel 3 layers in reverse)
  7. Write decrypted packets to TUN
- **Note:** `register_sessions()` (tunnel.rs:96-132) and `request_receipt_cosign()` (tunnel.rs:190-258) already work — only the packet forwarding loop is missing

### 4B. Implement bandwidth metering
- **File:** `client/src-tauri/src/lib.rs`
- **Change:** The tunnel loop from 4A counts bytes on read/write. Update `bytes_used` via existing `real_packet_counter: Arc<AtomicU64>`
- **Also update:** `get_session()` command (lib.rs:513-536) to return real `bytes_used`
- **Frontend:** `SessionCost.tsx` already computes `bytes_used * 1e-12` — works once backend reports real numbers

### 4C. Kill switch crash recovery
- **File:** `client/src-tauri/src/kill_switch.rs`
- **Change:** On app startup, check if ShieldNode-specific firewall rules are active (query `netsh`/`iptables`/`pf`). If found and app is not connected, deactivate them

### 4D. Remove DNS leak in kill switch
- **File:** `client/src-tauri/src/kill_switch.rs`
- **Change:** Remove port 53 exception now that TUN routes all traffic including DNS
- **Dependency:** Requires 4A complete

### Verification
```bash
cd client && cargo build --manifest-path src-tauri/Cargo.toml
# Manual: connect through 3 local nodes, browse a website
# Verify SessionCost shows real bytes and cost
# Kill app mid-session, restart, verify firewall rules cleaned up
```

---

## Section 5: Client Security Hardening

**Why fifth:** With traffic flowing, secure the user's wallet before any external testing.

### 5A. WalletConnect v2 integration
- **File:** `client/src-tauri/src/wallet.rs` — replace `PrivateKeySigner` with WalletConnect
- **Change:**
  - Add WalletConnect v2 SDK dependency
  - On first use, display QR code / deep link in the React frontend for wallet pairing
  - Store WC session (not private key) in config
  - `open_session()` and `settle_session()` request signature from external wallet
  - Receipt signing (`receipts.rs::sign_receipt()`) also delegates to WC
- **Frontend changes:** Add pairing UI in `Settings.tsx` — QR code display, connection status, wallet address display
- **Remove:** `operator_private_key` field from `ClientConfig`. Migration: on first launch with old config, prompt user to pair wallet and discard stored key
- **Fallback:** If WC session expires mid-tunnel, queue the settlement and prompt user to re-pair on next app open

### 5B. Replace Alchemy demo key
- **File:** `client/src-tauri/src/config.rs` (~line 54)
- **Change:** Remove hardcoded demo key. Default to empty with clear error directing user to configure RPC. Add validation on startup (`eth_chainId` call)

### 5C. Sphinx MAC nonce inclusion
- **File:** `packages/shieldnode-types/src/sphinx.rs` (shared crate from Section 2)
- **Change:** Include per-session incrementing counter in MAC: `HMAC(key, nonce || next_hop || payload)` instead of `HMAC(key, next_hop || payload)`. Prevents packet replay
- **Single change point:** Thanks to Section 2, both node and client get this fix automatically

### 5D. Key zeroing for circuit keys
- **File:** `client/src-tauri/src/circuit.rs`
- **Change:** `impl Drop for CircuitState` that zeroizes per-hop session keys via `zeroize` crate

### Verification
```bash
# Test WC: pair MetaMask, connect circuit, verify tx signed externally
# Test RPC: remove URL from config, verify clear error on startup
# Test replay: capture two identical packets, verify different MACs
```

---

## Section 6: ZK Settlement Pipeline

**Why sixth:** With real traffic and metering, the ZK path can be completed. This is the privacy differentiator.

### 6A. Witness generation
- **File:** `client/src-tauri/src/settlement.rs` (~lines 88-102, currently returns hard error)
- **Change:** Build witness from real session data:
  - `session_id`, `cumulative_bytes`, `timestamp` from `SessionInfo`
  - `price_per_byte`, `deposit` from circuit state
  - Client signature from `sign_receipt()`
  - Node signature from `request_receipt_cosign()` (stored during session)
  - Public keys from wallet + node registry
  - Merkle proofs: build Poseidon Merkle tree client-side from on-chain registry data
- **Reference:** `client/src-tauri/src/zk_prove.rs` defines the witness structure (lines ~29-70)
- **Hardest part:** Client-side Poseidon Merkle tree construction matching circuit's depth-20 tree

### 6B. Proof generation integration
- **File:** `client/src-tauri/src/zk_prove.rs`
- **Change:** Wire `generate_proof()` to call `ark-groth16::Groth16::prove()` with witness from 6A. ProvingKey cache already implemented per TECH-DEBT.md

### 6C. Proof submission to ZKSettlement
- **File:** `client/src-tauri/src/wallet.rs` or `settlement.rs`
- **Change:** Call `ZKSettlement.settleWithProof()` via WalletConnect with Groth16 proof, 13 public signals, nullifier, depositId, payee addresses

### 6D. Circuit artifact distribution
- **File:** `client/src-tauri/src/settlement.rs`
- **Change:** Bundle circuit artifacts (`.r1cs`, `.wasm`, `.zkey`) in Tauri resources directory. Add `artifacts_path` to `ClientConfig` for override

### 6E. BandwidthReceipt witness example
- **File:** `circuits/bandwidth_receipt/input.json` (new)
- **Change:** Valid example witness JSON matching circuit inputs. Enables standalone prove/verify testing

### Verification
```bash
cd circuits && bash scripts/compile.sh && bash scripts/setup.sh
bash scripts/prove.sh && bash scripts/verify.sh
# End-to-end: connect, transfer data, disconnect, verify ZK settlement tx on Sepolia
```

---

## Section 7: CI/CD & Testing

**Why seventh:** With the product functional, add automation to prevent regressions.

### 7A. Contract CI workflow
- **File:** `.github/workflows/contracts.yml` (new)
- `forge build`, `forge test -vv`, `forge snapshot` on push/PR to `contracts/`

### 7B. Node CI workflow
- **File:** `.github/workflows/node.yml` (new)
- `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check` on push/PR to `node/`

### 7C. Client CI workflow
- **File:** `.github/workflows/client.yml` (new)
- `cargo build` (Tauri), `pnpm build`, TypeScript type check on push/PR to `client/`

### 7D. Security scanning
- **File:** `.github/workflows/security.yml` (new)
- Weekly: `cargo audit`, `pnpm audit`, check for ML-KEM/ML-DSA stable releases

### 7E. Integration test harness
- **File:** `tests/integration/` (new)
- Script: spin up 3 local nodes + `anvil`, connect client, send traffic, settle, verify on-chain state
- Start as smoke test, expand over time

### 7F. Contract fuzz expansion
- **Files:** `contracts/test/` (existing)
- Add fuzz tests for: payment calculation edges, force-settle scaling, getActiveNodes at scale

### Verification
```bash
# All CI locally:
cd contracts && forge test
cd node && cargo test && cargo clippy
cd client && pnpm build && cargo build --manifest-path src-tauri/Cargo.toml
```

---

## Section 8: Pre-Mainnet Hardening

**Why last:** Depends on all above. Prepares for audit, testnet soak, and launch.

### 8A. NAT traversal documentation
- **File:** `docs/OPERATOR-GUIDE.md` (update)
- Document UPnP behavior from 3D + manual port-forwarding fallback

### 8B. Trusted setup ceremony
- **File:** `circuits/trusted_setup/CEREMONY.md` (new)
- Download Hermez powers-of-tau (2^22), run Phase 2 setup, document multi-party procedure
- Dev ceremony for testnet; coordinate 10+ participants for mainnet

### 8C. circom-ecdsa audit
- **Action:** External — commission audit or switch to audited alternative
- **Deliverable:** Audit report or documented risk acceptance

### 8D. Extended testnet soak
- **Action:** Deploy contract fixes to Sepolia. Run 5-10 nodes for 30+ days
- **Monitor:** Heartbeats, settlements, gas costs, circuit health, UPnP reliability

### 8E. External security re-audit
- **Action:** Commission re-audit of contracts + ZK circuit
- **Dependency:** All Sections 1-6 complete and deployed

---

## Execution Order & Parallelism

```
Section 1: Contract Fixes        ─┐
                                   ├── parallel
Section 2: Shared Crate Extract  ─┘
                                   │
Section 3: Relay Node Data Plane ──┤ (depends on Section 2 for shared types)
                                   │
Section 4: Client Tunnel ──────────┤ (depends on Section 3 for relay readiness)
                                   │
Section 5: Client Security ────────┤ (depends on Section 4 for tunnel)
                                   │
Section 6: ZK Settlement ──────────┤ (depends on Section 4 for real traffic data)
                                   │
Section 7: CI/CD & Testing ────────┤ (can start after Section 1, expand incrementally)
                                   │
Section 8: Pre-Mainnet ────────────┘ (depends on all above)
```

**Critical path:** Section 2 → Section 3 → Section 4 → Section 6
