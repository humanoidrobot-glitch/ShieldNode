# ShieldNode — Remaining Work Plan (April 10, 2026)

## Context

Re-review revealed that many items from the April 9 plan were completed independently. ZK settlement, nonce overflow, key zeroization (node), Sphinx MAC replay, kill switch crash recovery, bandwidth metering, and more are done. This plan covers only what's still outstanding.

**Workflow:** Each item gets implemented, tested, simplify'd, and committed before moving to the next.

---

## Part A: Critical Blockers

### A1. Fix node registration ABI mismatch
**Why:** Node registration will REVERT on Sepolia — the sol! macro in the node code doesn't match the contract's new `register(nodeId, publicKey, endpoint, secp256k1Key)` signature.

**Files:**
- `node/src/network/chain.rs` — Update sol! macro + ChainService::register()
- `node/src/main.rs` — Update register call to derive and pass secp256k1 key

**Changes:**
1. Update sol! macro (chain.rs:12-31):
   - `register()` → add `bytes calldata secp256k1Key` parameter
   - `NodeInfo` struct → add all missing fields (slashCount, isActive, pricePerByte, commitment, secp256k1X, secp256k1Y) to match the actual contract struct
2. Update `ChainService::register()` (chain.rs:105-138):
   - Accept `secp256k1_pubkey: &[u8; 64]` parameter
   - Pass it as `Bytes::from(secp256k1_pubkey.to_vec())` to the contract call
3. Update `main.rs` (~line 166):
   - Derive secp256k1 public key from `operator_key` using `k256::ecdsa::SigningKey` → `VerifyingKey` → `EncodedPoint` (uncompressed, 64 bytes without 0x04 prefix)
   - Pass to `chain.register()`

**Reference:** `k256` v0.13 is already in `node/Cargo.toml`. The client's `chain.rs` shows the correct NodeInfo struct with all fields.

**Verify:** `cd node && cargo build`

### A2. Complete client tunnel TUN integration
**Why:** WireGuard encapsulation is implemented but no TUN device captures system traffic. Users can't browse through the VPN.

**Files:**
- `client/src-tauri/src/tunnel.rs` — Add TUN device read/write loop
- `client/src-tauri/src/lib.rs` — Wire TUN into connect/disconnect lifecycle

**Changes:**
1. In `start_tunnel()`, after WireGuard handshake:
   - Create TUN device via `tun-rs` (same as node's `tun_device.rs`)
   - Spawn read loop: TUN → Sphinx wrap → UDP to entry node
   - Spawn write loop: UDP from entry node → Sphinx unwrap → TUN
   - Track `bytes_used` via the existing `real_packet_counter: Arc<AtomicU64>`
2. On disconnect, tear down TUN device and stop loops

**Reference:** 
- Node's TUN: `node/src/tunnel/tun_device.rs` (AsyncTunDevice pattern)
- Existing Sphinx: `client/src-tauri/src/sphinx.rs` (create_packet, peel)
- Existing UDP: `tunnel.rs::get_relay_socket()`, `send_sphinx_packet()`

**Verify:** `cd client/src-tauri && cargo build`

---

## Part B: High Priority

### B1. Implement UPnP port mapping
**Why:** User chose "implement UPnP now" — nodes behind NAT can't receive connections.

**Files:**
- `node/Cargo.toml` — Add `igd-next` dependency
- `node/src/network/nat.rs` — New file
- `node/src/main.rs` — Call on startup
- `node/src/config.rs` — Add `upnp_enabled` field

**Changes:**
1. Add `igd-next = "0.15"` to Cargo.toml
2. Create `nat.rs` with `attempt_upnp_mapping(ports: &[u16], protocol: &str)`:
   - Search for gateway via `igd_next::search_gateway()`
   - Map each port with 1-hour lease (renewable)
   - Log success/failure per port, graceful fallback
3. Call from main.rs before socket binding when `config.upnp_enabled` (default true)
4. Map: 51820/UDP (WireGuard), 51821/UDP (relay), 4001/TCP (libp2p)

**Verify:** `cd node && cargo build` (functional test requires NAT environment)

### B2. Add circuit key zeroing
**Why:** CircuitState holds per-hop session keys that aren't zeroized on drop.

**Files:**
- `client/src-tauri/src/circuit.rs` — Add Drop impl with zeroize
- `client/src-tauri/Cargo.toml` — Add `zeroize` dependency if not present

**Changes:**
1. `impl Drop for CircuitState` — iterate hops, zeroize each `session_key: [u8; 32]`
2. Or derive `Zeroize` + `ZeroizeOnDrop` on the key fields

**Verify:** `cd client/src-tauri && cargo build`

### B3. Replace unwrap() in production paths
**Why:** 2 unwrap() calls in hot paths could panic on invariant violations.

**Files:**
- `node/src/tunnel/listener.rs:99` — Replace with `.expect("peer must exist after get_or_create")`
- `node/src/tunnel/packet_norm.rs:202` — Replace with `.expect("pending must be non-empty when len > 256")`

**Verify:** `cd node && cargo test`

### B4. Remove DNS leak from kill switch
**Why:** Port 53 is excepted on all platforms, leaking DNS queries outside the tunnel.

**Files:**
- `client/src-tauri/src/kill_switch.rs` — Remove port 53 exception rules on all 3 platforms

**Changes:**
1. Remove the `AllowDNS` rule blocks for Windows (netsh), Linux (iptables), macOS (pf)
2. DNS will route through the TUN device along with all other traffic
3. Update the comment explaining the removal

**Dependency:** Requires A2 (TUN integration) to be complete so DNS can route through tunnel.

**Verify:** `cd client/src-tauri && cargo build`

---

## Part C: Medium Priority

### C1. Shared crate extraction
**Why:** User chose "do it first" — duplicated code between node and client should be unified.

**Files:**
- `Cargo.toml` (new root workspace)
- `packages/shieldnode-types/Cargo.toml` (new crate)
- `packages/shieldnode-types/src/lib.rs` + modules
- `node/Cargo.toml` — Add workspace member + dependency
- `client/src-tauri/Cargo.toml` — Add workspace member + dependency
- Many `use` import updates in node/ and client/

**Changes:**
1. Create root `Cargo.toml` workspace: members = ["node", "client/src-tauri", "packages/shieldnode-types"]
2. Create `packages/shieldnode-types/` with:
   - `receipts.rs`: EIP-712 domain separator, receipt digest, encoding
   - `sphinx.rs`: compute_mac, SphinxPacket types, PQ types
   - `crypto.rs`: hkdf_sha256, AEAD wrapper, KeyExchange/Signer traits
   - `hop_codec.rs`: encode/decode next hop
   - `scoring.rs`: constants and formula
3. Update imports in node and client to use `shieldnode_types::`
4. Remove duplicated modules from both crates

**Verify:** `cargo test --workspace`

### C2. WalletConnect integration
**Why:** User chose WalletConnect for key security. OS keychain is done but WC was the decision.

**Files:**
- `client/src-tauri/src/wallet.rs` — Replace PrivateKeySigner with WC
- `client/src-tauri/Cargo.toml` — Add WalletConnect SDK
- `client/src/components/Settings.tsx` — Add pairing UI

**Changes:** Large scope — WC v2 SDK integration, QR code display, session management, delegated signing for openSession/settleSession/receipts. Consider: OS keychain may be sufficient for MVP and WC can be Phase 5.

**Decision needed:** Is OS keychain sufficient for now, or is WalletConnect still required before mainnet?

### C3. CI security scanning
**Why:** CI has unit tests but no dependency auditing or linting enforcement.

**Files:**
- `.github/workflows/ci.yml` — Add jobs

**Changes:**
1. Add `clippy` job: `cargo clippy --all-targets -- -D warnings`
2. Add `cargo-audit` job: `cargo install cargo-audit && cargo audit`
3. Add `pnpm audit` for frontend dependencies
4. Add `forge snapshot` for gas regression tracking

**Verify:** Push to branch, verify CI passes

### C4. Integration test harness
**Why:** No end-to-end test exists. Individual unit tests pass but the full flow is untested.

**Files:**
- `tests/integration/` (new directory)
- `tests/integration/smoke.sh` (or Rust test binary)

**Changes:**
1. Script that:
   - Starts `anvil` (local chain)
   - Deploys contracts via `forge script`
   - Starts 3 relay nodes
   - Runs client connect → transfer → settle
   - Verifies on-chain state
2. Start simple, expand over time

**Verify:** Run the script end-to-end

---

## Execution Order

```
A1  Node ABI mismatch fix         (commit + simplify)
A2  Client TUN integration        (commit + simplify)
B1  UPnP implementation           (commit + simplify)
B2  Circuit key zeroing           (commit + simplify)
B3  Replace unwrap()              (commit + simplify)
B4  DNS leak removal              (commit + simplify, depends on A2)
C1  Shared crate extraction       (commit + simplify)
C2  WalletConnect (if needed)     (commit + simplify)
C3  CI security scanning          (commit + simplify)
C4  Integration test harness      (commit + simplify)
```

Each item: implement → test → run simplify → commit with conventional format → move to next.
