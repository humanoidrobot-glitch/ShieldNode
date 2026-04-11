# ShieldNode — Full Project Review (April 10, 2026)

## Overall Assessment

The project has made enormous progress. The control plane, cryptography, contracts, and infrastructure are mature. Two critical data plane issues remain that would prevent real usage, plus the WalletConnect integration is incomplete.

---

## What's Solid (No Rework Needed)

- **Smart contracts**: 162+ tests (including 5 new integration tests), all 14 Pashov audit findings remediated, comprehensive security patterns (pull-payment, reentrancy guards, two-step ownership, timelocks). No exploitable vulnerabilities found.
- **Cryptography**: Hybrid X25519 + ML-KEM-768, Sphinx (classic + PQ), ratcheting with forward secrecy, Noise NK, ChaCha20-Poly1305. All correctly implemented.
- **ZK circuits**: BandwidthReceipt (3.5M constraints) and NodeEligibility (12K) are mathematically sound with correct endianness, nullifier binding, and privacy guarantees. Groth16 proving is wired end-to-end.
- **Infrastructure**: Cargo workspace with shared crate (`packages/shieldnode-types`), CI (6 jobs + reproducible build), Docker, nonce-aware deploy script, integration tests (Foundry + shell smoke).
- **Documentation**: Production-grade across OPERATOR-GUIDE, OPERATOR-SECURITY, THREAT-MODEL, OWNERSHIP-RENOUNCEMENT, TECH-DEBT, anti-logging research.

---

## Critical Issues Remaining

### 1. Return Path Is Broken (Data Plane)

**The biggest weakness.** Traffic flows outbound (client → entry → relay → exit → internet) but responses cannot come back through the circuit.

- `node/src/network/relay_listener.rs` only handles incoming Sphinx packets — no code to read TUN responses and forward them back upstream
- Exit node's TUN listener (`node/src/tunnel/listener.rs:133-168`) sends WireGuard traffic back to `last_active_peer`, but relay nodes don't participate in return path forwarding
- Client's `tun_loop.rs::decrypt_inbound()` expects reverse-Sphinx layered encryption, but no node produces this format
- Comment at `tun_loop.rs:6-8` admits: "Full reverse-Sphinx onion routing for the return path is tracked as future work"

**Impact**: Any real traffic (browsing, API calls) will timeout waiting for responses.

**Fix**: Implement reverse-path Sphinx wrapping on the exit node, with relay nodes forwarding return packets back through the circuit.

### 2. WalletConnect Bridge Wired But Not Used

- `wallet_bridge.rs` is architecturally complete (async signing bridge, Tauri events, frontend hook)
- `config.rs` has `WalletMode::WalletConnect` enum
- `lib.rs` has `resolve_signing`, `get_wallet_mode`, `set_wallet_mode` commands
- Frontend `useWallet.ts` hook handles pairing and signing events
- **BUT**: `wallet.rs` lines 66-155 **never checks `wallet_mode`** — all three signing functions (`open_session`, `settle_session`, `zk_deposit`) unconditionally call `parse_signer()`
- If user connects MetaMask, backend still tries to use local private key and fails

**Fix**: Add conditional branching in `wallet.rs` — when `WalletMode::WalletConnect`, emit signing events to frontend via bridge instead of `parse_signer()`.

### 3. ZKSettlement Registry Root Is Manual

- `ZKSettlement.sol:280-310`: `proposeRegistryRoot()` / `executeRegistryRoot()` with 48-hour timelock
- Requires manual intervention every time node registry changes materially
- If owner unavailable, ZK settlement halts

**Impact**: Operational burden, single point of failure for ZK settlements.

---

## High Priority Items

| Issue | Severity | Effort |
|-------|----------|--------|
| Reverse-path Sphinx (return traffic) | **Critical** | 3-5 days |
| Wire WalletConnect into wallet.rs | **High** | 1 day |
| Multi-peer routing on exit nodes (`last_active_peer` assumption) | **High** | 1 day |
| External security audit (contracts + node crypto) | **High** | 4-6 weeks |
| Upgrade ML-KEM/ML-DSA from RC to stable | **Medium** | When available |
| ZKSettlement registry root automation | **Medium** | 2 days |
| Trusted setup ceremony (multi-party) | **Medium** | 1-2 weeks coordination |
| circom-ecdsa library audit | **Medium** | External |
| UPnP lease renewal (expires after 1 hour) | **Medium** | 1 day |
| `cargo audit` without `|| true` in CI | **Low** | 10 min |

---

## Work Completed (April 9-10)

### From Implementation Plan (all items done)
| Item | Commit | Description |
|------|--------|-------------|
| A1 | `bda973f` | Node registration ABI aligned with secp256k1 contract changes |
| A2 | `099ecdc` | Client TUN device integration with Sphinx forwarding loops |
| B1 | `237fbbd` | UPnP/IGD port mapping for NAT traversal |
| B2 | `d0527bd` | Circuit session key zeroization on drop |
| B3 | `ad0d740` | Production unwrap() replaced with expect() |
| B4 | `dfef5bf` | DNS leak removed from kill switch (all platforms) |
| C1 | `49ff094` + `12937f3` | Shared types crate (AEAD, KDF, EIP-712, hop codec, Sphinx MAC) |
| C2 | `2ecff55` | WalletConnect v2 signing bridge (backend + frontend) |
| C3 | `f0c2a35` + `58eed89` | CI: clippy, cargo-audit, pnpm audit, gas snapshots |
| C4 | `e591d8a` | Integration test harness (Foundry + shell smoke) |

### Additional fixes
| Commit | Description |
|--------|-------------|
| `4e809e0` | Simplify: UPnP local IP fix, chain key zeroize, CI hardening |
| `0eb8260` | README + ROADMAP updated to reflect current state |
| `6c5f8cc` | Docker workspace fix (both Dockerfiles) |
| `2688930` | CI client linker fix (--lib for Tauri) |

### Previously completed (by user, pre-April 9)
- Real boringtun WireGuard integration (`7c7a706`)
- TUN bidirectional exit mode on relay node (`a18e32e`)
- Batch reorder loop spawned (`4d10a84`)
- Packet normalization wired into relay path (`750ecb5`)
- Bandwidth metering from tunnel counters (`b9f70e1`)
- Kill switch crash recovery via sentinel (`03c82d8`)
- OS keychain private key storage (`587fc22`)
- Sphinx MAC hop_index replay protection (`26515d2`)
- Ed25519 watchlist verification (`522e7de`)
- Handshake deadlock fix (`a2d1ca0`)
- NodeKeyPair zeroization via ZeroizeOnDrop (`ba38641`)
- Comprehensive CI workflow (`c824798`)
- Hardcoded Alchemy key removed (`0f3df04`)
- secp256k1 pubkey in NodeRegistry + ZK deposit wiring (`e323b69`)
- ZK settlement pipeline: witness builder, Merkle tree, proof generation (`5ca9a24`, `57e3ef2`, `ae65c0e`, `7ecc31c`)

---

## Contract Security Summary

- **162+ tests** across 20 files (unit, fuzz, invariant, halmos, fork, integration)
- **0 critical / 0 high / 1 medium** finding (registry root management)
- All interfaces match implementations
- Pull-payment pattern on all withdrawals
- Reentrancy guards on all ETH-sending functions
- Two-step ownership on all admin contracts
- 48-hour timelocks on sensitive operations
- Progressive slashing (10% → 25% → 100% + ban) with separate fraud/liveness tracks
- `_activeNodeIds` swap-and-pop for efficient pagination
- `cleanupSession()` with 30-day timeout for abandoned sessions
- secp256k1 key validation prevents operator impersonation

---

## Pre-Mainnet Checklist

### Phase 1: Make Traffic Flow (1-2 weeks)
- [ ] Implement reverse-path Sphinx for return traffic through relay chain
- [ ] Wire WalletConnect conditional signing in wallet.rs
- [ ] Fix exit node multi-peer routing (support concurrent clients)
- [ ] Deploy updated contracts to Sepolia

### Phase 2: Testnet Validation (2-4 weeks)
- [ ] Register 5-10 seed nodes on Sepolia
- [ ] Run 30+ day soak test with real traffic
- [ ] Verify bandwidth metering accuracy
- [ ] Verify settlement receipts (plaintext + ZK)
- [ ] Measure gas costs against estimates
- [ ] Implement UPnP lease renewal

### Phase 3: Security Audit (4-6 weeks)
- [ ] External audit of contracts (SessionSettlement, ZKSettlement, NodeRegistry)
- [ ] External audit of node crypto (Sphinx, ratcheting, hybrid KEM)
- [ ] Audit circom-ecdsa library (unaudited PoC)
- [ ] Run complete Halmos formal verification
- [ ] Upgrade ML-KEM/ML-DSA to stable releases

### Phase 4: Mainnet Launch
- [ ] Multi-party trusted setup ceremony for Groth16
- [ ] Deploy immutable contracts to L1
- [ ] Establish multisig for admin roles (oracle, treasury, pauser)
- [ ] Register foundation seed nodes
- [ ] Operator onboarding (docs site, Discord)
- [ ] Public analytics dashboard
