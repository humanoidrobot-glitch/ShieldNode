# ShieldNode — Full Project Review (April 9, 2026)

## Overall Assessment

Technically impressive project with strong cryptography, excellent documentation, and thoughtful architecture. The foundations are solid, but there are clear gaps between current state and mainnet readiness.

**What exists:** A well-architected protocol with strong crypto, sound ZK circuits, audited contracts (with fixes in progress), excellent docs, and a polished client UI.

**What's missing:** The actual data plane. Traffic doesn't flow yet. The control plane (circuit selection, scoring, on-chain sessions) is essentially complete, but the forwarding plane (tunnel, WireGuard, Sphinx packet relay, bandwidth metering, receipt signing) needs to be finished and connected end-to-end.

---

## Critical Blockers (Must Fix Before Any Real Usage)

### 1. The Client Has No Actual Tunnel
- `client/src-tauri/src/tunnel.rs` — `start_tunnel()` logs "starting tunnel (stub)" and does nothing
- No TUN/TAP device, no WireGuard integration, no actual packet routing
- Connect/disconnect flow works, circuit selection is sophisticated, UI is polished — but no traffic flows
- `bytes_used` is hardcoded to 0 everywhere
- **Fix:** Integrate boringtun + TUN device in client (relay node has partial implementations to reference)

### 2. Relay Node Incomplete for End-to-End Traffic
- **Bidirectional exit mode not implemented** — `node/src/tunnel/listener.rs` line 280: TUN read path stubbed (Phase 2)
- **Session setup/teardown control messages** — `node/src/network/relay_listener.rs`: skeleton only, not parsed
- **Batch reorder loop** — `node/src/network/batch_reorder.rs`: fully implemented but **never spawned** in main.rs
- **Packet normalization** — `node/src/tunnel/packet_norm.rs`: implemented but **not wired into relay forward path**
- **NAT traversal** — completely missing. Nodes behind NAT can't receive connections. Need UPnP/hole punching or document manual port-forwarding requirement

### 3. Settlement Receipts Not Actually Signed or Verified
- EIP-712 digest computed but **node signatures never verified** in client
- Client sends `receipt_data` to `settleSession()` without proper dual-signed receipts
- Nodes could forge bandwidth claims, clients could underpay
- **Fix:** Implement full dual-signature flow per the EIP-712 spec already defined in `client/src-tauri/src/receipts.rs` and `client/src/lib/eip712.ts`

### 4. ZK Settlement Is a Stub
- `client/src-tauri/src/settlement.rs` lines 88-100: `settle_zk()` checks if artifacts exist, then has a TODO
- No witness generation, no proof generation, no submission to ZKSettlement
- Every session falls back to plaintext settlement
- Arkworks integration declared in Cargo.toml but never exercised
- Circuit artifacts paths hardcoded but files likely don't exist on client machines

---

## High-Priority Security Issues

### Smart Contracts

| Issue | Location | Impact |
|-------|----------|--------|
| Division-by-zero when `cumulativeBytes=0` | `SessionSettlement._settle()` lines 338-340 | Revert on zero-byte sessions |
| Exit node share not explicitly verified in ZK path | `ZKSettlement._verifyAndCredit()` lines 355-361 | Potential underpayment to exit nodes |
| `getActiveNodes()` iterates ALL nodes twice (unbounded) | `NodeRegistry` lines 249-282 | DoS at scale (1000+ registrations) |
| No reentrancy guard on `slash()` | `NodeRegistry` lines 298-318 | Cross-contract reentrancy risk via external call |
| Commitment field always zero | `NodeRegistry.register()` | Phase 6 ZK eligibility will break without migration |
| Missing events on permanent ban | `SlashingOracle.executeSlash()` | Off-chain indexers can't track bans |
| Missing event on retrySlash success | `ChallengeManager.retrySlash()` lines 320-331 | Challenge state history incomplete |
| No idle session cleanup mechanism | `SessionSettlement` | Abandoned sessions permanently block node unstaking |
| Force-settle cap (50%) not justified in spec | `SessionSettlement` | Potential node overpayment |
| Inconsistent error style (require vs revert) | All contracts | Client-side error parsing harder |

### Rust Relay Node

| Issue | Location | Impact |
|-------|----------|--------|
| `NodeKeyPair` has no `Drop` impl — secret never zeroized | `node/src/crypto/keys.rs` line 26-27 | Persistent key in memory after drop |
| ML-KEM v0.3.0-rc.0 and ML-DSA v0.1.0-rc.8 (RC versions) | `node/Cargo.toml` | API may change; not production-grade |
| No nonce overflow protection in ratchet | `node/src/crypto/ratchet.rs` | Theoretical wrap-around after extreme usage |
| `unwrap()` calls in production paths | `tunnel/listener.rs:91`, `tunnel/packet_norm.rs:202` | Panic on invariant violation |
| No per-operation timeouts on relay forwarding | `relay_listener.rs` | Long-lived ops can block shutdown |
| Lock contention on BandwidthTracker per-packet | `metrics/bandwidth.rs` | Bottleneck under high throughput (10K+ pps) |

### Client Application

| Issue | Location | Impact |
|-------|----------|--------|
| Private key stored as plaintext hex in JSON config | `client/src-tauri/src/config.rs` line 42-44 | Disk compromise = fund loss |
| Default Alchemy demo API key exposed | `config.rs` line 54 | Rate limiting, unreliable |
| Kill switch stays active on crash | `kill_switch.rs` | User loses all internet if app crashes |
| No WalletConnect / hardware wallet support | `wallet.rs` | Only raw private key import |
| Sphinx MAC doesn't include nonce | `sphinx.rs` | Onion packet replay possible |
| No key zeroing — old circuit keys live in memory until GC | `kex.rs`, `circuit.rs` | Memory scraping attack surface |
| Unsigned community watchlists accepted | `watchlist.rs` lines 28-32 | MitM can inject false node flags |
| Silent failures in React hooks | `useCircuit.ts` lines 45-48 | Errors swallowed, user not informed |

---

## What's Working Well (No Significant Rework Needed)

### Cryptography Layer
- Hybrid X25519 + ML-KEM-768 correctly implemented (`node/src/crypto/hybrid.rs`)
- Sphinx onion routing with both classic and PQ variants (`node/src/crypto/sphinx.rs`) — 17 test cases
- Ratcheting with forward secrecy, 30s/10MB rekey, one-epoch lookback, proper zeroization (`ratchet.rs`)
- Noise NK handshake (`noise.rs`)
- ChaCha20-Poly1305 AEAD
- ECDSA (secp256k1) and ML-DSA-65 (FIPS 204) signing
- Crypto trait abstractions (`KeyExchange`, `Signer`) with KEM semantics ready for PQ

### ZK Circuits
- **BandwidthReceipt** (`circuits/bandwidth_receipt/circuit.circom`, 353 lines, ~3.5M constraints): Mathematically sound
  - In-circuit EIP-712 digest computation (eliminates external trust)
  - Dual ECDSA verification (client + node co-signatures)
  - 3-node Merkle registry proofs (depth 20, ~1M node capacity)
  - Correct division-with-remainder pattern for payment splits
  - Poseidon commitment binding for all 4 payees
  - Nullifier prevents proof replay
  - All sensitive data private; strong privacy guarantees
  - Correct endianness handling (big-endian EVM ↔ little-endian circom)
- **NodeEligibility** (`circuits/node_eligibility/circuit.circom`, 102 lines, ~12K constraints): Clean, minimal, correct
- Custom Merkle verification (`circuits/lib/merkle.circom`): Constant-time, no branch leaks
- Build/setup/prove/verify scripts all present and correct

### Smart Contract Architecture
- Pull-payment pattern, two-step ownership transfers, progressive slashing
- Timelocked admin actions (48h for challenger/root updates)
- Pashov AI audit: 17 findings, most remediated in commits `e6a7fc5`, `0861fc4`
- Halmos formal verification specs added for critical paths
- Fork tests for Ethereum integration
- 18 test files, 127+ test functions

### Documentation (Production-Grade)
- `docs/OPERATOR-GUIDE.md` — Complete setup, config, troubleshooting, economics
- `docs/OPERATOR-SECURITY.md` — Key management, Safe wallets, PQ migration path
- `docs/THREAT-MODEL.md` — Adversary model, traffic morphing research
- `docs/OWNERSHIP-RENOUNCEMENT.md` — 6-phase trust minimization roadmap
- `docs/TECH-DEBT.md` — Known deferred items with timeline
- `docs/ZK-CIRCUIT-REVIEW.md` — Circuit security analysis + action items
- `docs/anti-logging-research.md` — Hardware TEE, reproducible builds, cover traffic
- `ROADMAP.md` (57K+) — Phases 1-6 with completion status

### Client UX Architecture
- Circuit selection with diversity constraints (subnet /24, ASN, region, operator address)
- Node scoring: `10*sqrt(stake) + 25*uptime - 0.001*price - 15*slash^2 + 15*completion + 20*TEE`
- Health monitoring with throughput sampling and automatic circuit rebuild
- Auto-rotation on configurable interval (default 10 min)
- Cover traffic (10 or 50 pps with COVER_MARKER)
- Kill switch (Windows netsh, Linux iptables, macOS pf)
- Community watchlists with optional Ed25519 signature verification
- Client-side reputation tracking (low-bandwidth flags, stake concentration clusters)
- Debounced settings persistence
- Clean React 19 + Tailwind v4 frontend

### Infrastructure
- Production Dockerfile + deterministic reproducible build for TEE attestation
- docker-compose.yml with healthchecks, volume mounts, port mappings
- `verify-build.sh` for binary hash verification
- Nonce-aware deployment script (`contracts/script/Deploy.s.sol`) with two-step ownership transfer
- GitHub Actions workflow for reproducible build verification

---

## Component Completeness Matrix

### Relay Node (`node/src/`)

| Component | Status | Notes |
|-----------|--------|-------|
| Crypto: X25519 KEM | Complete | Correct trait abstraction |
| Crypto: ML-KEM-768 | Complete | FIPS 203, correct sizes |
| Crypto: Hybrid KEM | Complete | X25519+ML-KEM via HKDF-SHA256 |
| Crypto: Sphinx (classic+PQ) | Complete | 17 test cases |
| Crypto: Ratcheting | Complete | Forward secrecy, zeroization |
| Crypto: Noise NK | Complete | X25519 only (no hybrid) |
| Crypto: ECDSA | Complete | secp256k1 via k256 |
| Crypto: ML-DSA-65 | Complete | FIPS 204, OsRng workaround |
| Network: Relay service | Complete | Session management, forwarding |
| Network: Control messages | Complete | Registry, no discriminant collisions |
| Network: EIP-712 receipts | Complete | Signing works |
| Network: libp2p discovery | Complete | Kademlia + gossipsub + mDNS |
| Network: Link padding | Complete | Per-peer rate, ±15% jitter |
| Network: Batch reorder | Complete | **But never spawned in main.rs** |
| Tunnel: WireGuard wrapper | Complete | boringtun integration |
| Tunnel: Packet normalization | Complete | **Not wired into relay path** |
| Tunnel: TUN device | Partial | Write path only; read path stubbed |
| Tunnel: Circuit state | Partial | CRUD only; no lifetime state machine |
| Network: Relay listener | Partial | UDP bind works; control msg parsing stub |
| Network: NAT traversal | Missing | No UPnP, hole punching, or relay assist |
| Network: Chain interaction | Partial | Registration skeleton |
| Metrics: API | Complete | Axum HTTP server |
| Metrics: Bandwidth | Complete | Per-session byte tracking |

### Client (`client/`)

| Feature | Status | Notes |
|---------|--------|-------|
| Connect/Disconnect lifecycle | Complete | Proper state cleanup |
| 3-hop circuit selection | Complete | Weighted random, diversity constraints |
| On-chain session open | Complete | 0.001 ETH deposit, event parsing |
| Node fetching & caching | Complete | 60s TTL, completion rate cache 10min |
| Node scoring | Complete | Mirrors Rust formula |
| Circuit visualization (UI) | Complete | 3-hop diagram |
| Auto-rotation | Complete | Configurable interval |
| Health monitor | Complete | Throughput sampling, auto-rebuild |
| Cover traffic | Complete | 10/50 pps levels |
| Kill switch | Complete | Windows/Linux/macOS |
| Settings persistence | Complete | Debounced JSON save |
| Community watchlists | Complete | Optional Ed25519 verify |
| Reputation tracking | Complete | Low-bandwidth, stake clusters |
| Gas monitor (UI) | Complete | 30s polling, color-coded |
| Session cost display (UI) | Complete | **But bytes_used always 0** |
| On-chain session settle | Partial | Receipt format defined, sigs unchecked |
| ZK settlement | Stub | TODO comment, artifacts not generated |
| Actual WireGuard tunnel | Missing | `start_tunnel()` is a stub |
| Bandwidth metering | Missing | Hardcoded to 0 |
| TUN/TAP integration | Missing | Only test `send_packet()` |
| Receipt signing (real) | Missing | EIP-712 digest computed, never signed |
| Private key encryption | Missing | Plaintext in JSON |
| Hardware wallet support | Missing | Comment: "WalletConnect in production" |

### Smart Contracts (`contracts/src/`)

| Contract | Status | Notes |
|----------|--------|-------|
| NodeRegistry | Complete | Needs: reentrancy guard on slash, getActiveNodes optimization, commitment field |
| SessionSettlement | Complete | Needs: division-by-zero fix, idle session cleanup |
| SlashingOracle | Complete | Needs: permanent ban event, consistent error style |
| ZKSettlement | Complete | Needs: exit share verification, clarify deposit pool sharing |
| Treasury | Complete | Timelock + multisig |
| ChallengeManager | Complete | Needs: retrySlash success event, evidence validation |
| CommitmentTree | Complete | Needs: initialize validation |
| EligibilityVerifier | Complete | Needs: root validation documentation |
| Deploy.s.sol | Complete | Nonce-aware, two-step ownership |

### ZK Circuits (`circuits/`)

| Circuit | Status | Notes |
|---------|--------|-------|
| BandwidthReceipt | Complete | ~3.5M constraints, ECDSA only |
| NodeEligibility | Complete | ~12K constraints |
| Merkle library | Complete | Constant-time |
| circom-ecdsa | External | **Unaudited PoC — needs audit before mainnet** |
| keccak256-circom | External | ~151K constraints per hash |
| Build scripts | Complete | compile/setup/prove/verify |
| ML-DSA support | Missing | Planned future iteration |
| Witness examples | Missing | No input.json for BandwidthReceipt |
| Trusted setup ceremony | Missing | Dev ceremony only |

---

## CI/CD Status

| Component | Build | Test | Deploy | Security Scan | Artifact |
|-----------|-------|------|--------|---------------|----------|
| Relay Node | YES (Docker) | YES (cargo test) | YES (reproducible) | NO | YES |
| Contracts | YES (forge) | YES (forge test) | YES (script) | PARTIAL (X-Ray) | NO |
| Client | NO | NO | NO | NO | NO |
| ZK Circuits | YES (scripts) | NO | NO | NO | NO |

**Single CI workflow:** `.github/workflows/reproducible-build.yml` (relay node only)

---

## Pre-Mainnet Checklist

### P0 — Must Do (Blocking)

- [ ] **Implement actual tunnel in client** (TUN + boringtun + Sphinx packet sending)
- [ ] **Complete relay node data plane**: bidirectional exit mode, session setup parsing, wire in batch reorder + packet normalization
- [ ] **Implement bandwidth metering** — track real bytes, generate real receipts
- [ ] **Sign and verify receipts** — dual EIP-712 signatures, both client and node
- [ ] **Fix SessionSettlement division-by-zero** when `cumulativeBytes=0`
- [ ] **Fix NodeRegistry.getActiveNodes()** — maintain separate active node list
- [ ] **Add idle session cleanup** with timeout mechanism
- [ ] **Add NodeKeyPair zeroization** in relay node (`impl Drop`)
- [ ] **Encrypt private keys at rest** in client (or implement WalletConnect)
- [ ] **NAT traversal** — UPnP/hole punching or document manual port-forwarding
- [ ] **External security re-audit** — Pashov findings remediated but need sign-off
- [ ] **ZK trusted setup ceremony** — multi-party ceremony (dev-only so far)
- [ ] **Audit circom-ecdsa library** — explicitly labeled "not for production"

### P1 — Should Do (High Priority)

- [ ] **Expand CI/CD** — add `forge test`, `cargo test`, `npm audit`, client builds
- [ ] **End-to-end integration tests** — client → entry → relay → exit → settle
- [ ] **Extract shared types crate** (`packages/shieldnode-types/`) — deduplicate scoring, EIP-712, Sphinx
- [ ] **Load testing** — 100+ concurrent circuits, measure lock contention
- [ ] **Monitoring infrastructure** — Prometheus exporter, Grafana dashboard
- [ ] **Fuzz testing** — Sphinx packet parsing, control messages, contract payment math
- [ ] **Add missing contract events** — permanent ban, retrySlash success
- [ ] **Fix ZKSettlement exit share verification** — add explicit check
- [ ] **Add reentrancy guard to NodeRegistry.slash()**
- [ ] **Fix kill switch crash behavior** — watchdog or crash recovery
- [ ] **Verify ML-KEM/ML-DSA crate stability** — upgrade when stable releases ship
- [ ] **Complete ZK settlement in client** — witness generation, proof submission

### P2 — Before Mainnet Launch

- [ ] **Run 10+ nodes on Sepolia for 30+ days** — gather performance data
- [ ] **NodeRegistry commitment field** — allow setting at registration or via setter
- [ ] **Rate limiting** per peer/circuit in relay node
- [ ] **Graceful circuit degradation** (one failed hop shouldn't kill circuit)
- [ ] **IPv6 support** in TUN device
- [ ] **Per-operation timeouts** in relay forwarding
- [ ] **Replace Alchemy demo key** with production RPC configuration
- [ ] **Code signing** for Tauri app (Windows + macOS notarization)
- [ ] **Operator community infrastructure** — Discord, documentation site
- [ ] **On-chain analytics** — The Graph subgraph

---

## Recommended Order of Work

1. **Get a 3-hop packet flowing:** client → entry → relay → exit → internet → back
2. **Wire up real bandwidth metering and receipt signing**
3. **Fix critical contract bugs** (division-by-zero, getActiveNodes, idle cleanup)
4. **Security hardening** (key zeroization, encrypted storage, reentrancy guards)
5. **Run 5-10 nodes on Sepolia for 30+ days**
6. **Expand CI/CD and add integration tests**
7. **Commission external re-audit**
8. **Run ZK trusted setup ceremony**
9. **Mainnet deploy**

The hardest part (crypto design, protocol architecture, contracts, ZK circuits) is done. What remains is plumbing — connecting the pieces that already exist into a working data path, then hardening for production.

---

## Audit History

| Date | Type | Scope | Findings | Status |
|------|------|-------|----------|--------|
| Apr 6, 2026 | Pashov AI | All contracts | 17 (7C, 5H, 5M/L) | Remediated in code, needs sign-off |
| Apr 2026 | Internal X-Ray | 1534 nSLOC contracts | Entry point mapping, trust boundaries | Complete |
| Apr 9, 2026 | Internal ZK Review | Both circuits | Poseidon/keccak analysis | Fixed per git |
| Apr 9, 2026 | Full Project Review | All components | This document | Active |

## Testnet Deployment (Sepolia)

```
NodeRegistry:       0xC6D9923E54547e0C7c5B456bFf16fEdF2d61df11
SessionSettlement:  0xF32aE5324E3caCCEC4F198FEF783482A0c5eE959
SlashingOracle:     0x28E5059F61F458a86c5318C63b8b7688BA678FeD
Treasury:           0xaE76fF930d1137b4a10e76285d82A5e40FF0619f
```
