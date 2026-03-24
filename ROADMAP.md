# ShieldNode Roadmap

This document tracks the development milestones for ShieldNode. Each phase builds on the previous one, progressing from a functional single-hop relay to a fully decentralized, ZK-private VPN network on Ethereum L1.

---

## Phase 1: Single-Hop Tunnel (MVP) -- COMPLETE

The foundation: a working relay node, on-chain contracts, and a basic client.

- [x] **Relay node binary** — WireGuard tunnel (boringtun), UDP listener with peer management, Sphinx onion routing, HKDF-SHA256 key derivation, ChaCha20-Poly1305 encryption, libp2p discovery (Kademlia + Gossipsub + mDNS), heartbeat service, metrics HTTP API
- [x] **Node wired end-to-end** — All services orchestrated via tokio (UDP listener, metrics API, heartbeat, libp2p discovery), persistent key management (load-or-generate), graceful Ctrl+C shutdown, stale peer eviction
- [x] **Smart contracts** — NodeRegistry (staking, heartbeats, paginated queries, slashing), SessionSettlement (EIP-712 receipts, 25/25/50 split, force-settle), SlashingOracle (progressive slashing), Treasury (timelock withdrawals). 19 Foundry tests passing
- [x] **Contracts deployed to Sepolia** — NodeRegistry (`0xC6D9...df11`), SessionSettlement (`0xF32a...E959`), SlashingOracle (`0x28E5...8FeD`), Treasury (`0xaE76...619f`)
- [x] **Tauri client** — Rust backend (6 commands, circuit scoring, wallet, receipts) + React frontend (dark-themed: ConnectToggle, CircuitMap, NodeBrowser, SessionCost, GasMonitor, Settings)
- [x] **On-chain integration** — Node registers via `--register` with 0.1 ETH stake, real heartbeats via alloy. Client reads live nodes from registry, opens/settles sessions on SessionSettlement
- [x] **TUN device** — Cross-platform TUN via tun-rs for exit-mode IP forwarding. Decapsulated packets injected into OS network stack. Graceful degradation without admin privileges

**Success metric:** Browse the internet through a single ShieldNode relay and pay for it on L1 testnet.

---

## Phase 2: Multi-Hop + Onion Routing -- COMPLETE

Privacy through layered encryption — no single node sees both source and destination.

### Completed
- [x] **Sphinx packet format** — `create()` and `peel_layer()` for building and processing onion-encrypted packets
- [x] **Circuit management** — `CircuitManager` with create/teardown lifecycle, pure `process_relay_packet()` function designed for future ZK provability
- [x] **Noise NK handshake** — Session key establishment between any two nodes using X25519 DH
- [x] **3-hop circuit construction** — Client selects entry/relay/exit via scoring, generates ephemeral X25519 keypairs per hop, derives session keys via HKDF-SHA256. CircuitState stored backend-only (keys never exposed to frontend)
- [x] **Relay forwarding protocol** — Dedicated UDP relay listener (port 51821) on each node. Framing: `[8-byte session_id][SphinxPacket]`. Peels one Sphinx layer, forwards to next hop or writes to TUN (exit). SphinxPacket wire serialization (to_bytes/from_bytes)
- [x] **Circuit visualization** — CircuitMap component shows actual entry/relay/exit node IDs when connected, placeholder path when disconnected. `get_circuit` Tauri command returns sanitized CircuitInfo
- [x] **Live multi-hop traffic** — Client sends Sphinx-wrapped packets through 3-node relay chain end-to-end
- [x] **EIP-712 bandwidth receipt co-signing** — Client signs receipt digest, sends RECEIPT_SIGN (0x03) control message to exit node, node co-signs and returns 65-byte signature. Dual-signed receipt ABI-encoded for on-chain settlement

- [x] **Circuit auto-rotation** — Background task rebuilds circuit through different nodes on a configurable interval (default 10 min). SESSION_TEARDOWN sent to old hops, new circuit selected with reuse penalty, sessions registered on new nodes. CancellationToken lifecycle, rotation count shown in UI

**Success metric:** Traffic routes through 3 independent nodes; no single node can see both source and destination.

---

## Phase 3: Staking + Slashing -- COMPLETE

Cryptoeconomic security — honest behavior earns ETH, misbehavior costs ETH.

### Completed
- [x] **Minimum stake** — 0.1 ETH enforced in NodeRegistry
- [x] **Slashing oracle** — Accepts evidence, executes slashes with 24-hour grace period
- [x] **Unstaking cooldown** — 7-day waiting period prevents stake-and-run attacks
- [x] **Progressive slashing** — 10% first offense, 25% second, 100% + permanent ban on third

- [x] **Client node scoring** — Weighted algorithm (30% uptime, 25% stake via log scale, 25% price inverse, 20% slash penalty) implemented in both Rust backend and TypeScript frontend

- [x] **Stake-weighted selection** — Weighted random sampling where selection probability is proportional to score. Stake is the dominant factor via sqrt scaling (1 ETH → score 10, 0.1 ETH → score 3.16), making staking a revenue accelerator. Frontend scoring updated to match

- [x] **Slashing evidence verification** — On-chain cryptographic verification for all three slash reasons. BandwidthFraud: verifies two conflicting EIP-712 dual-signed receipts (same session, different byte counts, same signers, node signer matches accused). ProvableLogging/SelectiveDenial: verifies challenger-signed EIP-712 attestation. 19 new tests in SlashingOracle.t.sol (38 total across all contracts)

### Design Note: Uptime Is Not Slashable

Uptime failures are ambiguous — power outages, ISP issues, and hardware failures are not malicious. Slashing is reserved for provably malicious behavior with cryptographic evidence (logging, censorship, bandwidth fraud). Unreliable nodes are punished economically through market mechanisms: poor uptime → worse score → fewer sessions → less revenue. The heartbeat system (miss 3 consecutive → inactive) and session completion scoring (Phase 4) handle this without stake destruction. This distinction matters: slashing is punitive (for malice), scoring deprioritization is corrective (for unreliability). Mixing them would discourage honest operators from running nodes.

**Success metric:** A slashed node loses stake on Sepolia and is deprioritized by clients.

---

## Phase 4: Economic Hardening + ZK Settlement Privacy `← next`

Make the economics self-sustaining and add privacy to on-chain settlements.

### Completed
- [x] **Market-driven pricing** — Nodes set their own price-per-byte in the registry (`updatePricePerByte`)
- [x] **Treasury** — Receives 50% of slashed stake

### Remaining
- [x] Client displays estimated session cost before connection
- [x] **Gas price monitoring** — GasMonitor component with color-coded Gwei display (green < 1, yellow 1-5, red > 5), polls every 30s, configurable gas ceiling in Settings
- [x] Stress test: 120 concurrent sessions opened and settled — open avg 155K gas, settle avg 106K gas, force-settle avg 133K gas, all within budget. Payment distribution verified at scale
- [x] **Hybrid PQ key exchange** — Upgrade circuit handshake from X25519-only to X25519 + ML-KEM-768 (Kyber). Session keys derived from both key exchanges via HKDF, so security is the stronger of the two. X25519 alone is vulnerable to Shor's algorithm; a "harvest now, decrypt later" adversary recording handshakes today could retroactively reveal circuit routes once quantum hardware exists. ML-KEM adds ~1 KB to the handshake per hop (~3 KB total for a 3-hop circuit) — negligible for a once-per-session operation. Uses `ml-kem` crate (RustCrypto, FIPS 203). This is the single most important PQ item because it protects the confidentiality of circuit routing, which is ShieldNode's core privacy guarantee
- [x] **Crypto trait abstractions** — Refactor `crypto/` module to use trait-based interfaces: `KeyExchange` trait (impl for X25519, ML-KEM, Hybrid), `Signer` trait (impl for ECDSA, ML-DSA), `SymmetricCipher` trait (impl for ChaCha20-Poly1305). This enables swapping primitives without touching tunnel or circuit logic. Prep for Ethereum's own PQ migration (L1 protocol upgrades targeted for 2029 per EF roadmap)
- [x] Design ZK bandwidth receipt circuit (circom + Groth16): dual ECDSA verification, payment split, Poseidon commitments, Merkle registry proof. ~3.2M constraints estimated. Full circuit, build scripts, and design doc in `circuits/`
- [x] Implement `ZKSettlement.sol` verifier contract alongside `SessionSettlement.sol` — deposit → ZK proof → payment distribution. 11 tests. Mock verifier for testing; real Groth16Verifier auto-generated by snarkjs setup
- [x] Client-side proof generation for private settlement — Rust module (`zk_prove.rs`) using ark-circom + ark-groth16 for native Groth16 proving. Loads compiled circuit (R1CS + WASM) and zkey, generates proof formatted for ZKSettlement.sol. circom 2.2.3 + snarkjs 0.7.6 toolchain installed, circuit dependencies cloned

### Anti-Griefing: Drop-After-Payment Protection

- [x] **Circuit health monitor** — Background task in the client that tracks per-circuit throughput and latency in real time. If throughput drops below a configurable minimum (e.g., 10 KB/s sustained for 15s) or latency exceeds a threshold (e.g., 2000ms RTT for 30s), automatically tear down the circuit and rebuild through different nodes. The bad node earns zero revenue (receipt shows near-zero bytes). At ~$0.04 gas per `openSession()`, rebuilding is cheap. Implement in `client/src-tauri/src/circuit.rs` as a tokio task that runs alongside the tunnel, sampling metrics from the bandwidth counter every 5 seconds.

- [x] **Session completion scoring** — Extend the node scoring algorithm to factor in session completion rate. Derive this from on-chain settlement events: for each node, calculate `(sessions settled with >1MB transferred) / (total sessions settled)`. Nodes where clients consistently abandon circuits (settling near-zero bytes) get deprioritized. This requires no new contracts — just read existing `SessionSettled` events from `SessionSettlement.sol`. Add a `completionRate` field to the scoring model in both Rust backend (`scoring` module) and TypeScript frontend (`scoring.ts`). Weight: 15% of total score. Rebalance existing weights: uptime 25% (was 30%), stake 25%, price 20% (was 25%), slash penalty 15% (was 20%), completion rate 15% (new).

- [x] **Minimum bandwidth flag** — Add a `lowBandwidthCount` field to the client's local node reputation cache. If a session through a given node settles with <1MB transferred relative to >5 minutes duration, increment the counter. Nodes with 3+ flags in the last 24 hours get a score penalty equivalent to a minor slash. This is client-side only (no contract changes) and acts as a fast local signal before on-chain completion rate data accumulates.

### What ZK Settlement Achieves
**Before ZK:** The chain sees wallet `0xABC` opened session #47 with nodes `[0x1, 0x2, 0x3]`, transferred 1.2 GB, settled at block 19847362.

**After ZK:** A valid proof was submitted, 0.0024 ETH was distributed to three commitments, remainder refunded to a shielded address. No session ID, no node identities, no timing correlation.

### Post-Quantum Note
The ZK receipt circuit should be designed to verify ML-DSA (Dilithium) signatures alongside ECDSA from the start. ML-DSA signatures are ~2.4 KB (40x larger than ECDSA), which would be expensive to verify on-chain directly, but inside a ZK circuit the signature size doesn't affect on-chain gas — only proof verification cost matters. This means ZK settlement is the natural home for PQ signatures: prove you have a valid PQ-signed receipt without posting the large signature on-chain.

**Success metric:** The economic loop works end-to-end. At least one session settles via ZK proof on testnet. Hybrid PQ handshake operational across all circuit hops. Circuit health monitor detects and recovers from a simulated node drop within 20 seconds on testnet.

---

## Phase 5: Mainnet Launch

Security audits, hardening, and public deployment.

- [ ] Security audit of all contracts (prioritize SessionSettlement, ZKSettlement, and NodeRegistry — these hold funds)
- [ ] Security audit of node software (prioritize crypto operations and memory handling)
- [ ] Audit of ZK circuit correctness — proof must not allow over-claiming or underpaying
- [ ] **PQ handshake audit** — Independent review of the hybrid X25519 + ML-KEM key exchange implementation, session key derivation, and that the hybrid combiner correctly ensures security under both classical and quantum assumptions
- [ ] **PQ signature verification in ZK circuit** — Confirm ML-DSA signature verification inside the ZK receipt circuit is sound and matches the on-chain verifier's acceptance criteria
- [x] Kill switch, auto-rotate circuits, and circuit pinning fully functional in client
- [ ] Challenge-response protocol v1 (trusted challenger set)
- [ ] Deploy immutable contracts to Ethereum mainnet (no proxy)
- [ ] ZK settlement as default for privacy-conscious users, plaintext settlement as fallback
- [ ] Documentation site: how to run a node, use the client, verify the contracts
- [ ] **Operator security guide** — Recommend smart contract wallets (Safe) with PQ-upgradeable signature verification for node staking keys, rather than raw EOAs. Document Ethereum's PQ migration path (account abstraction) so operators are prepared
- [ ] **Anti-griefing testing** — Adversarial test suite: simulate nodes that accept circuits then drop after N seconds, nodes that throttle bandwidth to near-zero, and nodes that selectively drop traffic to specific destinations. Verify the circuit health monitor rebuilds within 20s, completion scoring deprioritizes bad nodes within 3 sessions, and the low-bandwidth flag triggers within 24 hours. Run as part of CI on every PR touching client circuit or scoring code.
- [ ] At least 10 independently operated nodes live before public client release

**Success metric:** Real users browsing through ShieldNode on Ethereum mainnet, with ZK-private settlement and post-quantum circuit handshakes.

---

## Phase 6: Decentralization + Growth

Remove all remaining centralization points and scale the network.

- [ ] **Decentralize challenge-response** — Challenge bonds replace the trusted challenger multisig; anyone can challenge by posting a bond
- [ ] **Mobile client** — iOS and Android (defer until desktop is stable)
- [ ] **Operator onboarding** — One-click setup: `docker run shieldnode/relay`, local dashboard for earnings/health
- [ ] **Preconfirmations (EIP-7917)** — Sub-slot session opening (<1s tunnel establishment vs. current 12s block time)
- [ ] **ZK node eligibility proofs** — Commitment-based registry where nodes prove they meet selection criteria (stake, uptime, no slashes) without revealing which node they are. Hardens against enumeration attacks by state actors
- [ ] **ZK no-log compliance proofs** — Nodes periodically prove their operational state contains no connection metadata. Most useful against honest-but-curious operators
- [ ] **ZK proof of honest relay (research)** — Evaluate whether ZK-VM systems (RISC Zero, SP1, Valida) are mature enough to prove correct packet forwarding. Depends on 100x proving cost reduction. Node relay logic is already structured as a pure function to enable this
- [ ] **PQ Sphinx packet format** — Upgrade the Sphinx onion routing layer itself to use PQ primitives for the per-hop DH operations. The hybrid handshake (Phase 4) protects circuit *construction*, but Sphinx's internal layered encryption also uses X25519. Full PQ Sphinx replaces all elliptic curve operations in the packet format with PQ equivalents. Research dependency: efficient PQ group operations suitable for Sphinx's SURB (Single Use Reply Block) construction. Monitor Nym's PQ Sphinx research for prior art
- [ ] **ML-DSA receipt signing as default** — Once Ethereum's execution layer supports PQ signature verification via precompiles (EF roadmap fork J*), switch bandwidth receipt signing from ECDSA to ML-DSA as the default, with ECDSA as fallback. The ZK circuit already supports both (added Phase 4). The plaintext settlement path will need a new `PQSessionSettlement.sol` that verifies ML-DSA on-chain via the precompile
- [ ] **Track EF PQ key registry (fork I*)** — When Ethereum adds a PQ key registry at the consensus layer, evaluate whether ShieldNode's NodeRegistry should mirror this pattern — allowing node operators to register PQ public keys that are anchored in the same infrastructure validators use

---

## Post-Quantum Strategy

ShieldNode's approach to quantum resistance follows the EF's principle of **cryptographic agility** — the ability to upgrade primitives without destabilizing the system.

### Threat Model
Quantum computing threatens public-key cryptography (ECDSA, X25519, BLS) via Shor's algorithm. Symmetric crypto (ChaCha20-Poly1305, SHA-256, HKDF) retains adequate security post-quantum (Grover's algorithm provides only quadratic speedup — 256-bit keys retain 128-bit security).

For ShieldNode specifically, the threats in priority order are:

1. **Circuit handshake confidentiality (highest priority)** — "Harvest now, decrypt later." An adversary recording X25519 handshakes today can retroactively reveal circuit routes once quantum hardware exists. This breaks ShieldNode's core privacy guarantee. **Mitigated in Phase 4** via hybrid X25519 + ML-KEM-768
2. **Bandwidth receipt forgery** — An adversary who cracks ECDSA keys could forge receipts to steal session deposits or frame nodes. **Mitigated in Phase 4** via ML-DSA signatures inside ZK circuits
3. **Node operator key theft** — Deriving private keys from on-chain public keys to drain stakes or impersonate nodes. **Mitigated in Phase 5** via operator security guide (smart contract wallets with PQ-upgradeable verification)
4. **Sphinx packet decryption** — Retroactive decryption of onion layers to reconstruct traffic routes. Lower priority than handshake because packets are ephemeral, but still a concern for adversaries with long-term traffic captures. **Mitigated in Phase 6** via PQ Sphinx

### What's Already Quantum-Safe
- **ChaCha20-Poly1305** symmetric encryption (tunnel data, onion layer payloads)
- **HKDF-SHA256** key derivation
- **SHA-256 / Keccak-256** hashing (contract storage, Merkle trees)

### What Needs Upgrading
| Component | Current | PQ Upgrade | Phase |
|-----------|---------|------------|-------|
| Circuit handshake | X25519 | Hybrid X25519 + ML-KEM-768 | 4 |
| Receipt signatures | ECDSA (secp256k1) | ML-DSA-65 (inside ZK circuit) | 4 |
| Operator staking keys | EOA (secp256k1) | Smart contract wallet + PQ sig verification | 5 |
| Sphinx DH operations | X25519 | PQ group operations (research) | 6 |
| On-chain receipt verification (plaintext path) | ECDSA ecrecover | ML-DSA via EF precompile (fork J*) | 6 |

### Dependencies on Ethereum's PQ Roadmap
ShieldNode benefits from Ethereum's own PQ transition but does not block on it:
- **Fork I* (PQ key registry)**: useful for node operator key management but not required — ShieldNode's registry is independent
- **Fork J* (PQ sig precompiles)**: enables on-chain ML-DSA verification for the plaintext settlement path. Until then, PQ signatures are verified inside ZK circuits only (no on-chain gas penalty)
- **Fork L* (PQ attestations + leanVM)**: no direct impact on ShieldNode, but strengthens the L1 consensus layer we depend on
- **Full PQ consensus (longer term)**: secures the base layer ShieldNode settles on. Not something we build, but something we benefit from

### Implementation Notes
- Use `pqcrypto` or `ml-kem` crate for ML-KEM-768 in Rust. Both wrap the reference C implementation with Rust bindings. Verify the crate is NIST FIPS 203 compliant
- Use `pqcrypto-dilithium` or `ml-dsa` crate for ML-DSA-65 signatures. NIST FIPS 204 compliant
- Hybrid key exchange combiner: `session_key = HKDF-SHA256(X25519_shared || ML-KEM_shared, salt=session_id, info="shieldnode-hybrid-kex")`. Both shared secrets contribute; compromise of either alone does not break the session key
- ML-KEM-768 key sizes: public key 1,184 bytes, ciphertext 1,088 bytes. Per-hop handshake adds ~2.3 KB. For a 3-hop circuit: ~6.9 KB total overhead during construction. Negligible given this happens once per session
- ML-DSA-65 signature size: 3,293 bytes. Too large for direct on-chain verification at reasonable gas cost, but inside a ZK circuit the signature size does not affect on-chain gas — only the proof verification cost (~200K–300K gas) matters. This is why ZK settlement is the natural home for PQ signatures
- The `Signer` trait abstraction (Phase 4) must support both deterministic (ECDSA) and randomized (ML-DSA) signing. ML-DSA requires access to a CSPRNG during signing — ensure the trait interface accommodates this

---

## Bootstrapping Strategy

The cold-start problem: users need nodes for coverage, nodes need users for revenue.

1. **Foundation seed nodes** — 5-10 nodes across major regions (US East/West, EU West/Central, Asia) operated by the core team before public client release
2. **Early operator incentives** — `BootstrapRewards` contract: 0.05 ETH bonus per node for the first 50 operators maintaining >95% uptime for 30 days. Total cost: ~2.5 ETH
3. **Geographic focus** — Start in Europe (strong privacy culture, dense infrastructure), expand to North America in Phase 4, Asia in Phase 5+
4. **Exit node incentives** — 2x revenue share (50% vs 25%), optional higher stake tier, jurisdiction-by-jurisdiction legal guide, relay-only as default (exit is opt-in)

---

## Non-Goals (Scope Boundaries)

These are explicitly out of scope to maintain focus:

- **No L2 deployment** — The entire point is L1 nativity
- **No token** — ETH only for staking, sessions, and slashing
- **No free tier** — Pay-per-use from day one
- **No browser extension** — Standalone desktop app first
- **No centralized RPC infrastructure** — Encourage self-hosting
- **No upgradeable contracts** — Unless absolutely necessary, with 30-day timelock minimum
