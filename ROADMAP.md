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

### Anti-Collusion: Circuit Diversity & Sybil Resistance

- [x] **Circuit diversity constraints** — Enforce in the client's circuit builder that entry, relay, and exit nodes must be on different IP subnets (/24), different autonomous systems (ASN), and different geographic regions. Query node metadata from the registry (extend `NodeRegistry` to store an optional `asnId` and `regionCode` per node, set at registration via `register()` params). If metadata is unavailable, fall back to IP-based heuristic (first two octets differ). This is the single biggest practical improvement against collusion — it eliminates the lazy attack where one operator runs all three hops on the same infrastructure. Implement in `client/src-tauri/src/circuit.rs` in the node selection path, as a hard constraint applied before scoring.

- [x] **Same-operator exclusion** — If multiple nodes share the same registrant address on-chain, the client must treat them as a single entity and never place two in the same circuit. Read `NodeRegistered` events to build an operator→nodes mapping. This doesn't catch attackers using different wallets, but it prevents accidental self-correlation by honest multi-node operators and eliminates the trivial Sybil case.

- [x] **Stake concentration heuristics** — Client-side analysis that flags clusters of nodes with suspicious registration patterns: sequential funding transactions from related wallets (funded by the same source within N blocks), identical stake amounts registered within a short time window, or correlated uptime patterns (all go offline/online together). Flagged clusters get a scoring penalty. This is probabilistic, not provable — it runs client-side where heuristic reasoning is appropriate, not on-chain where cryptographic proof would be required. Store flags in the client's local node reputation cache.

- [x] **Minimum network size guard** — The client should warn users (or refuse to connect in strict mode) if the active node count is below a safety threshold (e.g., <20 nodes). With very few nodes, the probability of an attacker controlling entry+exit on the same circuit is too high regardless of other mitigations. Display the current network size and estimated collusion risk in the UI.

### Traffic Analysis Resistance: Making Captured Data Useless

- [x] **Fixed-size packet normalization** — Enforce a uniform outer packet size for all tunnel traffic (e.g., 1280 bytes, matching common MTU). Pad undersized packets with random bytes, fragment oversized packets into multiple fixed-size chunks. Sphinx already normalizes the inner onion layer, but the WireGuard encapsulation can leak size information at the wire level. Extend normalization to the outer UDP packet so every packet on the network is identical in size. This eliminates packet-size fingerprinting — an observer capturing traffic sees a stream of identically-sized ciphertext blobs. Implement in `node/src/tunnel/wireguard.rs` at the send/receive boundary. Fragmentation adds a reassembly buffer on the receiving side — use a sequence number in the fixed-size header to reconstruct original packets. Performance impact: minimal for packets near MTU, some overhead for very small packets (padding waste) and very large packets (fragmentation latency)

### What ZK Settlement Achieves
**Before ZK:** The chain sees wallet `0xABC` opened session #47 with nodes `[0x1, 0x2, 0x3]`, transferred 1.2 GB, settled at block 19847362.

**After ZK:** A valid proof was submitted, 0.0024 ETH was distributed to three commitments, remainder refunded to a shielded address. No session ID, no node identities, no timing correlation.

### Post-Quantum Note
The ZK receipt circuit should be designed to verify ML-DSA (Dilithium) signatures alongside ECDSA from the start. ML-DSA signatures are ~2.4 KB (40x larger than ECDSA), which would be expensive to verify on-chain directly, but inside a ZK circuit the signature size doesn't affect on-chain gas — only proof verification cost matters. This means ZK settlement is the natural home for PQ signatures: prove you have a valid PQ-signed receipt without posting the large signature on-chain.

**Success metric:** The economic loop works end-to-end. At least one session settles via ZK proof on testnet. Hybrid PQ handshake operational across all circuit hops. Circuit health monitor detects and recovers from a simulated node drop within 20 seconds on testnet. Circuit builder rejects node combinations on the same ASN or IP subnet. All tunnel traffic normalized to fixed-size packets — no packet size variation observable on the wire.

---

## Phase 5: Mainnet Launch

Security audits, hardening, and public deployment.

- [ ] Security audit of all contracts (prioritize SessionSettlement, ZKSettlement, and NodeRegistry — these hold funds)
- [ ] Security audit of node software (prioritize crypto operations and memory handling)
- [ ] Audit of ZK circuit correctness — proof must not allow over-claiming or underpaying
- [ ] **PQ handshake audit** — Independent review of the hybrid X25519 + ML-KEM key exchange implementation, session key derivation, and that the hybrid combiner correctly ensures security under both classical and quantum assumptions
- [ ] **PQ signature verification in ZK circuit** — Confirm ML-DSA signature verification inside the ZK receipt circuit is sound and matches the on-chain verifier's acceptance criteria
- [x] Kill switch, auto-rotate circuits, and circuit pinning fully functional in client
- [x] Challenge-response protocol v1 (trusted challenger set)
- [ ] Deploy immutable contracts to Ethereum mainnet (no proxy)
- [ ] ZK settlement as default for privacy-conscious users, plaintext settlement as fallback
- [ ] Documentation site: how to run a node, use the client, verify the contracts
- [ ] **Operator security guide** — Recommend smart contract wallets (Safe) with PQ-upgradeable signature verification for node staking keys, rather than raw EOAs. Document Ethereum's PQ migration path (account abstraction) so operators are prepared
- [x] **Anti-griefing testing** — Adversarial test suite: simulate nodes that accept circuits then drop after N seconds, nodes that throttle bandwidth to near-zero, and nodes that selectively drop traffic to specific destinations. Verify the circuit health monitor rebuilds within 20s, completion scoring deprioritizes bad nodes within 3 sessions, and the low-bandwidth flag triggers within 24 hours. Run as part of CI on every PR touching client circuit or scoring code.
- [ ] At least 10 independently operated nodes live before public client release

### Anti-Logging: Hardware & Environmental Hardening

- [x] **TEE remote attestation (AMD SEV-SNP)** — Require (or strongly incentivize via scoring bonus) node operators to run the relay binary inside an AMD SEV-SNP enclave (or Intel SGX/TDX). The enclave produces a remote attestation: a hardware-signed certificate proving "this specific binary is running inside a genuine enclave, and the host OS cannot read its memory." Even if the operator runs tcpdump, installs a rootkit, or modifies the kernel, they cannot access plaintext traffic inside the enclave. Implementation: at registration time, the node submits its attestation report. The client verifies the attestation before circuit selection — checking (1) valid hardware signature from AMD/Intel, (2) binary hash matches the reproducible build of the audited open-source ShieldNode relay. Nodes with valid TEE attestation get a significant scoring bonus (e.g., 2x weight on the trust component). Entry node position (most sensitive — sees client IP) should prefer TEE-attested nodes. Trust assumption shifts from "trust the node operator" to "trust AMD/Intel's hardware security" — a dramatically better model. Available today on commodity cloud: AWS Nitro Enclaves, Azure Confidential VMs, GCP Confidential Computing. Also available on bare metal with SEV-SNP capable CPUs

- [x] **Reproducible builds pipeline** — Set up deterministic, reproducible builds for the relay node binary so anyone can compile from source and get the exact same binary hash. This is required for TEE attestation to be meaningful — the attestation proves "this code is running in an enclave" but the client needs to verify "and this code is the honest, audited binary." Build pipeline: pinned Rust toolchain version, locked dependency tree via `Cargo.lock`, Docker-based build environment with fixed base image hash, CI job that produces the reproducible binary and publishes its hash. The published hash is what clients check against in the TEE attestation report

- [x] **Traffic volume analysis** — Entry and exit nodes in a circuit measure total bytes the relay node receives and sends. If the relay is forwarding honestly, bytes_in ≈ bytes_out (minus Sphinx layer overhead). If the relay is exfiltrating captured data to a logging server, bytes_out > bytes_in by a measurable margin. Implement as a check during session settlement: if the exit node's observed bytes from the relay diverge from the entry node's sent bytes by more than a threshold (e.g., >15% accounting for protocol overhead), flag the relay node. This is a weak signal individually but additive with other layers. Catches the obvious case of real-time log exfiltration. Does not catch sophisticated exfiltration (steganography, batched upload during off-hours, covert timing channels)

### Traffic Analysis Resistance: Forward Secrecy & Cover Traffic

- [x] **Micro-ratcheting session keys** — Rekey the symmetric session key every 30 seconds or every 10 MB of data (whichever comes first), using a Double Ratchet-inspired mechanism. Each ratchet step derives a new ChaCha20-Poly1305 key from the current key + a fresh ephemeral DH exchange (hybrid X25519 + ML-KEM, matching the circuit handshake). Previous keys are immediately zeroized. If an attacker captures ciphertext and somehow later obtains one session key (hardware fault, future cryptanalytic break), they get at most 30 seconds of traffic — all previous and subsequent ratchet windows remain secure. This is the same principle as Signal's Double Ratchet but applied to tunnel traffic rather than messages. Implement in `node/src/crypto/` as a `Ratchet` struct that wraps the `SymmetricCipher` trait. Both client and relay must synchronize ratchet state — use an in-band ratchet-step message (a single fixed-size Sphinx packet with a control flag) to signal the new key epoch. Performance impact: one additional DH + HKDF computation every 30 seconds — negligible (microseconds on modern hardware)

- [x] **Adaptive cover traffic** — Client generates cover traffic during low-activity periods to maintain a baseline packet rate that prevents timing-based activity detection. When real traffic is flowing, cover traffic is suppressed (real traffic already fills the rate). When real traffic drops below a threshold (e.g., <10 packets/second), cover traffic fills the gap with dummy Sphinx packets indistinguishable from real traffic at the relay level. The cover rate is configurable: "off" (no cover traffic — lowest bandwidth cost), "low" (maintain 10 pps baseline — moderate protection), "high" (maintain 50 pps baseline — strong protection, higher bandwidth). Default: "low". Cover packets are generated by the client, routed through the full 3-hop circuit, and silently dropped by the exit node (which recognizes them via a flag in the Sphinx header that only the exit can read after peeling all layers). An operator logging all traffic through their relay cannot distinguish cover from real — both are fixed-size, encrypted, and follow the same routing path. Bandwidth cost at "low" setting: ~10 pps × 1280 bytes = ~12.8 KB/s = ~1.1 GB/day. At "high": ~64 KB/s = ~5.5 GB/day. Users on metered connections should use "off" or "low". Implement in `client/src-tauri/src/tunnel.rs` as a background tokio task that monitors outbound packet rate and injects cover packets when needed

- [x] **Inter-node link padding** — Constant-rate encrypted padding between adjacent relay nodes, independent of user traffic. Each pair of connected nodes maintains a baseline packet rate between them (e.g., 50 pps) regardless of how many sessions are active. When real session traffic is below the baseline, padding fills the gap. When real traffic exceeds the baseline, the rate scales up (but all links scale up together so the increase doesn't correlate to a specific session). This prevents a network-level observer from determining which links carry real traffic and which are idle. More expensive than client-side cover traffic (every link, not just active circuits) but provides stronger protection against global passive adversaries. Implement in `node/src/network/relay.rs` as a link-level padding manager. Bandwidth cost: ~50 pps × 1280 bytes × number of peer links. For a node with 10 peers: ~640 KB/s = ~55 GB/day. This is meaningful — only enable for nodes with high-bandwidth connections. Make it opt-in via node config with clear documentation of bandwidth implications

**Success metric:** Real users browsing through ShieldNode on Ethereum mainnet, with ZK-private settlement and post-quantum circuit handshakes. At least 3 TEE-attested nodes operational on mainnet with client-verified attestation.

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
- [ ] **Community watchlists** — Opt-in, non-binding public lists of suspected colluding node clusters that clients can subscribe to. Similar to Tor's consensus flagging but decentralized and advisory rather than authoritative. Maintained by community contributors, signed with known identities. Client can enable/disable in Settings. Does not interact with the slashing oracle — probabilistic evidence is appropriate for client-side avoidance but not for on-chain stake destruction
- [ ] **Research: decentralized correlation detection** — Investigate whether clients can collaboratively report circuit performance anomalies (without leaking their own traffic data) to build a decentralized view of suspicious node behavior. ZK proofs could allow clients to prove "I experienced correlated failures through nodes X and Y" without revealing their identity or traffic. This is an open research problem — document findings in `docs/THREAT-MODEL.md` regardless of whether a practical solution emerges
- [ ] **ZK-VM proof of correct forwarding (replaces trusted challengers for selective denial)** — Instead of trusted challenger attestations, nodes prove they correctly forwarded packets using a ZK-VM (RISC Zero or SP1). How it works: the node commits to a Merkle root of all packets received during a time window (e.g., 10 minutes). A challenger picks N random packets from the commitment. The node produces a ZK-VM proof that it executed `process_relay_packet()` on each selected packet and produced the correct output (next-hop forwarded packet). If the node can't produce the proof, it either didn't forward the packet or forwarded it incorrectly — that's provable, not attestation-based. Random sampling catches a node dropping X% of traffic with probability scaling with sample size (100 samples catches 5% drop rate with near certainty). This eliminates the trusted challenger for selective denial entirely. Dependency: ZK-VM proving costs must be benchmarked — current RISC Zero performance is on the edge of feasibility for simple computations like the relay function. The `process_relay_packet()` function is already a pure function with no side effects specifically to enable this
- [ ] **ZK-VM execution trace proof for logging detection (partial replacement of trusted challengers)** — Extends the ZK-VM forwarding proof to cover the full execution trace, not just input/output. The ZK-VM proves that during execution of the relay function, the only output was the forwarded packet — no side-channel writes, no additional memory allocations, no network calls other than the forward. This proves the *node software itself* didn't log. Documented limitation: this cannot prove the operator isn't running a separate process (tcpdump, modified kernel module, packet sniffer) capturing traffic outside the node binary. The ZK-VM proves what happened inside its sandbox, not what's happening at the OS level. Still a meaningful improvement: eliminates the scenario where operators run modified node software (the majority of realistic logging threats), and is stronger than what any other decentralized system currently offers. State-level adversaries compromising the host OS remain outside the proof's scope — document this transparently in `docs/THREAT-MODEL.md`
- [ ] **Dummy commitment Merkle tree (bootstrapping network size privacy)** — Deploy the initial NodeRegistry with a fixed-size Merkle tree (e.g., 512 slots). At launch with few real nodes, remaining slots contain dummy commitments indistinguishable from real ones. As real nodes register, they replace dummy slots. Requires simulated heartbeats for dummy slots at realistic intervals (~$0.02/tx, ~$32/day for 400 dummies at 4x/day — manageable during grant-funded bootstrapping, decreases as real nodes replace dummies). Dummy salt generation must use a VDF or public commit-reveal scheme so even the deployer can't later prove which commitments were dummies. Once real node count crosses a threshold (e.g., 256), fork to a new NodeRegistry contract without dummy logic and migrate real stakes. This migration uses the same immutable-contract upgrade pattern already documented. Design the fork trigger as either a `realNodeCount` threshold or a time-based sunset (e.g., 12 months post-launch). Note: even with dummies, an attacker can observe total registration events and stake locked in the contract — the dummies hide the *real* node count within the fixed tree size but don't hide the tree size itself. At 512 slots with 20 real nodes, the attacker knows "somewhere between 1 and 512 nodes" which is far better than knowing "exactly 20"
- [ ] **Ephemeral compute enforcement** — Node relay software runs in ephemeral containers destroyed and recreated on a fixed schedule (e.g., every hour). The environment has no persistent storage — read-only filesystem, no volume mounts, memory wiped on teardown. The node produces an attestation (TEE-backed or ZK-VM-backed) that it's running in an environment matching a specific configuration hash (no writable storage, no extra network interfaces beyond tunnel endpoints). Combined with ZK-VM execution trace proof: the software didn't log, and the environment couldn't persist logs. Does not prevent real-time streaming of captured packets to an external server during the container's lifetime, but prevents retrospective log accumulation. The traffic volume analysis (Phase 5) covers the real-time exfiltration gap
- [ ] **Research: secure coprocessor for relay function** — Investigate whether the relay forwarding function could run on dedicated hardware (secure element, HSM-like device) with no general-purpose OS, no filesystem, no logging capability by design. Similar to a hardware wallet but for packet forwarding — physically no mechanism to extract packet data because the hardware lacks storage or I/O paths that would allow it. This is the strongest possible anti-logging guarantee but requires custom hardware. Not practical for general operators, but could be offered as a premium "verified hardware node" tier. Study Oasis Network's Sapphire runtime and similar confidential computing hardware for prior art. Document findings in `docs/THREAT-MODEL.md`
- [ ] **Optional packet batching and reordering** — Relay nodes collect packets for a configurable time window (default 50ms), shuffle the order within the batch, and forward as a group. This breaks timing correlation between input and output packets at each hop — an observer cannot match an incoming packet to an outgoing packet based on arrival/departure timing because the ordering is randomized within each batch window. Adds 25-75ms latency (half the batch window on average). Opt-in because the latency cost is significant for interactive applications (gaming, video calls). Users who prioritize privacy over latency enable it in client Settings — the client negotiates batch preference with each relay during circuit construction via a Sphinx header flag. Users who need low latency leave it off and rely on fixed-size normalization + cover traffic for protection. The batch window is configurable per-node (operators set their preferred window in config.toml). Implement in `node/src/network/relay.rs` as a per-hop batch buffer that flushes every N milliseconds
- [ ] **Research: traffic morphing** — Investigate whether client-side traffic shaping can make ShieldNode traffic patterns resemble a different traffic type (e.g., shape VPN traffic to look like video streaming or cloud backup). This is an active research area with mixed results — academic work shows it raises the cost of fingerprinting but rarely eliminates it. Document findings in `docs/THREAT-MODEL.md`. Relevant prior art: BuFLO, CS-BuFLO, Tamaraw, FRONT defenses against website fingerprinting

---

## Anti-Collusion Design & Known Limitations

The hardest unsolved problem in decentralized relay networks is preventing a single entity from controlling multiple nodes in the same circuit and correlating entry/exit traffic. Financial stake makes Sybil attacks expensive but not impossible for well-funded adversaries. Tor addresses this with centralized directory authorities that act on probabilistic signals — ShieldNode cannot do this because on-chain slashing requires cryptographic proof, not statistical suspicion.

### What ShieldNode does

**Economic deterrence**: running N colluding nodes at competitive stake (0.5-1 ETH each) costs $1K-2K per node. Controlling enough of the network to reliably land both entry and exit positions requires significant capital at risk of slashing.

**Client-controlled circuit selection**: the client independently selects all three hops. An attacker controlling K of N total nodes has roughly (K/N)² probability of controlling both entry and exit on any given circuit. At 10/100 nodes: ~1%. At 10/500: ~0.04%. Network growth is the strongest defense.

**Circuit diversity constraints (Phase 4)**: entry, relay, and exit must be on different ASNs, IP subnets, and geographic regions. Eliminates the attack variant where one operator uses the same or adjacent infrastructure for multiple nodes.

**Same-operator exclusion (Phase 4)**: nodes sharing an on-chain registrant are never placed in the same circuit.

**Stake concentration heuristics (Phase 4)**: client-side probabilistic detection of suspicious node clusters based on registration patterns, funding sources, and correlated behavior.

**Circuit auto-rotation (Phase 2, complete)**: circuits rebuild periodically through different nodes, limiting the window of any single successful correlation attack.

### What ShieldNode does NOT fully solve

**Sophisticated Sybil with diverse infrastructure**: an attacker using different wallets, different hosting providers, different IP ranges, and staggered registration timing is very difficult to detect — either on-chain or client-side. No decentralized system has fully solved this.

**Provable collusion detection**: the gap between what's statistically suspicious and what's cryptographically provable on-chain is fundamental. The slashing oracle cannot act on "these nodes look correlated" — it needs proof of logging, censorship, or fraud. This means collusion that doesn't produce detectable misbehavior (passive traffic correlation) cannot be slashed.

**OS-level surveillance**: ZK-VM proofs (Phase 6) can prove the node software behaved honestly, but cannot prove the operator isn't running a separate capture process outside the node binary. This is a fundamental limitation of software-level proofs — they prove what happened inside the sandbox, not what's happening on the host. TEE attestation (Phase 5) closes this gap by isolating traffic inside a hardware enclave the operator cannot access. Multi-hop architecture provides additional mitigation — compromising one node's host OS is insufficient without also compromising the other two hops.

**Global network view**: without a trusted entity that sees all traffic patterns (like Tor's directory authorities), detecting correlated behavior across the network requires either a decentralized reputation system or collaborative client-side reporting — both are research-level problems. ZK anonymous client reporting (Phase 6 research) is the most promising direction.

### Mitigation roadmap

| Phase | Mitigation | Type |
|-------|-----------|------|
| 2 (done) | Circuit auto-rotation | Limits correlation window |
| 3 (done) | Stake-weighted selection, sqrt scaling | Economic deterrence |
| 4 | Circuit diversity constraints (ASN/subnet/region) | Hard constraint |
| 4 | Same-operator exclusion | Hard constraint |
| 4 | Stake concentration heuristics | Client-side probabilistic |
| 4 | Minimum network size guard | UX safety |
| 5 | TEE remote attestation (SEV-SNP) | Hardware-enforced isolation |
| 5 | Reproducible builds | Completes TEE attestation chain |
| 5 | Traffic volume analysis | Exfiltration detection |
| 5 | Dummy commitment Merkle tree (bootstrapping) | Hides real network size during early growth |
| 6 | ZK node eligibility (commitment-based registry) | Hides node set from enumeration |
| 6 | ZK-VM proof of correct forwarding | Replaces trusted challenger for selective denial |
| 6 | ZK-VM execution trace proof | Partial replacement of trusted challenger for logging |
| 6 | Ephemeral compute enforcement | Prevents log persistence |
| 6 | Community watchlists (opt-in suspicious cluster lists) | Social/probabilistic |
| 6+ | Research: decentralized correlation detection | Open problem |
| 6+ | Research: secure coprocessor hardware | Strongest possible anti-logging |
| Post-threshold | Fork to remove dummy commitments | Cleanup once anonymity set is sufficient |

### Prior art to study

- **Tor**: directory authorities + consensus weight system. Centralized trust model for relay selection. Extensive research on Sybil detection heuristics
- **Nym**: mixnet with Sphinx packets, staking-based reputation. Study their approach to mix node selection, Sybil resistance via staking, and traffic analysis resistance through packet timing obfuscation
- **Oxen/Session**: decentralized onion routing with service node staking. Study their swarm-based node grouping and path selection as an alternative approach to circuit diversity
- **HOPR**: mixing with cover traffic. Probabilistic packet relaying to resist traffic analysis

### Honest assessment

A sufficiently funded state-level adversary operating nodes across diverse infrastructure, using independent wallets and staggered registration, cannot be fully prevented by any known decentralized mechanism. ShieldNode's defenses make this attack expensive and probabilistically unlikely, but not impossible. This is a shared limitation with every decentralized relay network. The strongest long-term defense is network growth — the larger the honest node set, the lower the probability of adversarial circuit capture.

---

## Anti-Logging Architecture

Preventing node operators from logging user traffic is the hardest security guarantee to provide in a decentralized relay network. Cryptography can prove what happened inside a computation but cannot prove what didn't happen on hardware you don't control. ShieldNode addresses this through layered defenses where each layer catches what the others miss.

### Defense layers

| Layer | What it proves | What it misses | Phase |
|-------|---------------|----------------|-------|
| No-log software design | Node binary has no logging mechanism | Operator can modify binary or run separate capture | 1 (done) |
| TEE attestation (SEV-SNP) | Host OS cannot read enclave memory; binary matches audited source | Hardware manufacturer backdoors, side-channel attacks | 5 |
| Reproducible builds | Attested binary is the honest open-source code | Nothing — completes the attestation chain | 5 |
| Traffic volume analysis | Relay isn't sending more data than expected (exfiltration) | Sophisticated covert channels, batched exfiltration | 5 |
| ZK-VM execution trace | Node software didn't log during execution | OS-level capture outside the ZK-VM sandbox | 6 |
| Ephemeral compute | Environment cannot persist logs across restarts | Real-time exfiltration during container lifetime | 6 |
| Secure coprocessor (research) | Hardware physically cannot store or exfiltrate data | Requires custom hardware, impractical for most operators | Research |

### Trust model progression

**Phase 1-4 (current):** Trust the node operator not to log. Enforced by: software design (no logging mechanism), economic incentives (staked ETH at risk), and trusted challenger attestations.

**Phase 5 (TEE):** Trust shifts from node operator to hardware manufacturer (AMD/Intel). The operator is removed from the trust equation — even a malicious operator cannot access traffic inside the enclave. TEE-attested nodes are preferred in circuit selection, especially for the entry position.

**Phase 6 (layered):** ZK-VM proves software honesty. TEE proves hardware isolation. Ephemeral compute proves no persistence. Traffic analysis detects exfiltration. Each layer is independently insufficient but collectively they cover each other's blind spots.

**Long-term (research):** Purpose-built secure coprocessor hardware eliminates the host OS from the architecture entirely for operators who want the strongest guarantee.

### Known limitation

No combination of software, cryptographic, or hardware techniques can provide a mathematical proof that an arbitrary remote machine isn't logging. TEE + ZK-VM + ephemeral compute gets close — the remaining attack surface is hardware-level side channels against the TEE, which require physical access to the machine and sophisticated lab equipment. For ShieldNode's threat model, this is sufficient: the multi-hop architecture means an attacker must compromise the TEE on both entry and exit nodes in the same circuit to correlate traffic, and hardware side-channel attacks don't scale to attacking many nodes simultaneously.

### TEE implementation notes

- Prefer AMD SEV-SNP over Intel SGX. SGX has had multiple side-channel breaks (Spectre, Foreshadow, ÆPIC Leak, Plundervolt). SEV-SNP is newer with a stronger security track record so far
- The relay binary must be compiled as a single static binary that runs inside the enclave with minimal dependencies. No dynamic linking, no shell access, no debugging interfaces
- Attestation verification can happen client-side (the client checks the attestation report against AMD's root of trust certificate chain) or on-chain (store attestation hashes in the NodeRegistry for public verifiability). Client-side is simpler; on-chain is more transparent. Implement client-side first, add on-chain attestation hashes as a NodeRegistry field in Phase 6
- TEE nodes should be a tier, not a requirement. Requiring TEE would exclude operators running on non-TEE hardware (Raspberry Pis, older servers, some VPS providers). Instead, TEE attestation provides a scoring bonus and entry-node preference. The network benefits from both TEE-attested high-trust nodes and non-TEE commodity nodes for breadth

---

## Traffic Analysis Resistance

Even with content fully encrypted, metadata leaks from packet timing, sizes, and volume patterns can enable traffic correlation attacks. ShieldNode's approach: make captured data structurally useless through layered defenses that eliminate each metadata signal independently.

### What an operator can capture vs. what it's worth

| Captured data | Current status | Mitigation | Phase | Result after mitigation |
|--------------|----------------|------------|-------|----------------------|
| Packet payloads | Encrypted (Sphinx + ChaCha20) | Already useless | 1 (done) | Ciphertext, undecryptable without ephemeral keys |
| Packet sizes | Variable, leaks traffic type | Fixed-size normalization | 4 | All packets identical size — no fingerprinting |
| Packet timing | Correlatable between hops | Cover traffic + batching | 5-6 | Timing obscured by padding and shuffle |
| Activity patterns | Visible (traffic vs silence) | Adaptive cover traffic | 5 | Constant baseline rate, active indistinguishable from idle |
| Session duration | Visible (circuit start/end) | Circuit auto-rotation (done) + cover traffic | 2+5 | Short-lived circuits with uniform traffic profiles |
| Session keys | Ephemeral, zeroized on drop | Micro-ratcheting (30s windows) | 5 | Key compromise exposes ≤30s of traffic |
| Next-hop IPs | Necessarily known by relay | Circuit diversity constraints | 4 | Knowing adjacent hops reveals only public node IPs, not client or destination |
| Inter-link traffic volume | Observable per link | Link padding | 5 | All links carry constant-rate traffic regardless of real load |

### Defense tiers

**Tier 1 — Content protection (done):** Sphinx onion encryption + ChaCha20-Poly1305 + hybrid PQ handshake. Captured payloads are ciphertext. This is already built and operational.

**Tier 2 — Size normalization (Phase 4):** Fixed-size packets eliminate size-based fingerprinting. Low overhead, no latency cost. Should be enabled by default for all traffic.

**Tier 3 — Temporal protection (Phase 5):** Micro-ratcheting limits key compromise exposure to 30-second windows. Adaptive cover traffic prevents activity detection. Inter-node link padding prevents link-level traffic analysis. These have bandwidth costs but make timing correlation significantly harder.

**Tier 4 — Reordering (Phase 6, opt-in):** Packet batching and shuffle at each hop breaks per-packet timing correlation. Adds latency (25-75ms). Best for users with strong privacy requirements who can tolerate the delay.

### Cover traffic design notes

- Cover packets must be cryptographically indistinguishable from real packets. They use the same Sphinx format, same fixed size, same encryption. The only difference is a flag in the innermost Sphinx layer (readable only by the exit node after peeling all layers) that tells the exit to discard rather than forward
- Cover traffic rate should adapt to the user's real traffic pattern, not be purely constant. A naive constant rate during active browsing followed by the same constant rate during sleep is distinguishable from a user who only has constant-rate traffic. The client should vary the cover rate stochastically around the baseline to prevent pattern detection
- Cover traffic has a real bandwidth cost that users should understand and control. Display estimated daily bandwidth overhead in Settings based on the selected cover level. Default "low" costs ~1.1 GB/day — significant for mobile/metered connections, negligible for home broadband
- Exit nodes must drop cover packets silently with no observable side effect (no different timing, no response, no error). The exit's handling of cover vs real packets must be constant-time to prevent a timing side channel

### Micro-ratcheting design notes

- The ratchet follows Signal's Double Ratchet pattern adapted for tunnel traffic: symmetric key chain ratcheted with each time/data window, DH ratchet stepped with fresh ephemeral keys periodically (every 5 minutes or every 100 MB)
- Both client and relay maintain synchronized ratchet state. A ratchet-step control message (fixed-size Sphinx packet with a control flag) signals the new epoch. If state desynchronizes (e.g., packet loss causes one side to advance), a resync mechanism uses the DH ratchet to re-derive a shared state
- Previous ratchet keys must be zeroized immediately — use Rust's `zeroize` crate on the key material. The `Ratchet` struct should implement `Drop` with zeroization. This is already the pattern used for session keys (Phase 1)
- The ratchet mechanism must be constant-time: the ratchet-step computation should take the same amount of time regardless of which epoch it's advancing to, to prevent timing side channels

### Honest assessment

Full constant-rate traffic (Nym's approach) provides the strongest theoretical protection but costs 95%+ bandwidth overhead — impractical for a VPN carrying real-time traffic. ShieldNode's adaptive approach trades theoretical perfection for practical deployability: fixed-size packets + adaptive cover + optional batching provides strong protection against passive observers and significantly raises the cost of active traffic analysis, while keeping bandwidth overhead manageable (1-6 GB/day depending on settings). A global passive adversary with long-term traffic captures and unlimited compute can still potentially correlate flows through statistical analysis of the adaptive cover pattern, but the cost of this analysis is orders of magnitude higher than against an unpadded system.

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
