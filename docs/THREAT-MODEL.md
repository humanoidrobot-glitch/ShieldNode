# ShieldNode Threat Model & Research

This document covers the threat model for ShieldNode's decentralized VPN, with dedicated research sections on traffic morphing, decentralized correlation detection, and secure coprocessor hardware. Referenced by ROADMAP.md Phase 6 items.

---

## Adversary Model

ShieldNode considers three adversary tiers:

| Tier | Capabilities | Examples |
|------|-------------|----------|
| **Passive local** | Observes traffic on one link (entry or exit, not both) | ISP, coffee shop WiFi operator |
| **Passive global** | Observes all network links simultaneously | State-level surveillance, backbone tap |
| **Active** | Can inject/delay/drop packets, run malicious nodes | Nation-state with budget for Sybil nodes |

The multi-hop onion architecture defends against Tier 1 by design (no single node sees both source and destination). Tiers 2 and 3 require the layered defenses documented here.

---

## Research: Traffic Morphing

**Status:** Research complete. Conclusion: not recommended as a primary defense; useful as a supplementary layer if bandwidth overhead is acceptable.

### Problem Statement

Even with encrypted, fixed-size packets, an observer can potentially identify ShieldNode traffic by analyzing macro-level patterns: burst/pause timing, session initiation signatures, and statistical fingerprints of common web browsing activity routed through a VPN. Traffic morphing attempts to reshape these patterns to resemble a different traffic type (e.g., video streaming, cloud backup, HTTPS browsing).

### Prior Art Reviewed

**BuFLO (Buffered Fixed-Length Obfuscator)** — Dyer et al., 2012
- Sends fixed-size packets at a constant rate for a fixed minimum duration
- Effective but extremely wasteful: 2-3× bandwidth overhead for web browsing
- Key insight: constant rate defeats timing analysis but the cost is prohibitive for bandwidth-intensive applications like VPN
- **Applicability to ShieldNode:** Our adaptive cover traffic (Phase 5) is a relaxed BuFLO — it maintains a baseline rate but allows bursts. Full BuFLO is too expensive for a VPN carrying real-time traffic

**CS-BuFLO (Congestion-Sensitive BuFLO)** — Cai et al., 2014
- Adapts the sending rate to network congestion, reducing BuFLO's overhead
- Still 40-60% overhead for typical browsing
- **Applicability:** More practical than BuFLO. Our cover traffic "high" setting (50 pps / ~5.5 GB/day) is conceptually similar but applied at the Sphinx layer rather than TCP

**Tamaraw** — Cai et al., 2014
- Uses different fixed rates for upstream and downstream
- Pads each direction independently to the next multiple of a fixed block size
- 50-100% overhead, but better classification resistance than BuFLO
- **Applicability:** The directional asymmetry is relevant — VPN traffic is typically download-heavy. Tamaraw's approach of different rates per direction could improve our cover traffic efficiency

**FRONT** — Gong & Wang, 2020
- Randomized response defense: injects dummy packets at random positions
- Much lower overhead than BuFLO (~20-30%)
- Key insight: randomized placement provides probabilistic guarantees without constant-rate cost
- **Applicability:** Our cover traffic jitter (±20%) achieves a similar effect. FRONT's specific dummy placement strategy could improve our injection pattern

**WTF-PAD** — Juárez et al., 2016
- Adaptive padding based on inter-packet timing analysis
- Targets website fingerprinting specifically
- Low overhead (~50-60% increase) with strong fingerprinting resistance
- **Applicability:** Interesting for the tunnel layer but complex to implement correctly. The adaptive timing analysis requires per-circuit state tracking

### Assessment for ShieldNode

| Approach | Overhead | Fingerprinting Resistance | Practical for VPN? |
|----------|----------|--------------------------|-------------------|
| Full BuFLO | 200-300% | Very high | No — prohibitive bandwidth |
| CS-BuFLO | 40-60% | High | Marginal — significant for metered connections |
| Tamaraw | 50-100% | High | Marginal — directional rates are useful |
| FRONT | 20-30% | Moderate-High | Yes — compatible with our cover traffic |
| WTF-PAD | 50-60% | High for fingerprinting | Possible — complex implementation |

### Recommendation

**Do not implement full traffic morphing as a standalone feature.** The bandwidth overhead (20-300%) is too high for a VPN that already has:
- Fixed-size packet normalization (eliminates size fingerprinting)
- Adaptive cover traffic with jitter (obscures activity patterns)
- Inter-node link padding (obscures link-level patterns)
- Packet batching and reordering (breaks per-packet timing)

These existing defenses collectively provide protection comparable to CS-BuFLO or Tamaraw at lower overhead. Adding full traffic morphing on top provides diminishing returns.

**What would be valuable:** Incorporate FRONT's randomized dummy placement strategy into our existing cover traffic injection. Instead of uniform-rate cover, weight injection probability higher immediately after real traffic bursts (when the observer is most likely to be correlating). This is a refinement of our existing "low"/"high" cover traffic levels, not a new system.

### Key Takeaway

Academic traffic morphing research shows that raising the cost of fingerprinting is achievable, but eliminating it entirely requires constant-rate traffic (BuFLO), which is impractical for bandwidth-sensitive applications. ShieldNode's layered approach (normalize + cover + pad + batch) is the right architecture. The remaining improvement is in the statistical quality of cover traffic injection patterns, not in adding a separate morphing layer.

---

## Research: Decentralized Correlation Detection

**Status:** Research complete. Conclusion: open problem with a promising ZK-based direction, but no production-ready solution exists.

### Problem Statement

Detecting correlated misbehavior across the network (e.g., two nodes that consistently go offline together, suggesting common infrastructure or operator) requires aggregating observations from multiple clients without revealing their traffic data. A centralized observer (like Tor's directory authorities) can do this easily but introduces a trust point. Can clients collaboratively build a reputation signal without a trusted aggregator?

### Approaches Investigated

**1. ZK Anonymous Client Reporting**

Clients could submit ZK proofs asserting: "I experienced correlated failures through nodes X and Y during time window T" without revealing their identity, circuit, or traffic.

- **What the proof shows:** Two node IDs, a time window, and the nature of the correlation (both failed, both throttled, etc.)
- **What the proof hides:** Client identity, circuit structure, traffic content
- **Verification:** On-chain or via a dedicated aggregation contract that accepts proofs and tallies reports per node pair
- **Threshold:** When N independent reports (from different provers, verified via nullifiers) flag the same node pair, a public alert is emitted

**Technical feasibility:**
- The ZK circuit is simple: prove knowledge of a session where nodes X and Y were in the same circuit and the session outcome was bad (low bytes, timeout, etc.)
- Estimated constraint count: ~500K (two signature verifications + session metadata commitments)
- Main challenge: preventing a single entity from submitting multiple reports with different nullifiers (Sybil at the reporting level)
- Possible mitigation: require reports to commit a deposit that is slashed if the report is provably false, or use Semaphore-style group membership proofs where each client gets one anonymous report per epoch

**Assessment:** Technically promising but requires solving the Sybil-at-reporting problem. Without deposit requirements or group membership proofs, a malicious actor could flood the system with fake correlation reports to grief honest nodes. With deposits, the cost of false reporting creates a deterrent, but also deters legitimate reports (friction). This is an unsolved mechanism design problem.

**2. Federated Reputation Oracles**

A small committee (3-of-5 multisig, rotated periodically) aggregates raw performance reports from clients (submitted encrypted to the committee) and publishes a summary reputation signal. Similar to Tor's directory authority model but with rotation and threshold decryption.

- **Pros:** Simple, proven model (Tor has used it for 20+ years)
- **Cons:** Introduces a trust point; the committee members can see which clients report which nodes; rotation doesn't eliminate the trust assumption, just limits its duration
- **Assessment:** Acceptable as a Phase 5 bootstrapping measure (similar to the trusted challenger set for slashing), but not a long-term solution for a system that claims "no trust assumptions beyond Ethereum consensus"

**3. Homomorphic Aggregation**

Clients encrypt their performance observations with a homomorphic encryption scheme. An aggregator sums the encrypted values without decrypting them. The result, when decrypted (by a threshold key ceremony), reveals aggregate statistics per node without revealing individual client observations.

- **Pros:** Strong privacy for individual reports
- **Cons:** Homomorphic encryption is computationally expensive (seconds per operation for current schemes), the threshold decryption ceremony is complex to coordinate, and the aggregate result still needs interpretation (what does "average score of 0.3 for node X" mean actionably?)
- **Assessment:** Theoretically elegant but impractical for real-time reputation. Better suited for periodic (weekly/monthly) network health reports than per-circuit reputation signals

### Recommendation

**Phase 5 (near-term):** Use the federated reputation oracle model as a complement to the existing trusted challenger set. The same multisig that authorizes challenges can aggregate client performance reports. This is not new trust — it's the same trust surface.

**Phase 6+ (long-term):** Investigate the ZK anonymous reporting path with Semaphore-style group membership. Each registered client (identified by a Semaphore identity commitment) gets one anonymous report per 24-hour epoch. The aggregation contract tallies reports per node pair and emits alerts when a threshold is crossed. The Sybil problem is bounded by Semaphore's one-person-one-identity assumption, which in ShieldNode's context could be tied to active session deposits (each depositor gets one reporting identity per epoch).

**Key limitation:** No fully decentralized, Sybil-resistant, privacy-preserving reputation aggregation system exists in production today. ShieldNode should not block mainnet launch on solving this. The existing client-side heuristics (stake concentration, same-operator exclusion, diversity constraints) provide meaningful protection without any centralized component.

---

## Research: Secure Coprocessor for Relay Function

**Status:** Research complete. Conclusion: strongest possible anti-logging guarantee but requires custom hardware; not practical for general operators. Viable as a premium "verified hardware node" tier.

### Problem Statement

Even with TEE attestation (AMD SEV-SNP), the trust model includes the hardware manufacturer — AMD could theoretically have backdoors, and side-channel attacks against SEV-SNP have been demonstrated in lab settings (though none are practical at scale). A secure coprocessor would eliminate the host OS entirely from the relay path: dedicated hardware with no general-purpose OS, no filesystem, no logging capability by design.

### Hardware Approaches Investigated

**1. Secure Elements (SE)**

Tamper-resistant chips (e.g., ATECC608, NXP SE050) designed for key storage and simple cryptographic operations. Used in hardware wallets, payment cards, and IoT authentication.

- **Capabilities:** AES/SHA/ECC operations, secure key storage, tamper detection
- **Limitations:** Very limited compute (MHz-class processors), no general-purpose execution, cannot run packet forwarding at line rate
- **Assessment:** Cannot run the relay function. Useful only for key storage (already handled by zeroize + TEE)

**2. HSMs (Hardware Security Modules)**

Dedicated cryptographic processing units (e.g., Thales Luna, AWS CloudHSM) with FIPS 140-2/3 certification. Provide key management, signing, and encryption at high throughput.

- **Capabilities:** High-throughput crypto (10K+ TLS handshakes/sec), secure key storage, audit logging
- **Limitations:** Not designed for arbitrary packet processing. The relay function requires packet routing decisions, Sphinx layer peeling, and bandwidth accounting — operations HSMs don't support
- **Assessment:** Could offload the ChaCha20-Poly1305 and HMAC operations, but the Sphinx routing logic must run elsewhere. Partial protection only: the key operations are secure but the packet metadata (source/destination) is still visible to the routing logic outside the HSM

**3. Oasis Network / Sapphire Runtime**

Confidential computing platform using Intel SGX enclaves for smart contract execution. The Sapphire runtime allows developers to write confidential contracts where state is encrypted and only accessible inside the enclave.

- **Capabilities:** Full Turing-complete execution inside SGX, encrypted state, remote attestation
- **Limitations:** SGX has had multiple side-channel vulnerabilities (Spectre, Foreshadow, ÆPIC Leak, Plundervolt). Performance is lower than native execution. Network I/O from inside the enclave is possible but adds latency
- **Assessment:** The Sapphire model — running a full application inside an enclave with encrypted state — is the closest existing analogue to what a ShieldNode relay coprocessor would look like. However, SGX's security track record makes it unsuitable as the sole protection. AMD SEV-SNP (already in our Phase 5 plan) has a stronger record

**4. FPGA-Based Packet Processor**

A custom FPGA design that implements the relay function in hardware logic: receive encrypted packet → peel Sphinx layer → forward to next hop. No CPU, no OS, no software stack.

- **Capabilities:** Line-rate packet processing (10 Gbps+), fully deterministic, no software vulnerabilities
- **Limitations:** Extremely expensive to develop ($100K+ for design and verification), difficult to update (hardware changes require new bitstream), specialized expertise required
- **Assessment:** The strongest possible guarantee — hardware that physically cannot log because it has no storage medium and no I/O paths except the input and output packet interfaces. But the development cost and inflexibility make it impractical for a decentralized network where operators use commodity hardware

**5. RISC-V with Custom Firmware**

A minimal RISC-V SoC running a bare-metal firmware that implements only the relay function. No OS, no filesystem, no networking stack beyond UDP send/receive. The firmware is compiled from the same `process_relay_packet()` source code used by the ZK-VM proofs.

- **Capabilities:** General-purpose compute but in a stripped-down environment. Attestable via secure boot (verify firmware hash on startup). Affordable hardware (~$50-100 for a RISC-V dev board)
- **Limitations:** Bare-metal firmware development is complex. No OS means no standard networking — requires custom UDP driver. Performance may be limited compared to a full Linux node
- **Assessment:** The most practical coprocessor option. Affordable, attestable, and running the same code that ZK-VM proofs verify. The operator cannot modify the firmware without changing the boot hash, which is detectable by clients checking the attestation. Main gap: no production-quality bare-metal RISC-V relay implementation exists yet

### Recommendation

**Tier system for node trust levels:**

| Tier | Trust Model | Available When |
|------|------------|---------------|
| Standard | Trust operator (software design + economics) | Now |
| TEE-attested | Trust AMD/Intel hardware (SEV-SNP enclave) | Phase 5 |
| Verified hardware | Trust RISC-V secure boot (bare-metal relay) | Phase 6+ |
| Research | FPGA coprocessor (no trust required) | Research only |

**Near-term (Phase 5):** TEE attestation via AMD SEV-SNP. Already planned and partially implemented. Provides strong protection against malicious operators at the cost of trusting AMD's hardware security.

**Medium-term (Phase 6):** RISC-V secure boot relay. Develop a bare-metal firmware image for commodity RISC-V boards that runs `process_relay_packet()` and nothing else. The firmware hash is published alongside the reproducible build. Operators who want the "verified hardware" tier run this on a dedicated $50 board. Clients check the attestation hash against the published firmware hash.

**Long-term (research):** FPGA coprocessor for operators who want the absolute strongest guarantee. Not practical for general deployment but could be offered as a premium tier for enterprise operators or privacy-critical use cases.

**Key limitation:** No combination of hardware approaches eliminates the need for the multi-hop architecture. Even a "perfect" coprocessor at one hop doesn't protect against an adversary who controls both the entry and exit hops through different means. The coprocessor reduces the attack surface at each hop; the multi-hop design ensures compromise of any single hop (regardless of method) is insufficient for traffic correlation.

---

## Summary: Defense-in-Depth

| Layer | What It Protects | Phase |
|-------|-----------------|-------|
| Sphinx onion encryption | Content confidentiality | 1 (done) |
| Fixed-size packets | Against size fingerprinting | 4 (done) |
| Hybrid PQ handshake | Against harvest-now-decrypt-later | 4 (done) |
| Circuit diversity | Against infrastructure correlation | 4 (done) |
| Micro-ratcheting | Limits key compromise to 30s windows | 5 (done) |
| Adaptive cover traffic | Against activity detection | 5 (done) |
| Link padding | Against link-level analysis | 5 (done) |
| TEE attestation | Against malicious operators | 5 (done) |
| Packet batching/reorder | Against per-packet timing correlation | 6 (done) |
| Dummy Merkle tree | Against network size enumeration | 6 (done) |
| ZK anonymous reporting | Against correlated misbehavior | 6 (research) |
| Secure coprocessor | Against host-level compromise | 6+ (research) |
| Traffic morphing | Against macro-level fingerprinting | Not recommended as standalone |
