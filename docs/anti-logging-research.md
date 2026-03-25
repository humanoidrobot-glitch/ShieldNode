# ShieldNode Anti-Logging Architecture: A Comprehensive Analysis

**Authors:** ShieldNode Core Team
**Date:** March 2026
**Version:** 1.0
**Status:** Living document — updated as implementation progresses

---

## Abstract

This document presents a comprehensive analysis of ShieldNode's anti-logging architecture — the layered defense system designed to ensure that node operators cannot meaningfully capture, retain, or exploit user traffic data. We examine ten distinct defense mechanisms spanning content encryption, packet normalization, cover traffic, post-quantum key exchange, cryptographic forward secrecy, hardware isolation, software verification, environmental constraints, exfiltration detection, and traffic reordering. For each mechanism, we define the threat it addresses, the protection provided, its known limitations, and its relationship to adjacent layers. We conclude with an honest assessment of the residual attack surface and a comparison with existing approaches in Tor, Nym, and related anonymity systems.

The central thesis is a reframing: rather than attempting to *prove* that logging does not occur — a problem that is fundamentally unsolvable for remote machines — ShieldNode's architecture ensures that any data an operator *could* capture is structurally difficult to exploit. Captured traffic consists of fixed-size ciphertext blobs, mixed with indistinguishable cover traffic, encrypted under keys that are ratcheted every 30 seconds and immediately destroyed, potentially reordered within batched windows, and — where TEE hardware is available — processed inside an enclave the operator cannot observe. The combination renders passive traffic capture largely futile and active traffic analysis significantly more expensive, though we are precise about which layers are currently implemented versus planned.

---

## 1. Threat Model

### 1.1 Adversary Classes

We consider three adversary classes with increasing capability:

**Honest-but-curious operator.** Runs unmodified ShieldNode software but wishes to learn about user traffic by examining data available to the relay process. This adversary does not modify binaries or install additional capture software but may inspect logs, memory dumps, or network interfaces accessible to the standard OS user.

**Malicious operator.** Modifies the relay binary, installs packet capture tools (tcpdump, Wireshark), kernel modules, or operates a compromised host OS. Has full root access to the machine running the relay node. This is the primary adversary for a decentralized VPN where operators are anonymous and economically motivated.

**State-level adversary.** Controls network infrastructure (ISPs, IX points), can observe traffic on multiple links simultaneously, and may compel operators to cooperate. May deploy sophisticated hardware attacks (side-channel extraction against TEEs) and has functionally unlimited computational resources for traffic analysis.

### 1.2 What the Adversary Observes

At the relay node level, a malicious operator with full system access can potentially observe:

1. **Encrypted packet payloads** — the raw bytes of each Sphinx packet entering and leaving the relay
2. **Packet sizes** — the byte length of each packet on the wire
3. **Packet timing** — arrival and departure timestamps at nanosecond precision
4. **Adjacent hop IP addresses** — the IP of the previous node and the next node in the circuit
5. **Traffic volume patterns** — aggregate bandwidth over time, session duration, activity/silence periods
6. **Session key material** — if the operator can access relay process memory during execution
7. **Circuit metadata** — session identifiers, handshake parameters visible to the relay

ShieldNode's defense layers systematically neutralize the value of each observable.

---

## 2. Layer 1: Content Encryption (Sphinx Onion Routing)

### 2.1 Mechanism

ShieldNode employs the Sphinx cryptographic packet format, introduced by Danezis and Goldberg [1], for all traffic routing through the relay network. Sphinx provides bitwise unlinkability: a packet entering a relay node cannot be correlated with the packet leaving that node based on content, because each relay cryptographically transforms the packet by removing one layer of encryption.

The construction works as follows: the client pre-computes a layered encryption of the payload, with one layer for each hop in the circuit. Each layer is encrypted under a symmetric key derived from an ephemeral Diffie-Hellman exchange between the client and that specific relay. When a relay processes a packet, it performs a DH computation with the packet's embedded group element, derives the layer key, decrypts its layer (revealing the next-hop address and a re-randomized group element), and forwards the resulting packet. The output packet is bitwise unlinkable to the input.

### 2.2 Properties Achieved

Sphinx provides several critical security properties proven in the random oracle model [1]:

- **Bitwise unlinkability per hop.** No passive observer can correlate input and output packets at a relay based on content.
- **Hidden path length.** All Sphinx packets are fixed-length regardless of how many hops remain, so an observer cannot determine a packet's position in the route from the packet format alone.
- **Tagging attack detection.** Modifications to the packet header are detected via MAC verification, preventing an adversary from "tagging" a packet at one hop and recognizing it at another.
- **Replay attack detection.** Duplicate packet headers are detected and rejected.

Note: while Sphinx itself hides relay position in a generic mixnet, ShieldNode's specific protocol makes positions partially distinguishable — the entry node accepts client connections (not relay-to-relay traffic), and the exit node decapsulates to plaintext for internet forwarding. The middle relay is the only position that is truly position-blind at the protocol level. This is an inherent tradeoff of the VPN use case, where the exit must interact with the clearnet.

### 2.3 ShieldNode Parameterization

ShieldNode instantiates Sphinx with the following primitives:

- **Group operation (Sphinx per-hop DH):** X25519 (Curve25519 Diffie-Hellman). Note: the Sphinx packet format's internal group operations use classical X25519 only. Post-quantum Sphinx (replacing X25519 with a KEM-based construction) is a Phase 6 research item — see [3] for emerging work on PQ packet formats
- **Circuit handshake (Noise NK):** Hybrid X25519 + ML-KEM-768 (see Section 5). This protects the *circuit construction* key exchange, which is separate from the Sphinx per-hop group operation
- **Symmetric encryption:** ChaCha20-Poly1305 (AEAD)
- **Key derivation:** HKDF-SHA256
- **MAC:** HMAC-SHA256 (truncated to 128 bits for header MAC)
- **Maximum path length:** 3 hops (entry, relay, exit)

### 2.4 What This Layer Does Not Address

Sphinx protects packet content but does not protect metadata. An observer at a relay node can still see packet sizes (before normalization), timing, and the IP addresses of adjacent hops. These metadata channels are addressed by subsequent layers.

### 2.5 References

[1] Danezis, G., Goldberg, I. "Sphinx: A Compact and Provably Secure Mix Format." IEEE Symposium on Security and Privacy, 2009. DOI: 10.1109/SP.2009.15.

[2] Stainton, D. "Sphinx Mix Network Cryptographic Packet Format Specification." Katzenpost, 2017. https://katzenpost.network/docs/specs/sphinx.html

[3] "Outfox: A Post-quantum Packet Format for Layered Mixnets." arXiv:2412.19937, 2024.

---

## 3. Layer 2: Fixed-Size Packet Normalization

### 3.1 Threat Addressed

Packet size variation leaks information about the nature of the underlying traffic. Web browsing produces characteristic bursts of small request packets followed by large response packets. Video streaming produces sustained large packets. DNS queries produce small fixed-size packets. An adversary logging packet sizes can perform traffic fingerprinting — matching observed size distributions against known traffic profiles to infer what the user is doing.

### 3.2 Mechanism

ShieldNode enforces a fixed outer packet size of 1280 bytes for all tunnel traffic. This value is chosen to match the minimum IPv6 MTU, ensuring packets are not fragmented by intermediate network equipment.

- **Undersized packets** are padded with cryptographically random bytes to reach exactly 1280 bytes.
- **Oversized packets** are fragmented into multiple 1280-byte chunks, each carrying a sequence number in a fixed-size header for reassembly at the receiving end.

The Sphinx packet format already normalizes the inner onion layer to a fixed size. The outer normalization extends this to the WireGuard encapsulation layer, ensuring that every UDP datagram on the physical network is identical in size.

### 3.3 Properties Achieved

After normalization, an observer capturing traffic at a relay sees a stream of identically-sized encrypted UDP datagrams. No information about the nature, size distribution, or protocol characteristics of the underlying traffic can be inferred from packet sizes alone.

### 3.4 Performance Impact

Padding adds overhead for small packets (worst case: a 1-byte payload padded to 1280 bytes). Fragmentation adds latency for large packets (reassembly buffer + additional round trips for fragments). In practice, VPN traffic is dominated by near-MTU packets (web content, streaming), so the overhead is minimal for typical usage. The reassembly buffer at the receiving end uses sequence numbers to reconstruct original packets, adding negligible computational cost.

### 3.5 Prior Art

Fixed-size packet normalization is a foundational technique in mixnet design. Chaum's original 1981 proposal required all messages to be padded to identical length [4]. The Sphinx format itself mandates fixed-length packets [1]. ShieldNode extends this principle from the cryptographic layer to the network transport layer.

[4] Chaum, D. "Untraceable Electronic Mail, Return Addresses and Digital Pseudonyms." Communications of the ACM 24(2), 1981.

---

## 4. Layer 3: Adaptive Cover Traffic

### 4.1 Threat Addressed

Even with fixed-size packets, an adversary can observe *when* packets are sent. Traffic timing reveals activity patterns: a user browsing produces bursty traffic with gaps; a user streaming produces sustained traffic; an idle user produces no traffic. An adversary monitoring a relay can detect when a circuit is active versus idle, correlate activity periods with external events, and potentially fingerprint specific websites or applications based on timing patterns alone.

### 4.2 Mechanism

ShieldNode implements adaptive cover traffic at two levels:

**Client-side cover traffic.** The client maintains a configurable baseline packet rate regardless of real traffic volume. When real traffic drops below the baseline, the client injects dummy Sphinx packets to fill the gap. These dummy packets are:

- Encrypted using the same Sphinx format as real packets
- The same fixed size (1280 bytes) as real packets
- Routed through the full 3-hop circuit
- Marked with a flag in the innermost Sphinx layer (readable only by the exit node after peeling all three layers) that instructs the exit to silently discard rather than forward

An adversary at any relay position cannot distinguish cover traffic from real traffic — both are identically-sized, identically-encrypted Sphinx packets traversing the same route.

Three configurable cover levels are provided:
- **Off:** No cover traffic. Lowest bandwidth. No activity obfuscation.
- **Low (default):** ~10 packets/second baseline. ~12.8 KB/s overhead (~1.1 GB/day).
- **High:** ~50 packets/second baseline. ~64 KB/s overhead (~5.5 GB/day).

**Inter-node link padding.** Between adjacent relay nodes, a constant-rate encrypted stream is maintained independent of user traffic. When real session traffic is below the link baseline rate, padding packets fill the gap. This prevents a network-level observer (ISP, IX point) from determining which relay-to-relay links are carrying real traffic. Bandwidth cost: ~50 pps × 1280 bytes per peer link (~640 KB/s for 10 peers, ~55 GB/day). This is opt-in for node operators with high-bandwidth connections.

### 4.3 Design Considerations

The cover traffic rate is not purely constant but stochastically varies around the baseline to prevent pattern detection. A naive constant-rate implementation can itself become a fingerprint — if the rate is always exactly 10.000 pps during activity and exactly 10.000 pps during idleness, the absence of any variation is itself distinctive. The client introduces Poisson-distributed jitter around the target rate.

Exit node handling of cover packets must be constant-time. If the exit processes cover packets faster than real packets (because it discards rather than forwards), this timing difference is observable by the relay feeding the exit node. The exit must process both types with identical computational and timing profiles.

### 4.4 Prior Art

Cover traffic is extensively studied in the mixnet literature. The Nym network generates continuous cover traffic that is indistinguishable from real traffic, with each mix node delaying packets independently according to an exponential distribution [5]. The Loopix design [6] introduced the distinction between loop cover traffic (client → client, for detecting active attacks) and drop cover traffic (discarded at the last hop, for preventing passive analysis). ShieldNode's design follows the Loopix drop cover model, with client-generated cover discarded at the exit.

The bandwidth cost of cover traffic is the primary practical limitation. Research on constant-rate anonymity designs showed that maintaining full constant-rate traffic can result in 95%+ of bandwidth being cover rather than real payload — the Aqua system [7] specifically addressed this by designing a more efficient architecture for bandwidth-intensive applications like BitTorrent, achieving significantly lower overhead than naive constant-rate approaches. ShieldNode's adaptive approach — covering only idle periods rather than maintaining full constant rate — follows a similar practical philosophy, trading theoretical perfection for deployability. Empirical evaluation of Nym's cover traffic by Wicky et al. [8] showed that even partial cover traffic significantly degrades website fingerprinting accuracy, suggesting that adaptive approaches provide meaningful (though not absolute) protection.

[5] Nym Technologies. "Nym Whitepaper." https://nymtech.net

[6] Piotrowska, A., et al. "The Loopix Anonymity System." USENIX Security, 2017.

[7] Le Blond, S., et al. "Towards Efficient Traffic-Analysis Resistant Anonymity Networks." ACM SIGCOMM, 2013.

[8] Wicky, S., et al. "Empirical Evaluation of Traffic Fingerprinting Against the Nym Mixnet." 2024. https://nymtech.net/uploads/Nym_WFP_Paper_5_58a1105679.pdf

---

## 5. Layer 4: Post-Quantum Hybrid Key Exchange

### 5.1 Threat Addressed

"Harvest now, decrypt later" (HNDL). An adversary recording circuit handshakes today can store the captured key exchange data indefinitely. When cryptographically relevant quantum computers become available (estimated early-to-mid 2030s per EF assessment [9]), Shor's algorithm could recover X25519 private keys from the captured public keys, enabling retroactive decryption of session keys and circuit routing information.

For ShieldNode, HNDL is particularly severe because the circuit handshake reveals the *route* — which nodes are connected in which order. Retroactive decryption doesn't just expose traffic content (which is also encrypted end-to-end); it exposes the network topology of each session, compromising the core anonymity guarantee.

### 5.2 Mechanism

ShieldNode implements a hybrid key exchange combining classical X25519 with post-quantum ML-KEM-768 (NIST FIPS 203 [10]). During circuit construction, each hop's handshake performs both exchanges in parallel:

```
session_key = HKDF-SHA256(
    ikm = X25519_shared_secret || ML-KEM-768_shared_secret,
    salt = session_id,
    info = "shieldnode-hybrid-kex"
)
```

The session key is derived from *both* shared secrets. Security is the stronger of the two: if ML-KEM-768 is broken by future cryptanalysis, X25519 still provides classical security. If X25519 is broken by quantum computers, ML-KEM-768 provides post-quantum security.

### 5.3 Overhead

ML-KEM-768 adds approximately 1,184 bytes (encapsulation key) + 1,088 bytes (ciphertext) per hop during circuit construction. For a 3-hop circuit: ~6.8 KB total additional handshake data. This is exchanged once during circuit setup, not per packet. At typical session throughputs of 50+ MB/s, the one-time overhead is negligible. ML-KEM-768 encapsulation and decapsulation complete in approximately 80-150 microseconds on modern hardware [11].

### 5.4 Standards Compliance

ML-KEM-768 is standardized as NIST FIPS 203 (August 2024) [10]. ShieldNode uses the `ml-kem` RustCrypto crate, which implements the FIPS 203 specification. AWS has deployed ML-KEM in production via hybrid TLS key exchange using the same parameter set [11], providing confidence in the implementation maturity.

The hybrid key exchange pattern follows the IETF draft for ECDHE-MLKEM in TLS 1.3 [12], which specifies the combination of X25519 with ML-KEM-768 for post-quantum hybrid key agreement.

### 5.5 References

[9] Ethereum Foundation. "Post-Quantum Ethereum: FAQ." https://pq.ethereum.org

[10] NIST. "FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard." August 2024. DOI: 10.6028/nist.fips.203

[11] AWS Security Blog. "ML-KEM Post-Quantum TLS Now Supported in AWS KMS, ACM, and Secrets Manager." May 2025.

[12] Kwiatkowski, K., et al. "Post-quantum Hybrid ECDHE-MLKEM Key Agreement for TLSv1.3." IETF Internet-Draft, draft-ietf-tls-ecdhe-mlkem-04, February 2026.

---

## 6. Layer 5: Micro-Ratcheting Forward Secrecy

### 6.1 Threat Addressed

Key compromise. If an adversary obtains a session key through any means — memory extraction, hardware fault, side-channel attack, or future cryptanalytic breakthrough — they can decrypt all traffic encrypted under that key. Without ratcheting, a single session key protects the entire duration of a circuit (potentially minutes to hours). With ratcheting, key compromise exposes only the traffic within one ratchet window.

### 6.2 Mechanism

ShieldNode implements a Double Ratchet-inspired key rotation mechanism, adapted from the Signal Protocol [13]. The symmetric session key used for ChaCha20-Poly1305 tunnel encryption is ratcheted every 30 seconds or every 10 MB of data, whichever comes first.

The ratchet operates in two modes:

**Symmetric chain ratchet (every 30 seconds / 10 MB):**
```
new_key = HKDF-SHA256(
    ikm = current_key,
    salt = ratchet_epoch,
    info = "shieldnode-sym-ratchet"
)
```

**DH ratchet (every 5 minutes / 100 MB):**
```
new_chain_key = HKDF-SHA256(
    ikm = fresh_hybrid_DH_shared_secret,
    salt = dh_ratchet_epoch,
    info = "shieldnode-dh-ratchet"
)
```

The symmetric chain advances frequently using only the previous key and an epoch counter — this is computationally trivial (one HKDF call). Periodically, a fresh ephemeral hybrid X25519 + ML-KEM exchange reseeds the chain with new DH material, providing both classical and post-quantum forward secrecy for the ratchet chain itself. This two-tier structure follows Signal's Double Ratchet design: the symmetric ratchet provides forward secrecy at low cost, while the DH ratchet provides break-in recovery (if the current symmetric state is compromised, the next DH ratchet step restores security).

Previous keys are zeroized immediately using the Rust `zeroize` crate, which overwrites memory with zeros and uses `compiler_fence` to prevent the compiler from optimizing away the erasure.

### 6.3 Properties Achieved

- Key compromise exposes at most 30 seconds of traffic
- Forward secrecy: past ratchet windows cannot be decrypted even if the current key is compromised
- Post-quantum forward secrecy: the DH ratchet uses hybrid ML-KEM, so quantum computers cannot retroactively break past ratchet epochs
- Compromise detection: if an adversary injects a packet encrypted under a previous-epoch key, the relay rejects it (keys no longer exist in memory)

### 6.4 Synchronization

Both client and relay maintain synchronized ratchet state. A ratchet-step control message (a fixed-size Sphinx packet with a control flag) signals the new epoch. If state desynchronizes due to packet loss, a resync mechanism uses the DH ratchet to re-derive shared state. The ratchet-step computation is constant-time to prevent timing side channels.

### 6.5 References

[13] Marlinspike, M., Perrin, T. "The Double Ratchet Algorithm." Signal Foundation, 2016. https://signal.org/docs/specifications/doubleratchet/

[14] Mattsson, J.P. "NULL Encryption and Key Exchange Without Forward Secrecy are Discouraged." IETF Internet-Draft, draft-mattsson-tls-psk-ke-dont-dont-dont-05.

---

## 7. Layer 6: TEE Hardware Isolation (AMD SEV-SNP)

### 7.1 Threat Addressed

OS-level surveillance. A malicious operator with root access can install packet capture tools, modify the kernel, or run monitoring processes alongside the relay binary. All software-level defenses (Sphinx encryption, key zeroization, ZK-VM proofs) operate within the boundary of the relay process and cannot prevent the operator from observing traffic *outside* that boundary — at the network interface, in kernel buffers, or through a separate monitoring process.

### 7.2 Mechanism

Trusted Execution Environments (TEEs) provide hardware-enforced memory isolation. The relay binary runs inside an enclave whose memory is encrypted by the CPU and inaccessible to the host OS, hypervisor, or physical machine owner. AMD SEV-SNP (Secure Encrypted Virtualization - Secure Nested Paging) is the preferred TEE platform due to its stronger security track record compared to Intel SGX, which has suffered multiple side-channel attacks (Spectre, Foreshadow, ÆPIC Leak, Plundervolt) [15][16].

The TEE provides remote attestation: a hardware-signed certificate chain proving:

1. The code running inside the enclave matches a specific binary hash
2. The enclave is running on genuine TEE-capable hardware
3. The host OS cannot read the enclave's memory

The client verifies this attestation before including a node in circuit selection, checking that the binary hash matches the reproducible build of the audited open-source ShieldNode relay.

### 7.3 Trust Assumption

TEE shifts the trust from "trust the node operator not to log" to "trust the hardware manufacturer's (AMD/Intel) security engineering." This is a meaningful improvement — the hardware manufacturer has strong commercial incentives to maintain TEE security, unlike an anonymous node operator who may have incentives to sell captured traffic data.

However, it is not trustless. Known TEE attack vectors include:

- **Side-channel attacks:** cache timing, power analysis, electromagnetic emanation [15]
- **Hardware vulnerabilities:** manufacturing defects, undisclosed debug interfaces
- **Supply chain attacks:** compromised hardware before deployment
- **Vendor cooperation:** court orders compelling the manufacturer to weaken TEE security

### 7.4 Implementation

TEE attestation is implemented as a node tier, not a requirement. Nodes running inside a verified TEE enclave receive a significant scoring bonus (approximately 2x weight on the trust component of the scoring algorithm). The entry node position — the most sensitive hop, since it sees the client's real IP address — preferentially selects TEE-attested nodes.

Reproducible builds are required to make attestation meaningful. The build pipeline uses a pinned Rust toolchain, locked `Cargo.lock`, and a Docker-based build environment with a fixed base image hash. A CI job produces the reproducible binary and publishes its hash. This hash is what clients verify against in the TEE attestation report.

TEE-capable hardware is available today on major cloud platforms (AWS Nitro Enclaves, Azure Confidential VMs, GCP Confidential Computing) and on bare metal with AMD EPYC 3rd generation (Milan) or newer processors. Consumer hardware (desktops, laptops, Raspberry Pi) generally does not support the required TEE features, which is why TEE is a tier rather than a requirement.

### 7.5 References

[15] Van Bulck, J., et al. "Foreshadow: Extracting the Keys to the Intel SGX Kingdom." USENIX Security, 2018.

[16] AMD. "SEV-SNP: Strengthening VM Isolation with Integrity Protection and More." AMD White Paper, 2020.

---

## 8. Layer 7: ZK-VM Software Verification

### 8.1 Threat Addressed

Modified relay software. A malicious operator could compile a modified version of the ShieldNode relay that includes logging functionality — writing packet contents, metadata, or session keys to disk or transmitting them to an external server. The TEE (Layer 6) prevents this if available, but for non-TEE nodes, software verification is the primary defense against binary modification.

### 8.2 Mechanism

ZK-VM systems (RISC Zero, SP1) can prove that a specific computation was executed correctly — including proving the *entire execution trace*, not just the input/output relationship. For ShieldNode's relay function:

1. The node commits to a Merkle root of packets received during a time window
2. A challenger selects N random packets from the commitment
3. The node produces a ZK-VM proof that it executed `process_relay_packet()` on each selected packet, producing the correct output
4. The proof additionally demonstrates that the execution trace contained no side-channel writes — no disk I/O, no additional network calls, no memory allocations beyond the expected forwarding operation

The `process_relay_packet()` function is deliberately implemented as a pure function with no side effects, no I/O, and deterministic behavior. This architectural choice was made specifically to enable ZK-VM proving.

### 8.3 Limitations

ZK-VM proofs verify what happened *inside the sandbox*. They cannot prove that the operator isn't running a separate process (tcpdump, modified kernel module) that captures traffic at the OS level before it reaches the relay binary. This is a fundamental limitation of software-level proofs.

This defense is most effective against honest-but-curious operators running unmodified software, and against lazy malicious operators who would modify the relay binary rather than set up OS-level capture. Sophisticated adversaries with root access are better addressed by the TEE layer.

### 8.4 Current Feasibility

ZK-VM proving costs are on the edge of practicality for ShieldNode's relay function. Current RISC Zero benchmarks achieve proof generation in seconds for simple computations. The relay function — an X25519 DH computation, HKDF key derivation, ChaCha20-Poly1305 decryption, and UDP forwarding — is well within the complexity class that current ZK-VMs can handle, but per-packet proving is infeasible at thousands of packets per second. The random sampling approach (prove N random packets from a window) makes this practical: the node doesn't prove every packet, only a random sample sufficient to detect misbehavior with high statistical confidence.

---

## 9. Layer 8: Ephemeral Compute & Environmental Constraints

### 9.1 Threat Addressed

Log persistence. Even if other layers prevent real-time log exploitation, a malicious operator could accumulate captured data over time — storing encrypted packets on the hope of future decryption, building traffic timing databases, or correlating metadata across sessions spanning days or weeks.

### 9.2 Mechanism

The relay runs in an ephemeral container environment (Docker, Firecracker) that is destroyed and recreated on a fixed schedule (default: every hour). The environment enforces:

- **Read-only filesystem:** no writable disk space available to the relay process
- **No volume mounts:** container has no access to persistent storage
- **Memory isolation on teardown:** the container runtime releases memory pages on destruction. Note: standard container runtimes (Docker, containerd) do not guarantee memory zeroing — released pages may be reused by the host without clearing. For stronger guarantees, the relay process itself zeroizes all sensitive data structures before container shutdown using the `zeroize` crate, and the container can be configured to use `memfd_secret` (Linux 5.14+) for key material, which prevents the host from reading those pages even during the container's lifetime
- **No additional network interfaces:** only the tunnel endpoints are accessible

The node produces an attestation (TEE-backed or ZK-VM-backed) that its runtime environment matches a specific configuration hash — confirming the ephemeral constraints are in place.

### 9.3 Limitations

Ephemeral compute prevents *retrospective* log accumulation but does not prevent *real-time* exfiltration. A sufficiently sophisticated operator could stream captured packets to an external server during the container's 1-hour lifetime. This gap is addressed by the traffic volume analysis component (see Section 10).

---

## 10. Layer 9: Traffic Volume Analysis (Exfiltration Detection)

### 10.1 Threat Addressed

Data exfiltration. If a relay is secretly logging and transmitting captured traffic to an external server, it produces more outbound network traffic than expected from legitimate relay forwarding alone.

### 10.2 Mechanism

The traffic volume analysis operates at two levels:

**Circuit-level byte accounting.** The client knows how many bytes it sent into the circuit and how many bytes it received back. The exit node knows how many bytes it forwarded to the internet and how many it received back. If these totals are consistent (accounting for Sphinx overhead, cover traffic, and protocol framing), the relay in the middle is behaving honestly. Significant divergence — particularly if the client-side totals don't match exit-side totals — suggests the relay is dropping, injecting, or duplicating traffic.

**Node-level network monitoring (external).** An independent observer (or the adjacent nodes) can monitor the relay's total network I/O. An honest relay's total outbound traffic should consist only of forwarded circuit traffic to its known peers. If the relay is exfiltrating captured data to an external server, its total network I/O will exceed what the circuit traffic accounts for. This can be detected by the entry and exit nodes if they monitor the relay's traffic patterns to non-circuit IP addresses, though this requires the relay's network interface to be observable — which is straightforward on shared infrastructure but harder on dedicated hardware.

During session settlement, if the byte accounting diverges beyond a threshold (>15%, accounting for protocol overhead, retransmissions, and cover traffic), the relay node is flagged. Repeated flags feed into the client's scoring algorithm and, if evidence is strong enough, into slashing proposals.

### 10.3 Limitations

This detection method catches bulk exfiltration but not sophisticated covert channels: steganographic encoding within legitimate forwarded packets, timing-based covert channels, or batched exfiltration during off-hours when the container is being recycled. These advanced techniques are partially mitigated by the ephemeral compute constraint (limiting accumulation time to 1 hour) and the TEE (preventing the relay process from accessing plaintext to encode steganographically).

---

## 11. Optional Enhancement: Packet Batching and Reordering

### 11.1 Threat Addressed

Per-packet timing correlation. Even with cover traffic filling idle periods, an adversary controlling both the entry and exit of a circuit can match the *timing pattern* of packets — the precise sequence of inter-packet intervals forms a fingerprint that survives onion encryption. This is the most powerful form of traffic analysis against low-latency anonymity systems.

### 11.2 Mechanism

Relay nodes collect packets for a configurable time window (default: 50ms), shuffle the order within the batch using a cryptographically secure random permutation, and forward the batch. This breaks the timing correlation between individual input and output packets at each hop.

### 11.3 Tradeoff

Batching adds 25-75ms latency (half the batch window on average). This is significant for interactive applications (gaming, video calls, real-time collaboration) but acceptable for browsing and bulk transfers. The feature is opt-in: users who prioritize privacy enable batching in client settings; users who need low latency rely on the other layers (normalization + cover traffic) for protection.

### 11.4 Prior Art

Packet batching is fundamental to the original mixnet design. Chaum's 1981 proposal [4] required mixes to collect a batch of messages, cryptographically transform them, and output them in a random order. The tradeoff between batching delay and anonymity strength has been extensively studied. The TARANET system [17] introduced constant-rate flowlets with packet splitting to achieve traffic normalization at the network layer. ShieldNode's optional batching provides a middle ground: available for users who want stronger protection, without imposing the latency cost on all traffic.

[17] Chen, C., et al. "TARANET: Traffic-Analysis Resistant Anonymity at the Network Layer." IEEE EuroS&P, 2018.

---

## 12. Composite Defense Analysis

### 12.1 Defense Layer Summary

| Layer | Mechanism | Threat Neutralized | Phase | Overhead |
|-------|-----------|-------------------|-------|----------|
| 1. Content Encryption | Sphinx onion routing | Payload inspection | Done | ~448 bytes/packet header |
| 2. Size Normalization | Fixed 1280-byte packets | Size fingerprinting | Phase 4 | Padding waste on small packets |
| 3. Cover Traffic | Adaptive dummy Sphinx packets | Activity fingerprinting | Phase 5 | 1.1-5.5 GB/day (configurable) |
| 4. PQ Key Exchange | Hybrid X25519 + ML-KEM-768 | Harvest-now-decrypt-later | Done | ~6.8 KB per circuit setup |
| 5. Micro-Ratcheting | 30-second key rotation + zeroization | Key compromise window | Phase 5 | 1 DH exchange per 30s |
| 6. TEE Isolation | AMD SEV-SNP enclave | OS-level surveillance | Phase 5 | TEE-capable hardware required |
| 7. ZK-VM Verification | Execution trace proofs | Modified relay binary | Phase 6 | Proof generation per sample window |
| 8. Ephemeral Compute | Hourly container recycling | Log persistence | Phase 6 | Container orchestration |
| 9. Traffic Analysis | Byte ratio monitoring | Data exfiltration | Phase 5 | Negligible |
| 10. Packet Batching | 50ms batch + shuffle (opt-in) | Per-packet timing correlation | Phase 6 | 25-75ms added latency |

### 12.2 What Captured Data Is Worth After All Layers

An adversary who captures every byte passing through their relay obtains:

1. **Fixed-size ciphertext blobs** — no size information (Layer 2, Phase 4)
2. **Mixed with indistinguishable cover traffic** — cannot separate real from dummy (Layer 3, Phase 5)
3. **Encrypted under keys that rotate every 30 seconds** — even if one key is compromised, exposure is limited to one window, and previous/future windows are protected by forward secrecy (Layer 5, Phase 5)
4. **Keys are post-quantum resistant** — cannot be retroactively broken by quantum computers (Layer 4, implemented)
5. **Potentially reordered within batch windows** — per-packet timing correlation is broken (Layer 10, Phase 6, opt-in)
6. **Processed inside a hardware enclave** — operator cannot access plaintext during processing (Layer 6, Phase 5, TEE nodes only)
7. **Relay binary is provably unmodified** — cannot have logging code injected (Layer 7, Phase 6)
8. **Running in an ephemeral environment** — captured data cannot persist beyond 1 hour (Layer 8, Phase 6)
9. **Exfiltration attempts are detectable** — anomalous traffic patterns are flagged (Layer 9, Phase 5)

**Important caveat on implementation status:** as of March 2026, Layers 1 and 4 are fully implemented. Layer 2 is in Phase 4 development. Layers 3, 5, 6, and 9 are Phase 5 (pre-mainnet). Layers 7, 8, and 10 are Phase 6 (post-mainnet research and development). The full composite defense described here represents the target architecture, not the current state. The current system provides content encryption (Sphinx) and post-quantum key exchange (hybrid ML-KEM), which protect against payload inspection and harvest-now-decrypt-later, but do not yet address metadata-level traffic analysis.

### 12.3 Residual Attack Surface

We identify the following residual attack vectors that are not fully addressed by the current architecture:

**TEE side-channel attacks.** Hardware-level side channels against AMD SEV-SNP (cache timing, power analysis) require physical access to the machine and laboratory equipment. These attacks do not scale — an adversary would need to perform them on *both* the entry and exit nodes in the same circuit, simultaneously, which requires physical presence at two geographically distributed locations.

**Adaptive cover traffic pattern analysis.** A global passive adversary with long-term traffic captures and unlimited compute can potentially detect statistical differences between adaptive cover traffic and real traffic patterns. Full constant-rate cover traffic (as in Nym) would eliminate this but at 95%+ bandwidth overhead. ShieldNode's adaptive approach significantly raises the cost of analysis but does not provide theoretical perfection.

**Correlation across multiple circuits.** If the same adversary observes a user across many circuit rotations over days or weeks, they can accumulate statistical signal that may eventually enable deanonymization. This is mitigated by circuit diversity constraints (different nodes each rotation) and by the cover traffic making individual circuit fingerprints less distinctive.

**Compromise of all three hops.** If a single adversary controls the entry, relay, and exit nodes of a circuit simultaneously, they can trivially correlate traffic regardless of encryption, cover traffic, or TEE. This is the collusion attack addressed by the anti-collusion architecture (circuit diversity, stake-weighted selection, Sybil resistance), not the anti-logging architecture. The two defense systems are complementary.

---

## 13. Comparison with Existing Systems

### 13.1 Tor

Tor uses onion routing (similar to Sphinx but with a different packet format) and does not employ cover traffic, packet normalization, or key ratcheting within circuits. Tor's anti-logging approach relies primarily on: (a) software design — the relay code does not log by default, (b) community trust — relay operators are volunteers in a social trust network, and (c) directory authorities — centralized trusted parties that monitor relay behavior.

ShieldNode differs by replacing social trust with cryptoeconomic incentives (staking/slashing), adding TEE hardware isolation, implementing cover traffic and packet normalization, and providing forward secrecy via key ratcheting. The tradeoff is higher bandwidth overhead and more complex infrastructure requirements.

### 13.2 Nym

Nym implements a full mixnet with continuous cover traffic, Poisson-distributed mixing delays, and the Sphinx packet format. Nym provides stronger theoretical traffic analysis resistance than ShieldNode's adaptive approach, but at significantly higher bandwidth cost (constant-rate cover traffic on all links). Nym uses staking for Sybil resistance but does not currently employ TEE attestation or ZK-VM verification.

ShieldNode's approach is designed for VPN-class throughput (streaming, browsing), where Nym's full constant-rate cover traffic is impractical. The two systems occupy different points on the performance-privacy tradeoff spectrum.

### 13.3 Orchid

Orchid uses a crypto-payment VPN model similar to ShieldNode but with single-hop routing and no onion encryption. Orchid does not address traffic analysis resistance, cover traffic, or logging prevention beyond operator trust. ShieldNode's multi-hop architecture with layered anti-logging defenses represents a fundamentally stronger security model.

---

## 14. Conclusion

ShieldNode's anti-logging architecture is built on the principle that preventing logging is less tractable than rendering logged data difficult to exploit. Through ten complementary defense mechanisms — spanning content encryption, packet normalization, cover traffic, post-quantum key exchange, cryptographic forward secrecy, hardware isolation, software verification, environmental constraints, exfiltration detection, and optional traffic reordering — the system aims to ensure that any data a node operator could capture provides minimal actionable intelligence.

No single layer provides complete protection. Content encryption protects payloads but leaks metadata. Cover traffic obscures metadata but has bandwidth costs and is adaptive rather than constant-rate, leaving residual statistical signal. TEE prevents OS-level observation but trusts the hardware manufacturer. ZK-VM proves software integrity but can't see outside its sandbox. The strength of the architecture lies in the composition: each layer addresses the specific gap left by the others.

The residual attack surface requires either (a) physical hardware attacks against TEE enclaves at multiple geographic locations simultaneously, (b) global passive adversary capability with long-term storage and computation for statistical analysis of adaptive cover traffic patterns, or (c) compromise of all three circuit hops (addressed by the separate anti-collusion architecture). These represent the practical limits of what a decentralized system can defend against without a trusted central authority. We do not claim that these limits are theoretical impossibilities for a well-resourced adversary — rather, we claim that crossing them requires capabilities and resources that are disproportionate to the value of the information gained from any single circuit.

---

## Appendix A: Cryptographic Primitive Summary

| Primitive | Standard | Use in ShieldNode | Quantum-Safe |
|-----------|----------|-------------------|-------------|
| X25519 | RFC 7748 | Classical DH key exchange | No (Shor's) |
| ML-KEM-768 | NIST FIPS 203 | Post-quantum KEM (hybrid with X25519) | Yes |
| ChaCha20-Poly1305 | RFC 8439 | Symmetric AEAD for tunnel + onion layers | Yes (256-bit) |
| HKDF-SHA256 | RFC 5869 | Key derivation for sessions + ratchet | Yes |
| HMAC-SHA256 | RFC 2104 | Sphinx packet MAC | Yes |
| ML-DSA-65 | NIST FIPS 204 | Post-quantum signatures (inside ZK circuits) | Yes |
| ECDSA (secp256k1) | SEC 2 | EIP-712 receipt signatures | No (Shor's) |
| Groth16 | Groth, 2016 | ZK settlement proof verification | N/A (proof system) |

## Appendix B: Bandwidth Cost Summary

| Defense Layer | Bandwidth Overhead | Configurable | Default |
|---------------|--------------------|-------------|---------|
| Sphinx onion headers | ~448 bytes/packet | No | Always on |
| Fixed-size padding | 0-1279 bytes/packet (avg ~200) | No | Always on |
| Client cover traffic (Low) | ~12.8 KB/s (~1.1 GB/day) | Yes | On (Low) |
| Client cover traffic (High) | ~64 KB/s (~5.5 GB/day) | Yes | Off |
| Inter-node link padding | ~640 KB/s per 10 peers (~55 GB/day) | Yes | Off (opt-in) |
| ML-KEM handshake overhead | ~6.8 KB per circuit setup | No | Always on |
| Ratchet DH exchanges | ~2.3 KB per 5 minutes | No | Always on |
| Packet batching | 0 (reordering, not additional data) | Yes | Off (opt-in) |
