# Technical Debt & Deferred Improvements

Items identified during code review that were intentionally deferred. Revisit these as the project matures beyond Phase 1.

---

## Architecture

### Shared crate for node + client types
The node (`node/src/`) and client (`client/src-tauri/src/`) both define overlapping types (`NodeInfo`, scoring logic, hex parsing, alloy sol! ABIs). These should be extracted into a shared `packages/shieldnode-types/` crate that both consume.

**Why deferred:** Adds build complexity (workspace setup, cross-crate dependencies). Acceptable while both crates are evolving rapidly.

**When to fix:** Before Phase 5 mainnet launch. Node and client already share packet formats, scoring, and EIP-712 logic that should be unified.

### ~~Node scoring algorithm divergence~~ — RESOLVED
Resolved in `fe83b5e`. Both Rust (`circuit.rs`) and TypeScript (`scoring.ts`) now use the same `10 * sqrt(stake_eth) + 30 * uptime - 0.001 * price - 20 * slashes^2` formula.

---

## Performance

### ~~Alloy provider caching~~ — RESOLVED (client)
Resolved (client side): `ChainReader` now parses the URL once in `new()` and provides a `provider()` helper that avoids re-parsing. Three functions (`get_active_nodes`, `get_gas_price`, `get_completion_rates`) no longer duplicate URL parsing. Node-side `ChainService` already had `build_provider()` centralized.

**Why deferred:** Overhead is negligible for current call frequency (once per connect, every 30s for gas). Caching requires `Arc` or `OnceCell` restructuring of `AppState`.

**When to fix:** Phase 4 stress testing, or if RPC latency becomes noticeable.

### ~~Sequential node fetches in get_active_nodes~~ — RESOLVED
Resolved: `get_active_nodes()` now uses `futures::future::join_all()` to fetch all node details in parallel. Added `futures = "0.3"` to client crate.

### std::sync::Mutex vs tokio::sync::Mutex
`client/src-tauri/src/lib.rs` uses `std::sync::Mutex` for `AppState` fields in async Tauri commands. This is a blocking lock in an async context.

**Why deferred:** Locks are never held across `.await` points — they're acquired, used, and dropped within a synchronous block. No contention risk at current scale.

**When to fix:** If AppState grows or lock scopes expand to include async operations.

---

## On-Chain Integration

### ~~Dummy settle signatures~~ — RESOLVED
Resolved in `b4afc92`. Client now produces real EIP-712 signatures, requests node co-signature via RECEIPT_SIGN control message, and ABI-encodes dual-signed receipt for `settleSession`.

### ~~Session ID parsing fragility~~ — RESOLVED
Resolved in `fc7c978`. Now scans all logs for matching `SessionOpened` event signature instead of blindly taking the first log.

---

## Code Quality

### Contract ABI duplication across modules
`INodeRegistry` is defined via sol! in both `node/src/network/chain.rs` and `client/src-tauri/src/chain.rs` with different subsets of functions. `ISessionSettlement` is defined in `client/src-tauri/src/chain.rs`.

**Why deferred:** Extracting to a shared crate (see above) is the proper fix. Until then, the ABIs are small and stable.

**When to fix:** With the shared crate migration.

### ~~Hex parsing implementations~~ — RESOLVED
Resolved: Added `hex = "0.4"` to client crate. `wallet.rs::parse_bytes32()` and `lib.rs::decode_hex_bytes()` now use `hex::decode()` instead of hand-rolled parsing. Node crate already used `hex` crate.

### ~~Custom hex encoding in chain.rs~~ — RESOLVED
Resolved: Removed the hand-rolled `mod hex` from `chain.rs`. The `hex` crate (now a direct dependency) provides `hex::encode()`.

---

## Multi-Hop Relay (Phase 2)

### ~~Relay Mutex lock per packet~~ — RESOLVED
Resolved: Replaced `Arc<Mutex<RelayService>>` with `Arc<RwLock<RelayService>>`. The hot-path `forward_packet()` (read-only: HashMap lookup + Sphinx peel) now uses `.read().await`, allowing concurrent packet forwarding. Only `add_session`/`remove_session` use `.write().await`.

### SphinxPacket allocates Vec on every serialize/deserialize
`to_bytes()` and `from_bytes()` allocate new `Vec<u8>` per call. `peel_layer()` also copies the inner payload. On the relay hot path this creates allocation pressure.

**Why deferred:** Correctness over performance for Phase 2. Buffer pooling or `Cow<[u8]>` references add complexity.

**When to fix:** Phase 4 stress testing, when per-packet allocation becomes measurable.

### HKDF key derivation duplicated between node and client
`node/src/crypto/noise.rs` and `client/src-tauri/src/circuit.rs` both implement HKDF-SHA256 key derivation with different salts. Should be a shared utility.

**Why deferred:** Part of the broader "shared crate" migration (see Architecture section above).

**When to fix:** With the shared crate migration.

### ~~Next-hop address encoding lacks bidirectional codec~~ — RESOLVED
Resolved — `hop_codec` module now exists in both node (`node/src/network/hop_codec.rs`) and client (`client/src-tauri/src/hop_codec.rs`) with `encode_next_hop`/`decode_next_hop`/`endpoint_to_next_hop` functions.

### ~~Sphinx MAC is a placeholder~~ — RESOLVED
Resolved: HMAC-SHA256 over (next_hop || payload) keyed by session key. MAC included in wire format. Constant-time verification via `hmac` crate.

### compute_mac duplicated between node and client sphinx.rs
`compute_mac()` is identical in `node/src/crypto/sphinx.rs` and `client/src-tauri/src/sphinx.rs`. Same function, same HMAC construction, same output pattern. Part of the broader shared crate duplication.

**Why deferred:** No shared crate exists. Both crates need the function independently.

**When to fix:** With the shared crate migration. Extract to `packages/shieldnode-crypto`.

---

## Frontend

### Polling vs event-driven updates
`useSession` and `useGas` hooks poll on intervals (5s and 30s). If the backend connection state changes externally, the UI may be stale for up to one polling interval.

**Why deferred:** Tauri event system integration is more complex. Polling is simple and works.

**When to fix:** Phase 2, when circuit rotation and real-time bandwidth tracking make responsiveness more important. Use `tauri::Emitter` to push state changes to the frontend.

### ~~Settings UI is not wired to the Rust backend~~ — RESOLVED
Resolved in `9f792c9`. Added `get_settings` and `update_settings` Tauri commands. Settings.tsx loads from backend on mount and debounce-saves on change. `SettingsPayload` struct excludes private key. Settings take effect on next `connect()`.

### Duplicate EIP-712 receipt logic across node and client
`client/src-tauri/src/receipts.rs` and `node/src/network/receipts.rs` have near-identical implementations of `compute_domain_separator` and `compute_receipt_digest`. The signing functions differ slightly (`sign_receipt` vs `sign_receipt_digest`) but produce the same output format.

**Files affected:**
- `client/src-tauri/src/receipts.rs`
- `node/src/network/receipts.rs`

**Why deferred:** These are in separate crates with no shared dependency. Sharing requires a workspace-level shared crate (see "Shared crate for node + client types" above).

**When to fix:** With the shared crate migration.

---

## Slashing Oracle (Phase 3)

### ~~Constructor uses require strings instead of custom errors~~ — RESOLVED
Resolved in `9b0ee46`. Constructor now uses `ZeroAddress()` custom error.

### ~~`_verifyFraudSigners` takes 10 parameters~~ — RESOLVED
Resolved: Introduced `FraudReceipt` struct (cumBytes, ts, clientSig, nodeSig). `_verifyBandwidthFraud` decodes into two `FraudReceipt` memory structs. `_verifyFraudSigners` now takes 4 params (nodeId, sessionId, r1, r2) instead of 10.

### ~~`_recoverSigner` duplicated between SlashingOracle and SessionSettlement~~ — RESOLVED
Resolved: Extracted to `contracts/src/lib/EIP712Utils.sol` with `recoverSigner`, `receiptStructHash`, and `hashTypedData`. Both contracts import and use the shared library.

### ~~Missing test: slash proposal for non-existent node~~ — RESOLVED
Resolved in `f3465f3`. Two tests added: proposal succeeds (attestation doesn't check registry), execution reverts at `registry.slash` with "node not found". Documented as expected behavior.

### ~~EIP712Utils.recoverSigner uses require string instead of custom error~~ — RESOLVED
Resolved: Replaced `require` strings with `BadSignatureLength(uint256)` and `InvalidSignature()` custom errors in `EIP712Utils`.

### ~~Attestation domain uses settlement address as verifyingContract~~ — RESOLVED
Resolved: `SlashingOracle` now has a separate `ATTESTATION_DOMAIN_SEPARATOR` using `address(this)` as `verifyingContract`. Receipt verification still uses the `DOMAIN_SEPARATOR` from `SessionSettlement`. `_verifyChallengerAttestation` uses the attestation-specific domain.

---

## Frontend

### ~~Config persistence uses current_dir()~~ — RESOLVED
Resolved: `update_settings` now uses `app.path().app_config_dir()` via Tauri's `AppHandle`. Config saved to OS-appropriate directory.

---

## Crypto Trait Abstractions (Phase 4)

### Client kex.rs duplicates node crypto traits
`client/src-tauri/src/kex.rs` duplicates `node/src/crypto/traits.rs` + `x25519_kem.rs` + `mlkem.rs` + `hybrid.rs`. The client version is a stripped-down subset (no `SecretKey`, no `decapsulate`, `String` errors instead of `CryptoError`). Documented in the file header.

**Why deferred:** No shared crate exists yet. Extracting `shieldnode-crypto` as a workspace member is the proper fix.

**When to fix:** With the shared crate migration (see Architecture section). Highest-priority candidate alongside EIP-712 receipt logic.

### ~~Dual backward-compat accessors on NodeKeyPair~~ — RESOLVED
Resolved: Removed `public_key()` and `secret()` raw dalek accessors. All callers in `main.rs` migrated to `public_key_bytes()` and `secret_kem().to_bytes()`.

### SymmetricCipher trait re-keys per call
`ChaCha20Poly1305Cipher` creates a new cipher instance on every `encrypt`/`decrypt`. The trait is stateless by design (`fn encrypt(key, nonce, plaintext)`).

**Why deferred:** Not in a hot loop currently — used for Sphinx layer encryption (once per hop) and Noise messages. Overhead per call is negligible.

**When to fix:** If this trait is ever used in a per-packet hot path, redesign to accept a pre-keyed cipher instance.

---

## ZK Settlement (Phase 4)

### ~~ZK recipient addresses not verified against commitments~~ — RESOLVED
Resolved: Circuit now outputs `entryPay`, `relayPay`, `exitPay`, `refund` as public signals. `ZKSettlement.sol` reads proven amounts from public signals instead of recomputing the split, and verifies `entryPay + relayPay + exitPay == totalPayment`.

### ~~EIP-712 digest computed off-circuit~~ — RESOLVED
Resolved: EIP-712 digest is now computed entirely in-circuit via two keccak256 calls (~300K constraints, ~9% increase). No external trust required.

### ~~Owner-gated registry root updates~~ — RESOLVED
Resolved: Registry root updates now use a 48-hour timelock via `proposeRegistryRoot()` and `executeRegistryRoot()`. `ROOT_TIMELOCK = 48 hours` enforces the delay. Multisig is still recommended for mainnet.

### ~~RECEIPT_TYPEHASH defined in three places~~ — RESOLVED
Resolved: `RECEIPT_TYPEHASH` now defined once in `EIP712Utils.sol`. Both contracts and test files import `EIP712Utils.RECEIPT_TYPEHASH`.

---

## Frontend (Phase 4 additions)

### Kill switch allows DNS (port 53) outside tunnel
`client/src-tauri/src/kill_switch.rs` explicitly allows UDP port 53 outbound so the client can resolve the RPC endpoint hostname. This means DNS queries leak outside the VPN tunnel, revealing which domains the user resolves.

**Why deferred:** The WireGuard TUN integration is a stub — real tunnel traffic isn't captured yet. Once the TUN device routes all traffic (including DNS) through the tunnel, the port 53 exception can be removed and DNS will be private by default.

**When to fix:** When the TUN device is fully wired. Route DNS through the tunnel, then remove the AllowDNS firewall exception. Alternatively, run a local DNS proxy on localhost that forwards queries through the tunnel.

### ~~Zkey ProvingKey loaded from disk on every proof generation~~ — RESOLVED
Resolved: `ProvingKey` is cached in a module-level `Mutex<Option<(String, Arc<ProvingKey<Bn254>>)>>`. First call loads from disk; subsequent calls return the cached `Arc`. Cache invalidates if the zkey path changes.

### ~~Gas price display units~~ — RESOLVED
Resolved: Backend now returns gas price as `f64` in Gwei. Sub-Gwei values (e.g., 0.15 Gwei) display correctly. Frontend `.toFixed(2)` handles precision.

---

## Anti-Collusion (Phase 4)

### ~~Strict mode for minimum network size guard~~ — RESOLVED
Resolved: `strict_network_size` config field + Settings UI toggle. When enabled and nodes < 20, `connect()` returns error instead of proceeding.

### ~~Node list not cached in AppState~~ — RESOLVED
Resolved: Added `node_list_cache` field to `AppState` with 30-second TTL. `fetch_nodes()` returns cached results on rapid successive calls (UI polling, network health checks) and only refreshes from RPC when the cache expires.

### ~~IPv6 subnet diversity not enforced~~ — RESOLVED
Resolved: Renamed `subnet_24()` to `subnet_prefix()`. Now parses endpoints via `SocketAddr` to handle both IPv4 (/24 prefix from first 3 octets) and IPv6 (/48 prefix from first 3 segments). Bracket notation (`[::1]:port`) is supported. Added IPv6-specific tests.

### No integration test for select_circuit_with_pins with diversity
The 5 diversity tests cover `is_diverse()` and `subnet_24()` in isolation. No test calls `select_circuit_with_pins` with a node pool that has known subnet/ASN collisions and verifies the returned circuit respects them. The `weighted_selection_favors_high_stake` test inadvertently runs under the diversity fallback path because all mock nodes share `127.0.0.1`.

**Why deferred:** Unit tests for `is_diverse` cover the constraint logic. Integration test requires mock nodes with distinct endpoints.

**When to fix:** Phase 5 anti-griefing test suite. Add nodes with varied endpoints to verify end-to-end diversity enforcement.

### ~~rebuild_circuit duplicated between health_monitor and rotation_loop~~ — RESOLVED
Resolved: Extracted `rebuild_circuit()` as a `pub(crate)` function in `lib.rs`. Takes `ChainReader`, exclude list, circuit state, and tunnel manager. Returns selected `NodeInfo` triple so callers can update connection state as needed. Both `health_monitor_loop` and `rotation_loop` now call this shared function.

---

## Anti-Logging (Phase 5)

### TEE enrichment pipeline not wired
`tee_attested` is set to `false` in `map_on_chain_node` and never enriched from any data source. The comment says "enriched by attestation verification" but no call to `verify_attestation` exists in the client, and `OnChainNodeInfo` has no attestation field. The full pipeline (node submits attestation at registration → stored on-chain or via DHT → client reads and verifies → `tee_attested` set to `true`) does not exist.

**Why deferred:** Requires either extending `NodeRegistry.sol` with an attestation hash field, or an off-chain attestation distribution mechanism (libp2p gossipsub). The attestation framework (`attestation.rs`) and scoring integration (`tee_attested` + bonus) are in place — the missing piece is the data path.

**When to fix:** When TEE nodes are ready to deploy. Extend `NodeRegistry.register()` with an optional `attestationHash` parameter, or add a client-side attestation fetch via the DHT.

### ~~TEE_ENTRY_BONUS is dead code~~ — RESOLVED
Resolved: Removed `TEE_ENTRY_BONUS` constant from `attestation.rs`. Position-aware TEE scoring is deferred until TEE nodes exist on the network.

### Client hardcodes TEE scoring bonus
The client's `score_node` in `circuit.rs` hardcodes `20.0` for the TEE bonus. The node crate defines `TEE_SCORE_BONUS = 20.0` in `attestation.rs`. These are currently equal but can silently diverge since the client crate has no dependency on the node crate.

**Why deferred:** Part of the broader shared crate migration (see Architecture section). No mechanism to share constants between node and client without a workspace-level shared crate.

**When to fix:** With the shared crate migration. Move `TEE_SCORE_BONUS` and `TEE_ENTRY_BONUS` to the shared types crate.

### TEE attestation only does structural validation
`verify_attestation` in `attestation.rs` checks report size and binary hash but does not verify hardware signatures. Any node can submit 1200 arbitrary bytes as `report_data` and receive `StructurallyValid`. Full verification requires platform-specific SDKs (sevctl for AMD, Intel DCAP, AWS NSM).

**Why deferred:** Hardware signature verification libraries are platform-specific and add significant dependency complexity. The structural framework is in place; the crypto verification is the last step.

**When to fix:** Before mainnet TEE scoring has real economic impact. Integrate `sev` crate for AMD SEV-SNP verification, or use a remote verification service.

---

## Challenge-Response Protocol (Phase 5)

### ~~Challenge response content not validated~~ — RESOLVED
Resolved: `respondToChallenge()` now rejects `bytes32(0)` responses for `BandwidthVerification` and `PacketIntegrity` challenge types. Full content-aware validation (e.g., ZK-VM proof of forwarding) remains Phase 6 work.

### ~~expireChallenge does not auto-propose slash~~ — RESOLVED
Resolved: `expireChallenge()` now calls `oracle.proposeSlash()` via try/catch. On failure, status is set to `SlashFailed` with a `retrySlash()` function for manual retry. Authorization is verified before the call to fail loudly on misconfigured deployments.

### ~~compute_domain_separator duplicated in Rust (challenge.rs + receipts.rs)~~ — RESOLVED
Resolved: Extracted to `node/src/network/eip712.rs`. Both `challenge.rs` and `receipts.rs` re-export `compute_domain_separator` from the shared module.

### ~~Solidity DOMAIN_SEPARATOR construction duplicated across 4 contracts~~ — RESOLVED
Resolved: Added `EIP712Utils.computeDomainSeparator(address)` to the shared library. `SessionSettlement`, `ZKSettlement`, and `ChallengeManager` constructors now call it. `SlashingOracle` reads from `SessionSettlement` (unchanged).

---

## Crypto — Ratcheting (Phase 5)

### ~~HKDF-SHA256 helper duplicated across 3 crypto files~~ — RESOLVED
Resolved: Extracted `hkdf_sha256::<N>(salt, ikm, info)` to `node/src/crypto/kdf.rs` with const-generic output size. All three callers (`ratchet.rs`, `noise.rs`, `hybrid.rs`) updated.

### ~~No shared control message type registry~~ — RESOLVED
Resolved: Added `node/src/network/control_msg.rs` with `RelayControlType` enum (SessionSetup/Teardown/ReceiptSign), `SphinxControlMagic` enum (RatchetStep/LinkPadding), shared ACK constants, and payload length constants. `relay_listener.rs` uses `RelayControlType::from_byte()`. `ratchet.rs` and `link_padding.rs` use `SphinxControlMagic` for magic bytes. Includes a collision-detection test.

---

## Cover Traffic (Phase 5)

### ~~cover_traffic config field is stringly-typed~~ — RESOLVED
Resolved: `CoverLevel` now derives `Serialize`/`Deserialize` with `#[serde(rename_all = "lowercase")]`. `ClientConfig` and `SettingsPayload` use `CoverLevel` directly. Manual `from_str()` removed.

### COVER_MARKER (0xCC) relies on implicit payload format assumption
Cover packets are identified by the exit node via `payload[0] == 0xCC` after peeling all Sphinx layers. This works because IPv4 headers start with `0x45` (version 4, IHL 5) so real tunnel traffic won't collide. However, the assumption is undocumented and fragile — non-IP payloads, custom protocols, or future Sphinx payload formats could start with `0xCC`.

**Why deferred:** False-positive rate is near-zero for IPv4/IPv6 tunnel traffic. A proper fix requires a structured Sphinx inner header with a reserved `packet_type` field (similar to Nym's approach), which changes the Sphinx payload format.

**When to fix:** When redesigning the Sphinx payload format (e.g., for Phase 6 batching negotiation flags). Add a 1-byte packet type prefix to all Sphinx inner payloads: `0x00` = data, `0x01` = cover, `0x02` = ratchet-step, etc.

---

## Link Padding (Phase 5)

### Rate calculation logic duplicated between link_padding and cover_traffic
`PeerLink::padding_needed()` in `node/src/network/link_padding.rs` and `CoverState::cover_needed()` in `client/src-tauri/src/cover_traffic.rs` are structurally identical: window reset → elapsed_secs → current_pps → deficit → ceil → jitter. Only the jitter range differs (±15% vs ±20%).

**Why deferred:** The two implementations live in different crates (node vs client). Extracting a shared `TrafficRateState` requires either a shared crate or duplicating a small utility. The pattern is simple and correct in both sites.

**When to fix:** With the shared crate migration, or when a third rate-tracking consumer appears. Extract to a `TrafficRateState` struct with configurable jitter range.

### ~~Link padding peer discovery not wired~~ — RESOLVED
Resolved: `RelayListener` now calls `LinkPaddingManager.add_peer()` on SessionSetup and `remove_peer()` on SessionTeardown. The manager and relay listener share an `Arc<tokio::sync::Mutex<LinkPaddingManager>>`, and the relay UDP socket is shared via `Arc<UdpSocket>`.

### ~~AtomicBool stop flag instead of CancellationToken in link_padding_loop~~ — RESOLVED
Resolved: Replaced `Arc<AtomicBool>` with `Arc<tokio::sync::Notify>`. The loop now uses `tokio::select!` to wake immediately on stop notification instead of polling after each sleep interval.

---

## ZK Settlement (Phase 5)

### ~~settlement_mode is stringly-typed (same pattern as cover_traffic)~~ — RESOLVED
Resolved: `SettlementMode` now derives `Serialize`/`Deserialize` with `#[serde(rename_all = "lowercase")]`. `ClientConfig` and `SettingsPayload` use `SettlementMode` directly. Manual `from_str()` removed.

### ZK circuit artifact paths are hardcoded relative paths
`default_artifacts()` in `settlement.rs` uses paths like `circuits/build/circuit.r1cs` relative to the working directory. This has the same unreliability as the old `current_dir()` config persistence bug. Should use `app_data_dir()` from Tauri or make paths configurable via `ClientConfig`.

**Why deferred:** Circuit artifacts don't exist yet in a deployed context — the paths are only meaningful during development. Production deployment will need a proper artifact distribution mechanism (bundled with the app or fetched from a registry).

**When to fix:** When preparing the ZK pipeline for production. Add an `artifacts_path` field to `ClientConfig` or use Tauri's resource directory for bundled artifacts.

### receipt_data parameter unused in ZK settlement path
`settle_session()` takes `receipt_data: Vec<u8>` which is always ABI-encoded before the mode is checked. In ZK mode the receipt_data is unused — the ZK path needs a different witness format. The encoding work is wasted when ZK is configured exclusively.

**Why deferred:** The ZK witness construction isn't wired yet. Once it is, the function signature will need to accept either a plaintext receipt or a ZK witness, not a raw `Vec<u8>`.

**When to fix:** When wiring the full ZK witness construction. Refactor to accept an enum `SettlementData { Plaintext(Vec<u8>), ZkWitness(ReceiptWitness) }` or split into two distinct functions.

---

## CommitmentTree (Phase 6)

### ~~Full-array SLOAD on every insert/remove (~600K gas per mutation)~~ — RESOLVED
Resolved: `CommitmentTree` now stores the full binary tree (1024-slot array, 1-indexed). `_updatePath()` walks from the mutated leaf to the root, updating only 9 internal nodes. `getMerkleProof()` reads siblings directly from storage — no recomputation. Gas per mutation reduced from ~600K to ~O(log n) path updates.

### keccak256 internal nodes incompatible with ZK circuit
CommitmentTree uses keccak256 for internal Merkle tree nodes. The ZK bandwidth receipt circuit uses Poseidon for its registryRoot Merkle proof. These roots will not match — the ZK circuit cannot verify membership against this tree's root. Documented in the contract with a migration note.

**Why deferred:** Poseidon is not available as a Solidity precompile. Implementing Poseidon in Solidity is possible but gas-expensive (~50K gas per hash vs ~30 for keccak256). A Poseidon library contract or a precompile-based approach is the correct path.

**When to fix:** Phase 6 when deploying the ZK-compatible tree. Deploy a Poseidon version alongside, migrate real commitments, update ZKSettlement.registryRoot. Consider using a Poseidon Solidity library (e.g., circomlibjs's Solidity Poseidon) or wait for an EVM Poseidon precompile.

### ~~Deployer-known salt compromises dummy indistinguishability~~ — RESOLVED
Resolved: `initialize()` now mixes the caller-supplied `saltCommitment` with `blockhash(block.number - 1)`, so the effective salt is not reconstructable from calldata alone. VDF or commit-reveal for the input salt is still recommended for mainnet.

---

## ZK Circuits — Shared Templates

### ~~Merkle proof template duplicated across circuits~~ — RESOLVED
Resolved: Extracted `MerkleVerify(DEPTH)` template to `circuits/lib/merkle.circom`. Both `node_eligibility/circuit.circom` and `bandwidth_receipt/circuit.circom` now include and use the shared template instead of inline Merkle traversal loops.

---

## PQ Sphinx (Phase 6)

### PQ Sphinx code duplicated between node and client
`PqSphinxPacket`, `PqSessionKeys`, `PqHopKeys`, `pq_derive_layer_key()`, `pq_compute_mac()`, and `pq_serialize()` are duplicated between `node/src/crypto/sphinx.rs` and `client/src-tauri/src/sphinx.rs`. The client implements creation + serialization only; the node adds peel/deserialization. All shared functions are byte-for-byte identical.

**Why deferred:** No shared crate exists. Part of the broader "shared crate for node + client types" migration (see Architecture section). The duplication is the same pattern as the classic Sphinx and EIP-712 receipt logic.

**When to fix:** With the shared crate migration. Extract `PqSessionKeys`, `PqHopKeys`, `pq_derive_layer_key()`, `pq_compute_mac()`, `pq_serialize()`, and `PqSphinxPacket::create()`/`to_bytes()` into `packages/shieldnode-crypto` or similar shared crate. Node adds peel/deserialize as an extension.

### Client PQ Sphinx uses String errors instead of typed errors
`PqSessionKeys::new()` and `PqSphinxPacket::create()` in the client return `Result<T, String>`. The node equivalents use typed `SphinxError` with `KemFailed`, `EncryptionFailed`, etc. Callers cannot distinguish error types for recovery or display.

**Why deferred:** The entire client Sphinx module (classic and PQ) uses `String` errors, matching the client's `kex.rs` `KeyExchange` trait which also returns `String`. Fixing PQ alone would create inconsistency within the client crate.

**When to fix:** When adding a client-side `SphinxError` enum. Do classic and PQ together. Alternatively, resolves naturally with the shared crate migration if the node's `SphinxError` is used directly.

---

## Contract Structural Patterns (identified April 9, 2026 review)

### ReentrancyGuard, Ownable2Step, PullPayment, Pausable duplicated across contracts
Five contracts each define their own `bool private _locked` + `nonReentrant()` modifier: NodeRegistry, SessionSettlement, ZKSettlement, SlashingOracle, ChallengeManager. Four contracts duplicate the two-step ownership pattern (`owner`, `pendingOwner`, `transferOwnership`, `acceptOwnership`): ZKSettlement, SlashingOracle, Treasury, CommitmentTree. Four contracts duplicate the pull-payment `withdraw()` function. Two contracts duplicate `whenNotPaused` + pause/unpause logic.

**Why deferred:** Each contract works correctly in isolation. Extracting shared base contracts (`contracts/src/lib/ReentrancyGuard.sol`, `Ownable2Step.sol`, `PullPayment.sol`, `Pausable.sol`) touches all contracts and all 157 tests. Better done as a dedicated refactor pass, not mid-feature work.

**When to fix:** Before Phase 5 mainnet launch. Extract lightweight local base contracts (no OpenZeppelin dependency) in `contracts/src/lib/`.

### `banned` mapping redundant with `permanentBan` in NodeRegistry
`NodeRegistry` has both `mapping(bytes32 => bool) public banned` and `mapping(bytes32 => bool) public permanentBan`. Both are set to `true` in `ban()`. The `banned` flag is deleted on `withdrawStake()` while `permanentBan` persists, but `_isActive()` already checks `n.isActive` which `ban()` sets to false. The `!banned[nodeId]` check in `_isActive` is belt-and-suspenders.

**Why deferred:** Removing `banned` requires auditing all callers and tests for the distinction. Low risk — no functional impact, just one extra SLOAD in `_isActive`.

**When to fix:** With the shared base contract extraction pass.

### ZK settlement gas budget needs update
Switching from `keccak256(abi.encode(addr, amount))` to `PoseidonT3.hash(...)` for commitment binding in `ZKSettlement._verifyAndCredit()` adds ~40-60K gas (4 Poseidon hashes). The gas budget in CLAUDE.md and docs says ~250K for ZK settle — should be updated to ~300-310K.

**Why deferred:** Documentation-only change, no functional impact.

**When to fix:** Next documentation pass.

### `MINIMUM_DEPOSIT` and share constants duplicated between SessionSettlement and ZKSettlement
`MINIMUM_DEPOSIT = 0.001 ether`, `ENTRY_SHARE = 25`, `RELAY_SHARE = 25` are defined identically in both contracts. If the split ratio changes, both must be updated.

**Why deferred:** Only two contracts, values are stable. Extracting to `contracts/src/lib/Constants.sol` is trivial but low priority.

**When to fix:** With the shared base contract extraction pass.

---

## Sphinx AEAD Nonce Reuse (identified April 10, 2026 review)

### Static hop_index nonce used for all packets in a session
Both forward-path (`SphinxPacket::create`) and return-path (`wrap_and_send_return`) use `hop_index` (or `hop_index + RETURN_NONCE_OFFSET`) as the AEAD nonce. This nonce is the same for every packet in the session at the same hop — meaning every packet at hop 0 is encrypted with `(session_key_0, nonce=0)`.

ChaCha20-Poly1305 requires unique nonces per encryption under the same key. Reusing `(key, nonce)` with different plaintexts leaks the XOR of plaintexts.

**Why not critical now:** The micro-ratcheting system (Phase 5) rekeys session keys every 30 seconds or 10MB, limiting the nonce-reuse window. Circuit rotation (default 10 minutes) also refreshes keys. An attacker would need to capture traffic AND break the session key within the ratchet window to exploit the XOR leak. The ratcheting system was specifically designed to mitigate this class of issue.

**When to fix:** Before Phase 5 mainnet launch. Replace the static `hop_index` nonce with a per-packet atomic counter per session per hop. Each `SessionState` should maintain a `nonce_counter: AtomicU64` that increments on every encrypt/decrypt. The counter value replaces `hop_index` in the AEAD nonce.

