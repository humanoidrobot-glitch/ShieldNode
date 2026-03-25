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

### Alloy provider caching
Every RPC call (node reads, gas price, session open/settle) constructs a new alloy HTTP provider, which involves URL parsing and HTTP client setup.

**Files affected:**
- `client/src-tauri/src/chain.rs` — `get_active_nodes()`, `get_gas_price()`
- `client/src-tauri/src/wallet.rs` — `open_session()`, `settle_session()`, `get_gas_price()`
- `node/src/network/chain.rs` — `register()`, `heartbeat()`, `update_endpoint()`

**Why deferred:** Overhead is negligible for current call frequency (once per connect, every 30s for gas). Caching requires `Arc` or `OnceCell` restructuring of `AppState`.

**When to fix:** Phase 4 stress testing, or if RPC latency becomes noticeable.

### Sequential node fetches in get_active_nodes
`client/src-tauri/src/chain.rs` calls `getNode()` sequentially for each active node ID. For N nodes, this is N serial RPC round trips.

**Why deferred:** Registry has <10 nodes currently. Serial fetches take <1s.

**When to fix:** When registry grows past ~50 nodes. Use `futures::future::join_all` to parallelize.

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

### Hex parsing implementations
Three separate hex-to-bytes32 functions exist:
- `node/src/main.rs` `parse_hex_private_key()` — uses `hex` crate
- `client/src-tauri/src/wallet.rs` `parse_bytes32()` — manual parsing, returns `FixedBytes`
- `client/src-tauri/src/lib.rs` `decode_hex_32()` — manual parsing, returns `[u8; 32]`, silent failure

**Why deferred:** Each has slightly different error handling needs (strict vs lenient). Consolidation requires deciding on a single error strategy.

**When to fix:** With the shared crate migration. Use the `hex` crate everywhere.

### Custom hex encoding in chain.rs
`client/src-tauri/src/chain.rs` has a hand-rolled `hex::encode` module instead of using the `hex` crate.

**Why deferred:** Avoids adding another dependency to the client crate. The implementation is 12 lines and correct.

**When to fix:** When `hex` crate is added as a dependency (already available transitively via alloy).

---

## Multi-Hop Relay (Phase 2)

### Relay Mutex lock per packet
`relay_listener.rs` acquires `Arc<Mutex<RelayService>>` on every incoming relay packet. Under high packet rates this becomes a bottleneck.

**Why deferred:** Acceptable throughput for Phase 2 testing with <10 nodes. Lock hold time is minimal (HashMap lookup + crypto peel).

**When to fix:** Phase 4 stress testing. Replace with `RwLock` or `DashMap` for concurrent session lookups.

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

### `_verifyFraudSigners` takes 10 parameters
The function accepts 10 individual parameters due to stack-too-deep constraints. A `FraudReceipt` struct would reduce this to 3 params (nodeId, sessionId, two receipt structs) and improve readability.

**Why deferred:** Requires `via_ir` regardless due to the nested decode. The struct refactor alone doesn't eliminate the need for the function split.

**When to fix:** When `via_ir` can be removed (e.g., if Solidity compiler improves stack handling) or during mainnet audit prep.

### ~~`_recoverSigner` duplicated between SlashingOracle and SessionSettlement~~ — RESOLVED
Resolved: Extracted to `contracts/src/lib/EIP712Utils.sol` with `recoverSigner`, `receiptStructHash`, and `hashTypedData`. Both contracts import and use the shared library.

### ~~Missing test: slash proposal for non-existent node~~ — RESOLVED
Resolved in `f3465f3`. Two tests added: proposal succeeds (attestation doesn't check registry), execution reverts at `registry.slash` with "node not found". Documented as expected behavior.

### EIP712Utils.recoverSigner uses require string instead of custom error
`EIP712Utils.recoverSigner` uses `require(sig.length == 65, "EIP712: bad sig length")`. The `SlashingOracle` previously used `revert InvalidEvidence("bad sig length")` — a custom error that is cheaper in gas and pattern-matchable by off-chain tools. The shared library chose `require` strings for simplicity since both contracts had different error conventions.

**Why deferred:** No test catches the error type difference. Gas impact is negligible for a failure path.

**When to fix:** During mainnet audit prep. Add a custom `EIP712Error` to the library if auditors flag it.

### Attestation domain uses settlement address as verifyingContract
`DOMAIN_SEPARATOR` uses the SessionSettlement address as `verifyingContract` for both receipt signatures (correct) and attestation signatures (semantically wrong — attestations are oracle-native). Wallets will show the settlement address when signing attestations, which is confusing. Low real-world impact since `SlashAttestation` has a distinct typehash.

**Why deferred:** Adding a second domain separator doubles complexity. The distinct typehash prevents cross-type confusion.

**When to fix:** Phase 6 when decentralising the challenge system. Attestations should use their own domain with `address(this)`.

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

### Dual backward-compat accessors on NodeKeyPair
`node/src/crypto/keys.rs` exposes parallel accessor pairs: `public_key()` / `public_key_kem()`, `secret()` / `secret_kem()`. The raw dalek-typed accessors exist for callers that haven't migrated to trait types.

**Why deferred:** `main.rs` and `noise.rs` still use the dalek types in some paths.

**When to fix:** When all callers are migrated to trait-based types, remove the raw dalek accessors.

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

### Owner-gated registry root updates
`ZKSettlement.updateRegistryRoot()` uses a simple `owner == msg.sender` check. Single point of failure for registry root integrity.

**Why deferred:** Documented as temporary in the contract. The proper fix is reading the Merkle root directly from NodeRegistry (requires NodeRegistry to maintain a Poseidon Merkle tree of registered nodes).

**When to fix:** Phase 5, alongside the mainnet security audit. Add timelock + multisig at minimum.

### ~~RECEIPT_TYPEHASH defined in three places~~ — RESOLVED
Resolved: `RECEIPT_TYPEHASH` now defined once in `EIP712Utils.sol`. Both contracts and test files import `EIP712Utils.RECEIPT_TYPEHASH`.

---

## Frontend (Phase 4 additions)

### Kill switch allows DNS (port 53) outside tunnel
`client/src-tauri/src/kill_switch.rs` explicitly allows UDP port 53 outbound so the client can resolve the RPC endpoint hostname. This means DNS queries leak outside the VPN tunnel, revealing which domains the user resolves.

**Why deferred:** The WireGuard TUN integration is a stub — real tunnel traffic isn't captured yet. Once the TUN device routes all traffic (including DNS) through the tunnel, the port 53 exception can be removed and DNS will be private by default.

**When to fix:** When the TUN device is fully wired. Route DNS through the tunnel, then remove the AllowDNS firewall exception. Alternatively, run a local DNS proxy on localhost that forwards queries through the tunnel.

### Zkey ProvingKey loaded from disk on every proof generation
`client/src-tauri/src/zk_prove.rs` reads and parses the zkey file (~100MB for a 3.5M constraint circuit) on every `generate_proof()` call. The `ProvingKey<Bn254>` is immutable after loading.

**Why deferred:** Proving happens once per session disconnect. Single load is acceptable for current usage.

**When to fix:** If batch settlements or retry logic make multiple proofs common. Cache the `ProvingKey` in `AppState` via `Arc<OnceCell<ProvingKey<Bn254>>>`.

### ~~Gas price display units~~ — RESOLVED
Resolved: Backend now returns gas price as `f64` in Gwei. Sub-Gwei values (e.g., 0.15 Gwei) display correctly. Frontend `.toFixed(2)` handles precision.

---

## Anti-Collusion (Phase 4)

### ~~Strict mode for minimum network size guard~~ — RESOLVED
Resolved: `strict_network_size` config field + Settings UI toggle. When enabled and nodes < 20, `connect()` returns error instead of proceeding.

### Node list not cached in AppState
`fetch_nodes()` calls `get_active_nodes()` via RPC on every invocation. Both `get_nodes` (UI) and `get_network_health` issue full RPC calls. If the UI polls frequently, this is wasteful.

**Why deferred:** Node list changes slowly (heartbeats every 6 hours). Current call frequency is low (on connect, on rotation).

**When to fix:** When UI polling is added for network health display. Cache node list in `AppState` with 30-60s TTL, similar to the completion rates cache.

### IPv6 subnet diversity not enforced
`subnet_24()` in `circuit.rs` only handles IPv4 dotted-quad endpoints. IPv6 endpoints (e.g., `[2001:db8::1]:51820`) return `None` from `subnet_24()`, silently skipping subnet diversity for IPv6 nodes. Two IPv6 nodes on the same /48 would not be detected.

**Why deferred:** No IPv6 nodes exist on the current testnet. The fallback is safe — `None` comparisons never match, so IPv6 nodes pass diversity unchecked rather than being incorrectly blocked.

**When to fix:** When IPv6 nodes appear on the network. Add a `subnet_48()` helper for IPv6 and handle bracket notation in endpoint parsing.

### No integration test for select_circuit_with_pins with diversity
The 5 diversity tests cover `is_diverse()` and `subnet_24()` in isolation. No test calls `select_circuit_with_pins` with a node pool that has known subnet/ASN collisions and verifies the returned circuit respects them. The `weighted_selection_favors_high_stake` test inadvertently runs under the diversity fallback path because all mock nodes share `127.0.0.1`.

**Why deferred:** Unit tests for `is_diverse` cover the constraint logic. Integration test requires mock nodes with distinct endpoints.

**When to fix:** Phase 5 anti-griefing test suite. Add nodes with varied endpoints to verify end-to-end diversity enforcement.

### rebuild_circuit duplicated between health_monitor and rotation_loop
`health_monitor.rs::rebuild_circuit()` and `lib.rs::rotation_loop()` perform nearly identical 7-step rebuild sequences: fetch nodes → select circuit → build circuit → register sessions → reconnect tunnel → swap state → update connection. ~50 lines of duplicated logic.

**Why deferred:** Both callers have slightly different error handling and context. Extracting a shared helper requires passing 5+ `Arc<Mutex>` params.

**When to fix:** When either path is extended (e.g., adding completion rate enrichment to rebuilds). Extract a `rebuild_circuit_internal()` helper callable from both.

---

## Anti-Logging (Phase 5)

### TEE enrichment pipeline not wired
`tee_attested` is set to `false` in `map_on_chain_node` and never enriched from any data source. The comment says "enriched by attestation verification" but no call to `verify_attestation` exists in the client, and `OnChainNodeInfo` has no attestation field. The full pipeline (node submits attestation at registration → stored on-chain or via DHT → client reads and verifies → `tee_attested` set to `true`) does not exist.

**Why deferred:** Requires either extending `NodeRegistry.sol` with an attestation hash field, or an off-chain attestation distribution mechanism (libp2p gossipsub). The attestation framework (`attestation.rs`) and scoring integration (`tee_attested` + bonus) are in place — the missing piece is the data path.

**When to fix:** When TEE nodes are ready to deploy. Extend `NodeRegistry.register()` with an optional `attestationHash` parameter, or add a client-side attestation fetch via the DHT.

### TEE_ENTRY_BONUS is dead code
`TEE_ENTRY_BONUS` (10.0) is defined in `node/src/network/attestation.rs` but never referenced anywhere. The client's `score_node` applies the general TEE bonus (20.0) but does not apply position-specific preference — the same score is used for all three hop positions. Entry nodes (most sensitive — see client IP) should preferentially be TEE-attested.

**Why deferred:** Position-aware scoring requires changing `select_circuit_with_pins` to pass the hop position to `score_node`, or applying a post-selection bonus/filter for the entry slot. Moderate refactor.

**When to fix:** When TEE nodes exist on the network. Add a position parameter to scoring or a post-selection filter that rerolls the entry slot if a TEE candidate is available.

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

### Challenge response content not validated
`ChallengeManager.respondToChallenge()` only verifies the EIP-712 signer matches the node operator. It does NOT validate the `responseHash` content — a node can sign any hash and pass. For `BandwidthVerification` the node should prove forwarding; for `PacketIntegrity` the response should match `challengeData`. Currently all challenge types accept any signed response.

**Why deferred:** v1 is a signer-only liveness gate — proving the node operator is online and has key access. Content verification requires type-specific validation logic (e.g., ZK-VM proof for packet forwarding) which is Phase 6 work.

**When to fix:** Phase 6 when ZK-VM proof of correct forwarding is implemented. Add type-specific validation dispatching in `respondToChallenge()`.

### expireChallenge does not auto-propose slash
`expireChallenge()` marks a challenge as `Expired` and emits `ChallengeExpired`, but does not automatically call `SlashingOracle.proposeSlash()`. The challenger must manually file a slash proposal using the expiration as evidence. If the challenger goes offline, unresponsive nodes face no penalty.

**Why deferred:** Intentional decoupling — challenge lifecycle and slashing are separate concerns. Auto-slash would create tight coupling between ChallengeManager and SlashingOracle's evidence encoding format.

**When to fix:** Add a `SlashReason.ChallengeUnresponded` to the SlashingOracle, or allow ChallengeManager to call `proposeSlash()` directly with a pre-encoded evidence blob. Consider adding a bot that watches `ChallengeExpired` events and auto-files slash proposals.

### compute_domain_separator duplicated in Rust (challenge.rs + receipts.rs)
Both `node/src/network/challenge.rs` and `node/src/network/receipts.rs` implement identical `compute_domain_separator()` functions (~18 lines each). Same ABI encoding pattern with the same domain name, version, and layout.

**Why deferred:** Part of the broader shared module extraction. Both files are in the same crate so extraction is straightforward but low priority.

**When to fix:** Extract to a shared `node/src/network/eip712.rs` utility module. Both callers import from there.

### Solidity DOMAIN_SEPARATOR construction duplicated across 4 contracts
`SessionSettlement`, `ZKSettlement`, `SlashingOracle`, and `ChallengeManager` all construct their EIP-712 DOMAIN_SEPARATOR with identical code (~8 lines each). Each uses a different `verifyingContract` (their own address), so the values differ, but the construction pattern is copy-pasted.

**Why deferred:** Each contract genuinely needs a different DOMAIN_SEPARATOR (different `verifyingContract`). A shared `computeDomainSeparator()` in `EIP712Utils` would save ~5 lines per contract but adds a function call in the constructor. Low ROI.

**When to fix:** Optional cleanup during audit prep. Add `EIP712Utils.computeDomainSeparator(string name, string version)` and have each constructor call it.

---

## Crypto — Ratcheting (Phase 5)

### HKDF-SHA256 helper duplicated across 3 crypto files
`ratchet.rs::derive_keys`, `noise.rs::derive_session_key`, and `hybrid.rs::combine_shared_secrets` all instantiate `Hkdf::<Sha256>` with the same pattern (new → expand → expect). A shared `fn hkdf_sha256(ikm, salt, info) -> [u8; 32]` would eliminate this.

**Why deferred:** Each call site has slightly different parameters (salt, info, output size). Extracting a shared helper requires a flexible signature (optional salt, variable output length).

**When to fix:** Extract to `node/src/crypto/kdf.rs` or add to an existing shared module. Low priority — the pattern is correct in all three sites.

### No shared control message type registry
Relay listener uses 1-byte discriminants (`0x01` SESSION_SETUP, `0x02` TEARDOWN, `0x03` RECEIPT_SIGN). Ratchet uses a 4-byte ASCII magic (`RATC`). These are independent ad-hoc schemes with no shared enum or framing layer. If messages ever share a transport, collisions are possible.

**Why deferred:** Messages currently travel on different channels (Sphinx payload vs raw relay socket). No functional conflict.

**When to fix:** When adding more control message types (cover traffic flags, batching negotiation). Define a `ControlMessageType` enum or a canonical framing header used by all control messages.

---

## Cover Traffic (Phase 5)

### cover_traffic config field is stringly-typed
`ClientConfig.cover_traffic` and `SettingsPayload.cover_traffic` are `String` ("off"/"low"/"high"). `CoverLevel` is a proper Rust enum but conversion happens only at the point of use via `CoverLevel::from_str()`, which silently maps invalid values to `Off`. Invalid config values like typos survive serialization and disk persistence without error.

**Why deferred:** Switching to `CoverLevel` as the config type requires `#[serde(rename_all = "lowercase")]` on the enum, a config migration for existing saved files, and updating the TypeScript `<select>` value handling.

**When to fix:** Next config schema cleanup. Derive `Serialize`/`Deserialize` on `CoverLevel` directly and store the enum. Implement `FromStr` trait (with `Result` return) instead of the current infallible `from_str` method that shadows the trait name.

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

### Link padding peer discovery not wired
`LinkPaddingManager.add_peer()`/`remove_peer()` are never called from the relay forwarding code. The manager starts with zero peers and produces no padding even when `link_padding_enabled = true`. The relay listener needs to register peers when hop-to-hop connections are established and remove them on teardown.

**Why deferred:** Documented with a TODO on the struct. Wiring requires changes to relay.rs session management to notify the padding manager of active peer links.

**When to fix:** When integrating link padding into the live relay pipeline. Add `add_peer`/`remove_peer` calls in relay session setup/teardown.

### AtomicBool stop flag instead of CancellationToken in link_padding_loop
`link_padding_loop` uses `AtomicBool` with `Relaxed` ordering for the stop signal. The node crate doesn't depend on `tokio-util` (which provides `CancellationToken`). The `AtomicBool` pattern requires the loop to finish its current sleep before observing the stop, whereas `CancellationToken` with `tokio::select!` wakes immediately.

**Why deferred:** Adding `tokio-util` to the node crate just for `CancellationToken` is a dependency overhead. The `AtomicBool` pattern works correctly — worst case is one extra 100ms iteration before stop.

**When to fix:** If `tokio-util` is added to the node crate for other reasons. Or replace with a `tokio::sync::Notify` which is already available via tokio.
