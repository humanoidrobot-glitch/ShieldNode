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

### Sphinx MAC is a placeholder
The `mac` field in `SphinxHeader` uses a weak binding tag (first 32 bytes of payload) instead of HMAC-SHA256. Packet tampering is not detected.

**Why deferred:** Placeholder since initial scaffold. Does not affect correctness in a trusted test environment.

**When to fix:** Before Phase 5 mainnet launch. Implement HMAC-SHA256 over the full header.

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

### `_recoverSigner` duplicated between SlashingOracle and SessionSettlement
Both contracts implement identical ECDSA signature recovery (assembly-based `r`/`s`/`v` extraction + `ecrecover`). The only difference is the error type (custom error vs require string).

**Why deferred:** Creating a shared Solidity library requires choosing one error convention and updating both consumers. Part of the broader "shared types" migration.

**When to fix:** Before mainnet deployment. Extract into a `library EIP712Utils`.

### ~~Missing test: slash proposal for non-existent node~~ — RESOLVED
Resolved in `f3465f3`. Two tests added: proposal succeeds (attestation doesn't check registry), execution reverts at `registry.slash` with "node not found". Documented as expected behavior.

### Attestation domain uses settlement address as verifyingContract
`DOMAIN_SEPARATOR` uses the SessionSettlement address as `verifyingContract` for both receipt signatures (correct) and attestation signatures (semantically wrong — attestations are oracle-native). Wallets will show the settlement address when signing attestations, which is confusing. Low real-world impact since `SlashAttestation` has a distinct typehash.

**Why deferred:** Adding a second domain separator doubles complexity. The distinct typehash prevents cross-type confusion.

**When to fix:** Phase 6 when decentralising the challenge system. Attestations should use their own domain with `address(this)`.

---

## Frontend

### Config persistence uses current_dir()
`update_settings` in `lib.rs` saves to `std::env::current_dir().join("shieldnode-client.json")`. The working directory is unpredictable at runtime — it depends on how the binary is launched. Should use Tauri's `app_config_dir()` for the OS-appropriate user config directory.

**Why deferred:** Requires threading `AppHandle` through to the `update_settings` command, which is a structural change to how the function accesses Tauri APIs.

**When to fix:** Before Phase 5. Use `app.path().app_config_dir()` from Tauri v2 path API.

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

### ZK recipient addresses not verified against commitments
`ZKSettlement.settleWithProof()` accepts `entryAddr`, `relayAddr`, `exitAddr`, `refundAddr` as plain parameters but does not verify they match the Poseidon commitments in the proof's public signals. A caller could submit a valid proof but route payments to different addresses.

**Why deferred:** Poseidon hashes cannot be verified on-chain with keccak256. Fixing requires either: (a) a Poseidon precompile/library on-chain, (b) making individual payment amounts public signals and having the contract compute commitments, or (c) redesigning the circuit to output addresses as public signals.

**When to fix:** Before Phase 5 mainnet launch. Option (b) is the most practical — add `entryPay`, `relayPay`, `exitPay`, `refundAmount` as public circuit outputs and verify the split on-chain against those values.

### ~~EIP-712 digest computed off-circuit~~ — RESOLVED
Resolved: EIP-712 digest is now computed entirely in-circuit via two keccak256 calls (~300K constraints, ~9% increase). No external trust required.

### Owner-gated registry root updates
`ZKSettlement.updateRegistryRoot()` uses a simple `owner == msg.sender` check. Single point of failure for registry root integrity.

**Why deferred:** Documented as temporary in the contract. The proper fix is reading the Merkle root directly from NodeRegistry (requires NodeRegistry to maintain a Poseidon Merkle tree of registered nodes).

**When to fix:** Phase 5, alongside the mainnet security audit. Add timelock + multisig at minimum.

### RECEIPT_TYPEHASH defined in three places
The EIP-712 `BandwidthReceipt` typehash is independently defined in `SessionSettlement.sol`, `SessionSettlement.t.sol`, and referenced by the circuit. Any change to the receipt structure requires updating all three (plus the circuit).

**Why deferred:** The typehash is a stable protocol constant unlikely to change. Extracting to a shared library saves ~2 lines per consumer.

**When to fix:** Before mainnet. Extract to a shared `SettlementConstants` library or interface.

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

### Gas price display units
The Rust backend returns gas price as `u64` in Gwei. The frontend displays it directly. If gas is sub-1-Gwei (common on Sepolia), it shows as 0.

**Why deferred:** Cosmetic issue. Sepolia gas is effectively free.

**When to fix:** Phase 4, when gas price awareness becomes a real UX feature for mainnet users. Return as `f64` or use wei with frontend conversion.
