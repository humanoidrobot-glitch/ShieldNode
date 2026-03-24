# Technical Debt & Deferred Improvements

Items identified during code review that were intentionally deferred. Revisit these as the project matures beyond Phase 1.

---

## Architecture

### Shared crate for node + client types
The node (`node/src/`) and client (`client/src-tauri/src/`) both define overlapping types (`NodeInfo`, scoring logic, hex parsing, alloy sol! ABIs). These should be extracted into a shared `packages/shieldnode-types/` crate that both consume.

**Why deferred:** Adds build complexity (workspace setup, cross-crate dependencies). Acceptable while both crates are evolving rapidly.

**When to fix:** Before Phase 2, when multi-hop circuits require the node and client to agree on packet formats and scoring.

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

### Session ID parsing fragility
`wallet.rs` parses the session ID from the first log's second topic without verifying the event signature hash. If the contract emits other events before `SessionOpened`, this will extract the wrong value.

**Why deferred:** Current contract only emits `SessionOpened` in `openSession()`. No ambiguity today.

**When to fix:** Before mainnet (Phase 5). Add event signature hash check: `topic[0] == keccak256("SessionOpened(uint256,address,bytes32[3],uint256)")`.

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

### Settings UI is not wired to the Rust backend
All fields in `Settings.tsx` (`rpcEndpoint`, `autoRotate`, `rotationIntervalMin`, `killSwitch`, `gasCeiling`) are local React state only. Changing them has no effect on the Rust `ClientConfig` — no Tauri commands exist to update config at runtime. The rotation loop reads `auto_rotate` and `circuit_rotation_interval_secs` from `AppState.config` at connect time, so UI changes are silently ignored.

**Files affected:**
- `client/src/components/Settings.tsx` — all settings are local state
- `client/src-tauri/src/config.rs` — `ClientConfig` has no Tauri command to update it
- `client/src-tauri/src/lib.rs` — no `update_config` handler registered

**Why deferred:** Wiring all settings requires a new `update_config` Tauri command, validation, and deciding whether changes take effect immediately or on next connect. The current UI communicates intent even if it doesn't persist.

**When to fix:** Phase 3–4, when users need to meaningfully control rotation intervals and gas ceilings. Add an `update_settings` Tauri command that writes to `AppState.config` and optionally persists to disk via `ClientConfig::save()`.

### Duplicate EIP-712 receipt logic across node and client
`client/src-tauri/src/receipts.rs` and `node/src/network/receipts.rs` have near-identical implementations of `compute_domain_separator` and `compute_receipt_digest`. The signing functions differ slightly (`sign_receipt` vs `sign_receipt_digest`) but produce the same output format.

**Files affected:**
- `client/src-tauri/src/receipts.rs`
- `node/src/network/receipts.rs`

**Why deferred:** These are in separate crates with no shared dependency. Sharing requires a workspace-level shared crate (see "Shared crate for node + client types" above).

**When to fix:** With the shared crate migration.

---

## Slashing Oracle (Phase 3)

### Constructor uses require strings instead of custom errors
`SlashingOracle.sol` constructor (lines 137–139) uses `require(_registry != address(0), "string")` for zero-address checks while the rest of the contract uses custom errors. Inconsistent but constructor-only — not on any hot path.

**Why deferred:** Constructor runs once at deployment. Gas savings from custom errors are negligible here.

**When to fix:** Next contract refactor pass or before mainnet deployment audit.

### `_verifyFraudSigners` takes 10 parameters
The function accepts 10 individual parameters due to stack-too-deep constraints. A `FraudReceipt` struct would reduce this to 3 params (nodeId, sessionId, two receipt structs) and improve readability.

**Why deferred:** Requires `via_ir` regardless due to the nested decode. The struct refactor alone doesn't eliminate the need for the function split.

**When to fix:** When `via_ir` can be removed (e.g., if Solidity compiler improves stack handling) or during mainnet audit prep.

### `_recoverSigner` duplicated between SlashingOracle and SessionSettlement
Both contracts implement identical ECDSA signature recovery (assembly-based `r`/`s`/`v` extraction + `ecrecover`). The only difference is the error type (custom error vs require string).

**Why deferred:** Creating a shared Solidity library requires choosing one error convention and updating both consumers. Part of the broader "shared types" migration.

**When to fix:** Before mainnet deployment. Extract into a `library EIP712Utils`.

### Missing test: slash proposal for non-existent node
`proposeSlash` with an unregistered `nodeId` passes attestation verification (which doesn't check registry) but `executeSlash` would call `registry.slash` on a zero-stake entry. The behaviour is undefined/untested.

**Why deferred:** Edge case unlikely in practice — challengers must be authorized and would not target non-existent nodes.

**When to fix:** Before Phase 5. Add a test and either add a registry existence check in `proposeSlash` or document the expected behaviour.

### Attestation domain uses settlement address as verifyingContract
`DOMAIN_SEPARATOR` uses the SessionSettlement address as `verifyingContract` for both receipt signatures (correct) and attestation signatures (semantically wrong — attestations are oracle-native). Wallets will show the settlement address when signing attestations, which is confusing. Low real-world impact since `SlashAttestation` has a distinct typehash.

**Why deferred:** Adding a second domain separator doubles complexity. The distinct typehash prevents cross-type confusion.

**When to fix:** Phase 6 when decentralising the challenge system. Attestations should use their own domain with `address(this)`.

---

## Frontend

### Gas price display units
The Rust backend returns gas price as `u64` in Gwei. The frontend displays it directly. If gas is sub-1-Gwei (common on Sepolia), it shows as 0.

**Why deferred:** Cosmetic issue. Sepolia gas is effectively free.

**When to fix:** Phase 4, when gas price awareness becomes a real UX feature for mainnet users. Return as `f64` or use wei with frontend conversion.
