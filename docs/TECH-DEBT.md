# Technical Debt & Deferred Improvements

Items identified during code review that were intentionally deferred. Revisit these as the project matures beyond Phase 1.

---

## Architecture

### Shared crate for node + client types
The node (`node/src/`) and client (`client/src-tauri/src/`) both define overlapping types (`NodeInfo`, scoring logic, hex parsing, alloy sol! ABIs). These should be extracted into a shared `packages/shieldnode-types/` crate that both consume.

**Why deferred:** Adds build complexity (workspace setup, cross-crate dependencies). Acceptable while both crates are evolving rapidly.

**When to fix:** Before Phase 2, when multi-hop circuits require the node and client to agree on packet formats and scoring.

### Node scoring algorithm divergence
The Rust backend (`client/src-tauri/src/circuit.rs`) and TypeScript frontend (`client/src/lib/scoring.ts`) implement the same scoring algorithm with different weights and normalization. They will select different nodes.

**Why deferred:** Phase 1 uses single-hop with mock/minimal nodes. Divergence doesn't matter yet.

**When to fix:** Phase 2, when circuit selection is live. Canonicalize in the Rust backend and have the frontend display the backend's score.

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

### Dummy settle signatures
`client/src-tauri/src/wallet.rs` `settle_session()` sends 65-byte zero vectors as client and node signatures. This will cause the `settleSession` contract to revert on signature verification.

**Why deferred:** Phase 1 focuses on the open/connect flow. Real settlement requires EIP-712 co-signing between client and node, which is a Phase 2 feature (bandwidth receipt co-signing).

**When to fix:** Phase 2, alongside bandwidth receipt implementation.

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

**When to fix:** With the shared crate migration before Phase 3.

### Next-hop address encoding lacks bidirectional codec
`relay_listener.rs` parses next-hop as `[4-byte IPv4][2-byte port][26 unused]`. No corresponding encoder exists for building next-hop bytes from (IP, port). Client will need this when wiring live traffic.

**Why deferred:** Will be built as part of the "live traffic wiring" Phase 2 remaining item.

**When to fix:** Next Phase 2 sprint — wire client Sphinx packet construction with proper next-hop encoding.

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

### Gas price display units
The Rust backend returns gas price as `u64` in Gwei. The frontend displays it directly. If gas is sub-1-Gwei (common on Sepolia), it shows as 0.

**Why deferred:** Cosmetic issue. Sepolia gas is effectively free.

**When to fix:** Phase 4, when gas price awareness becomes a real UX feature for mainnet users. Return as `f64` or use wei with frontend conversion.
