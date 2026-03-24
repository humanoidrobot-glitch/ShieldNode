# ShieldNode

A decentralized, cryptoeconomically-secured VPN built natively on Ethereum L1. No L2 compromises, no multisig exit risk, no trust assumptions beyond Ethereum consensus itself.

## Why Ethereum L1?

Post-Fusaka Ethereum averages <0.2 Gwei gas (~$0.01 per transaction). There is no economic reason to use an L2, and every L2 introduces trust assumptions (Security Council overrides, missing exit windows, upgradeable bridges) that contradict the core promise: **your VPN should be as trustless as the chain it runs on.**

ShieldNode inherits Ethereum's security directly. Every on-chain operation (node registration, session settlement, slashing) happens on mainnet. Users can verify everything on Etherscan.

## How It Works

```
                          Ethereum L1
                    ┌──────────────────────┐
                    │  NodeRegistry.sol     │
                    │  SessionSettlement.sol│
                    │  SlashingOracle.sol   │
                    │  Treasury.sol         │
                    └──────────┬───────────┘
                               │ staking, heartbeats,
                               │ session open/settle
         ┌─────────────────────┼─────────────────────┐
         │                     │                      │
    ┌────▼────┐          ┌─────▼─────┐          ┌─────▼─────┐
    │  Entry  │◄────────►│   Relay   │◄────────►│   Exit    │
    │  Node   │  onion   │   Node    │  onion   │   Node    │
    └────▲────┘ encrypted└───────────┘ encrypted└─────┬─────┘
         │                                            │
    ┌────┴────┐                                  ┌────▼────┐
    │  Client │                                  │ Internet│
    │  (Tauri)│                                  └─────────┘
    └─────────┘
```

**Multi-hop onion routing** ensures no single node can see both source and destination:
- The **entry node** knows the client IP but not the destination
- The **relay node** knows neither
- The **exit node** knows the destination but not the client

Each relay peels one layer of Sphinx-style encryption, sees only the next hop, and forwards. Session keys are ephemeral X25519 Diffie-Hellman, and all encryption uses ChaCha20-Poly1305.

## Architecture

### Relay Node (Rust)

The node binary that independent operators run. Located in `node/`.

| Module | Purpose |
|--------|---------|
| `tunnel/wireguard.rs` | WireGuard tunnel via boringtun (userspace, cross-platform) |
| `tunnel/circuit.rs` | Circuit lifecycle, pure `process_relay_packet` function (ZK-provable) |
| `crypto/aead.rs` | Shared ChaCha20-Poly1305 encrypt/decrypt helpers |
| `crypto/sphinx.rs` | Sphinx onion packet creation and layer peeling |
| `crypto/keys.rs` | X25519 keypair management, ephemeral DH sessions |
| `crypto/noise.rs` | Noise NK-pattern handshake, HKDF-SHA256 key derivation |
| `network/discovery.rs` | libp2p Kademlia DHT + Gossipsub peer discovery |
| `network/heartbeat.rs` | Periodic on-chain heartbeat for liveness proofs |
| `network/relay.rs` | Packet forwarding with bandwidth tracking, session key zeroization |
| `metrics/bandwidth.rs` | Per-session byte counting with O(1) running totals |
| `metrics/api.rs` | HTTP API (axum): `/health`, `/metrics`, `/sessions` |
| `config.rs` | TOML configuration with sane defaults |

Key design decisions:
- **No logging by design** — the node software has no mechanism to record connection metadata
- **Relay forwarding is a pure function** — deterministic, no side effects, structured for future ZK proof generation
- **Session keys are zeroized on drop** — sensitive material doesn't linger in memory

### Smart Contracts (Solidity)

All contracts deploy to Ethereum L1. Located in `contracts/`.

#### `NodeRegistry.sol`
Operators register by staking a minimum 0.1 ETH. The registry tracks public keys, endpoints, stake amounts, heartbeat freshness, and slash history. Paginated `getActiveNodes()` supports efficient client-side circuit selection. Includes a `commitment` field (unused until Phase 6) for future ZK eligibility proofs.

#### `SessionSettlement.sol`
Clients open sessions with a prepaid ETH deposit. During the session, bandwidth consumption is tracked off-chain with EIP-712 signed receipts co-signed by both client and nodes. Settlement distributes payment using a 25/25/50 split (entry/relay/exit) — exit nodes earn double because they bear more risk and bandwidth. Force-settlement lets nodes claim payment if the client disappears.

#### `SlashingOracle.sol`
Authorized challengers can propose slashing for provable logging, selective denial, or bandwidth fraud. Progressive slashing escalates from 10% to 25% to 100% + permanent ban. Slash proceeds are split 50/50 between challenger and treasury.

#### `Treasury.sol`
Receives slashed stake. Withdrawals are gated by a 48-hour timelock.

**Gas costs at 0.2 Gwei:**

| Operation | Estimated Gas | Cost |
|-----------|--------------|------|
| Node registration | ~150,000 | ~$0.06 |
| Heartbeat | ~50,000 | ~$0.02 |
| Open session | ~100,000 | ~$0.04 |
| Settle session | ~120,000 | ~$0.05 |
| Slash proposal | ~200,000 | ~$0.08 |

### Client Application (Planned)

A Tauri (Rust + React) desktop app. Core tunnel logic in Rust, UI in TypeScript. Reads the node registry directly from L1, scores nodes by uptime/stake/latency/price, constructs 3-hop circuits, and manages session lifecycle. One toggle to connect.

## Project Structure

```
shieldnode/
├── node/                          # Rust relay node
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs                # CLI, config loading, metrics server
│       ├── config.rs              # TOML config with defaults
│       ├── tunnel/
│       │   ├── wireguard.rs       # boringtun WireGuard integration
│       │   └── circuit.rs         # Circuit management, relay packet processing
│       ├── crypto/
│       │   ├── aead.rs            # Shared ChaCha20-Poly1305 helpers
│       │   ├── sphinx.rs          # Sphinx onion packet format
│       │   ├── keys.rs            # X25519 key generation and DH
│       │   └── noise.rs           # Noise NK handshake, HKDF-SHA256
│       ├── network/
│       │   ├── discovery.rs       # libp2p Kademlia + Gossipsub
│       │   ├── heartbeat.rs       # On-chain heartbeat service
│       │   └── relay.rs           # Packet forwarding, bandwidth tracking
│       └── metrics/
│           ├── bandwidth.rs       # Per-session byte counters
│           └── api.rs             # axum HTTP metrics API
├── contracts/                     # Solidity (Foundry)
│   ├── foundry.toml
│   ├── src/
│   │   ├── NodeRegistry.sol
│   │   ├── SessionSettlement.sol
│   │   ├── SlashingOracle.sol
│   │   ├── Treasury.sol
│   │   └── interfaces/
│   │       ├── INodeRegistry.sol
│   │       ├── ISessionSettlement.sol
│   │       └── ISlashingOracle.sol
│   ├── test/
│   │   ├── NodeRegistry.t.sol     # 12 tests
│   │   └── SessionSettlement.t.sol # 7 tests
│   └── script/
│       └── Deploy.s.sol
└── CLAUDE.md                      # Full spec and design decisions
```

## Getting Started

### Prerequisites

- **Rust** 1.77+ (install via [rustup](https://rustup.rs))
- **Foundry** (install via `curl -L https://foundry.paradigm.xyz | bash && foundryup`)
- **GCC/MinGW** (Windows) or Xcode CLI tools (macOS) — needed by the `ring` crate
- **Node.js** 20+ and **pnpm** (for the client, when built)

### Build the Relay Node

```bash
cd node
cargo build --release
```

### Run the Node

Create a config file `config.toml`:

```toml
listen_port = 51820
metrics_port = 9090
ethereum_rpc = "https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY"
node_private_key_path = "./data/node.key"
libp2p_port = 4001
exit_mode = false
```

```bash
cargo run -- --config config.toml
```

The metrics API will be available at `http://localhost:9090`:
- `GET /health` — node status
- `GET /metrics` — bandwidth totals and session count
- `GET /sessions` — per-session byte counters

### Build and Test Contracts

```bash
cd contracts
forge build
forge test -vv
```

All 19 tests should pass:
- 12 NodeRegistry tests (registration, heartbeats, staking, slashing, pagination)
- 7 SessionSettlement tests (open/settle/force-settle, payment splits, edge cases)

### Deploy Contracts (Sepolia Testnet)

```bash
cd contracts
forge script script/Deploy.s.sol --rpc-url $SEPOLIA_RPC --broadcast --private-key $DEPLOYER_KEY
```

## Node Operator Economics

Nodes earn ETH directly from session settlements. Revenue depends on bandwidth served, price-per-byte (market-driven, set by each operator), and utilization.

| Utilization | Avg Throughput | Price/GB | Monthly Revenue |
|-------------|---------------|----------|-----------------|
| Low (hobby) | 5 MB/s | $0.002 | ~$26 |
| Medium | 25 MB/s | $0.002 | ~$130 |
| High | 50 MB/s | $0.002 | ~$260 |
| Saturated | 100 MB/s | $0.002 | ~$518 |

**Minimum costs:** 0.1 ETH stake (illiquid, not spent), ~$2.40/month in heartbeat gas, minimal hardware requirements. Exit nodes earn 2x but carry more risk (their IP is visible to destinations).

**Staking is a revenue accelerator** — the client scoring algorithm weights stake size. An operator who stakes 1 ETH gets meaningfully more sessions routed to them than one at the 0.1 ETH minimum.

## Design Principles

1. **Ethereum L1 native** — no L2, no sidechain, no bridge. Full Ethereum security inherited directly
2. **No trust required** — every claim is verifiable on-chain or cryptographically
3. **Privacy by architecture** — surveillance is structurally impossible, not just policy-prohibited
4. **Economic alignment** — honest operation earns ETH, misbehavior costs ETH via slashing
5. **Immutable contracts** — deploy without upgrade proxies wherever possible. If you can't upgrade the contracts, you can't rug the users
6. **Client sovereignty** — support self-hosted RPC endpoints (Reth, Geth). Never depend on a centralized API
7. **Graceful degradation** — gas spikes don't break active tunnels. Receipts accumulate locally and settle when gas drops

## Roadmap

### Phase 1: Single-Hop Tunnel (MVP) `← current`
- [x] Rust node binary with WireGuard tunnel, Sphinx routing, and metrics API
- [x] Solidity contracts: NodeRegistry, SessionSettlement, SlashingOracle, Treasury
- [x] Foundry test suite (19 tests passing)
- [ ] End-to-end single-relay tunnel (client connects through one node)
- [ ] Tauri client with basic connect/disconnect
- [ ] Deploy contracts to Ethereum Sepolia testnet
- [ ] **Goal:** browse the internet through a single ShieldNode relay, paid on L1 testnet

### Phase 2: Multi-Hop + Onion Routing
- [ ] Sphinx packet format integrated into live traffic
- [ ] 3-hop circuit construction in client (entry -> relay -> exit)
- [ ] Each node correctly peels its encryption layer and forwards
- [ ] Circuit visualization in client UI
- [ ] Bandwidth receipt co-signing between client and all 3 nodes
- [ ] **Goal:** traffic routes through 3 nodes; no single node sees both source and destination

### Phase 3: Staking + Slashing
- [ ] Minimum stake requirement enforced in NodeRegistry
- [ ] SlashingOracle accepts evidence and executes slashes on-chain
- [ ] Client factors slash history and stake size into node scoring
- [ ] Unstaking cooldown period enforced (7 days)
- [ ] Progressive slashing live (10% -> 25% -> 100%)
- [ ] **Goal:** slashed nodes lose stake and get deprioritized by clients

### Phase 4: Economic Hardening + ZK Settlement Privacy
- [ ] Market-driven pricing: nodes set price-per-byte in registry
- [ ] Gas price monitoring and spike warnings in client UI
- [ ] Stress test: 100+ concurrent sessions, measure L1 throughput
- [ ] ZK bandwidth receipt circuit (circom/Noir): prove valid receipt without revealing session ID, node identities, or timing
- [ ] `ZKSettlement.sol` verifier contract (opt-in alongside plaintext settlement)
- [ ] Client-side proof generation (<5s on modern hardware)
- [ ] **Goal:** the economic loop works end-to-end, with optional ZK-private settlement on testnet

### Phase 5: Mainnet Launch
- [ ] Security audit: all contracts (especially SessionSettlement, ZKSettlement, NodeRegistry)
- [ ] Security audit: node crypto operations and memory handling
- [ ] Audit: ZK circuit correctness
- [ ] Kill switch, auto-rotate circuits, circuit pinning fully functional
- [ ] Challenge-response protocol v1 (trusted challenger set)
- [ ] Deploy immutable contracts to Ethereum mainnet
- [ ] Documentation site: run a node, use the client, verify the contracts
- [ ] At least 10 independently operated nodes before public client release
- [ ] **Goal:** real users on Ethereum mainnet with ZK-private settlement available

### Phase 6: Decentralization + Growth
- [ ] Decentralize challenge-response via challenge bonds (anyone can challenge)
- [ ] Mobile client (iOS/Android)
- [ ] One-click node setup (`docker run shieldnode/relay`)
- [ ] Explore preconfirmations (EIP-7917) for sub-slot session opening (<1s)
- [ ] ZK node eligibility proofs: commitment-based registry, nodes prove they meet criteria without revealing identity
- [ ] ZK no-log compliance proofs: nodes prove their state contains no connection metadata
- [ ] Research: ZK proof of honest relay via ZK-VMs (RISC Zero, SP1) — depends on 100x proving cost reduction

## What ShieldNode Does Not Do

- **No L2 deployment** — the entire point is L1 nativity. No Base, no Arbitrum, no rollups
- **No token** — ETH only for staking, sessions, and slashing. No governance token, no utility token
- **No free tier** — every byte costs someone money. Pay-per-use from day one
- **No centralized RPC** — encourage self-hosting. Public RPCs are convenience, not endorsed trust
- **No upgradeable contracts** — unless absolutely necessary, with a 30-day timelock minimum

## Reference Projects

| Project | Relevance |
|---------|-----------|
| [Nym](https://nymtech.net) | Mixnet with Sphinx packets — most relevant for onion routing layer |
| [Orchid](https://orchid.com) | Pioneered crypto-payment VPN; good payment model |
| [HOPR](https://hoprnet.org) | Mixnet with staking; strong privacy theory |
| [Mullvad VPN](https://mullvad.net) | Gold standard VPN UX — target this quality |
| [WireGuard](https://wireguard.com) | The tunnel protocol (via boringtun userspace implementation) |
| Fuel v1 / DeGate v1 | Immutable contract model (L2Beat Stage 2) — our contract philosophy |
| [Noir (Aztec)](https://noir-lang.org) | ZK circuit language for bandwidth receipt privacy |

## Contributing

This project is in early development. See `CLAUDE.md` for the full technical specification and design decisions.

## License

TBD
