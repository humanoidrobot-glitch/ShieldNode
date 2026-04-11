# ShieldNode

ShieldNode is a decentralized VPN built natively on Ethereum L1, where independent node operators stake ETH to run encrypted relay infrastructure and earn revenue from bandwidth served — with misbehavior punished via on-chain slashing. Traffic routes through 3-hop onion-encrypted circuits using Sphinx packets so no single node ever sees both source and destination, and session settlements use zero-knowledge proofs to pay nodes without revealing session metadata, node identities, or usage patterns on-chain. The cryptographic stack is hardened against quantum computing threats ahead of [Ethereum's own PQ timeline](https://pq.ethereum.org/), with a hybrid X25519 + ML-KEM-768 key exchange protecting circuit routes from harvest-now-decrypt-later attacks, and ML-DSA post-quantum signatures verified inside ZK circuits where their large size carries no gas penalty. No L2, no token, no trust assumptions beyond Ethereum consensus itself — privacy enforced by math, not policy.

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

Each relay peels one layer of Sphinx-style encryption, sees only the next hop, and forwards. Session keys are derived from a hybrid X25519 + ML-KEM-768 key exchange (post-quantum resistant), combined via HKDF-SHA256. All tunnel encryption uses ChaCha20-Poly1305.

## Architecture

### Relay Node (Rust)

The node binary that independent operators run. Located in `node/`.

| Module | Purpose |
|--------|---------|
| `tunnel/wireguard.rs` | WireGuard tunnel via boringtun (userspace, cross-platform) |
| `tunnel/circuit.rs` | Circuit lifecycle, pure `process_relay_packet` function (ZK-provable) |
| `crypto/traits.rs` | `KeyExchange` and `Signer` trait abstractions for cryptographic agility |
| `crypto/aead.rs` | Re-exports shared ChaCha20-Poly1305 helpers from `shieldnode-types` |
| `crypto/sphinx.rs` | Sphinx onion packet creation and layer peeling |
| `crypto/keys.rs` | X25519 + ML-KEM-768 hybrid key exchange (post-quantum) |
| `crypto/noise.rs` | Noise NK-pattern handshake, HKDF-SHA256 key derivation |
| `network/discovery.rs` | libp2p Kademlia DHT + Gossipsub peer discovery |
| `network/heartbeat.rs` | Periodic on-chain heartbeat for liveness proofs |
| `network/relay.rs` | Packet forwarding with bandwidth tracking, session key zeroization |
| `metrics/bandwidth.rs` | Per-session byte counting with O(1) running totals |
| `metrics/api.rs` | HTTP API (axum): `/health`, `/metrics`, `/sessions` |
| `config.rs` | TOML configuration with sane defaults |

Key design decisions:
- **No logging by design** — the node software has no mechanism to record connection metadata
- **Relay forwarding is a pure function** — deterministic, no side effects, structured for future ZK-VM proof generation
- **Session keys are zeroized on drop** — sensitive material doesn't linger in memory
- **Crypto trait abstractions** — `KeyExchange` and `Signer` traits allow swapping primitives (classical ↔ post-quantum) without touching tunnel or circuit logic

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

#### `ZKSettlement.sol`
ZK-private alternative to SessionSettlement. Clients submit a Groth16 proof that they hold a valid dual-signed bandwidth receipt and the correct payment is owed — without revealing the session ID, node identities, or timing on-chain. The contract verifies the proof and distributes payment to commitments. Built with circom 2.2.3 + snarkjs 0.7.6, ~3.2M constraints. Plaintext settlement via SessionSettlement remains as a fallback.

**Gas costs at 0.2 Gwei:**

| Operation | Estimated Gas | Cost |
|-----------|--------------|------|
| Node registration | ~150,000 | ~$0.06 |
| Heartbeat | ~50,000 | ~$0.02 |
| Open session | ~100,000 | ~$0.04 |
| Settle session | ~120,000 | ~$0.05 |
| ZK settle session | ~300,000 | ~$0.12 |
| Slash proposal | ~200,000 | ~$0.08 |

### Client Application (Tauri)

A Tauri (Rust + React) desktop app. Core tunnel logic in Rust, UI in TypeScript/React. Located in `client/`.

The client reads the node registry directly from L1, scores nodes by uptime/stake/latency/price/completion-rate, constructs 3-hop circuits with diversity constraints (different ASN/subnet/region per hop), and manages session lifecycle including auto-rotation. Features include a circuit health monitor that detects and recovers from node drops, gas price monitoring with configurable ceiling, kill switch, and wallet integration (WalletConnect/injected/raw key). Supports self-hosted RPC endpoints (Reth, Geth).

## Project Structure

```
shieldnode/
├── Cargo.toml                     # Workspace: node, client, packages/shieldnode-types
├── packages/
│   └── shieldnode-types/          # Shared crate (AEAD, KDF, EIP-712, hop codec, Sphinx MAC)
├── node/                          # Rust relay node
│   └── src/
│       ├── main.rs                # CLI, config, metrics server, UPnP
│       ├── tunnel/
│       │   ├── wireguard.rs       # boringtun WireGuard integration
│       │   ├── listener.rs        # Bidirectional TUN + WireGuard listener
│       │   ├── tun_device.rs      # TUN virtual network interface
│       │   ├── packet_norm.rs     # Fixed-size packet normalization (1280 bytes)
│       │   └── circuit.rs         # Circuit lifecycle, pure relay function
│       ├── crypto/
│       │   ├── traits.rs          # KeyExchange, Signer trait abstractions
│       │   ├── sphinx.rs          # Sphinx onion packets (classic + PQ)
│       │   ├── keys.rs            # X25519 + ML-KEM-768 hybrid key exchange
│       │   ├── ratchet.rs         # Micro-ratcheting session keys (30s/10MB)
│       │   └── noise.rs           # Noise NK handshake
│       ├── network/
│       │   ├── relay_listener.rs  # UDP relay with session setup/teardown/receipt co-signing
│       │   ├── relay.rs           # Session management, packet forwarding
│       │   ├── discovery.rs       # libp2p Kademlia + Gossipsub + mDNS
│       │   ├── heartbeat.rs       # On-chain heartbeat service
│       │   ├── nat.rs             # UPnP/IGD port mapping for NAT traversal
│       │   ├── link_padding.rs    # Constant-rate inter-node padding
│       │   └── batch_reorder.rs   # Packet batching and shuffling
│       └── metrics/
│           ├── bandwidth.rs       # Per-session byte counters
│           └── api.rs             # axum HTTP API: /health, /metrics, /sessions
├── contracts/                     # Solidity (Foundry), 157+ tests
│   ├── src/
│   │   ├── NodeRegistry.sol       # Staking, heartbeats, secp256k1 key storage
│   │   ├── SessionSettlement.sol  # EIP-712 receipts, 25/25/50 split, cleanup
│   │   ├── ZKSettlement.sol       # Groth16 proof verification, Poseidon commitments
│   │   ├── SlashingOracle.sol     # Progressive slashing, evidence verification
│   │   ├── ChallengeManager.sol   # Bonded challenge-response protocol
│   │   ├── CommitmentTree.sol     # Poseidon Merkle tree for ZK eligibility
│   │   ├── EligibilityVerifier.sol
│   │   └── Treasury.sol
│   ├── test/                      # 18 test files + helpers + invariant fuzz
│   └── script/Deploy.s.sol       # Nonce-aware deployment with ownership transfer
├── circuits/                      # ZK circuits (circom + Groth16)
│   ├── bandwidth_receipt/         # ~3.5M constraints, dual ECDSA + Poseidon
│   ├── node_eligibility/          # ~12K constraints, anonymous eligibility
│   ├── lib/merkle.circom          # Shared Merkle proof template
│   ├── scripts/                   # compile, setup, prove, verify
│   └── trusted_setup/
├── client/                        # Tauri (Rust + React) desktop client
│   ├── src-tauri/src/
│   │   ├── tunnel.rs              # WireGuard tunnel (boringtun)
│   │   ├── tun_loop.rs            # Bidirectional TUN ↔ Sphinx forwarding
│   │   ├── tun.rs                 # TUN device creation
│   │   ├── circuit.rs             # 3-hop selection, scoring, key zeroization
│   │   ├── wallet.rs              # Transaction signing (local + WalletConnect)
│   │   ├── wallet_bridge.rs       # WalletConnect signing delegation bridge
│   │   ├── settlement.rs          # ZK or plaintext settlement dispatch
│   │   ├── zk_prove.rs            # Groth16 proof generation (ark-circom)
│   │   ├── kill_switch.rs         # OS-level firewall (Windows/Linux/macOS)
│   │   ├── health_monitor.rs      # Circuit degradation detection
│   │   ├── cover_traffic.rs       # Timing-attack mitigation
│   │   └── config.rs              # Settings, keychain, WalletConnect mode
│   └── src/
│       ├── components/            # ConnectToggle, CircuitMap, NodeBrowser, Settings
│       ├── hooks/                 # useCircuit, useNodes, useSession, useGas, useWallet
│       └── lib/                   # contracts.ts, scoring.ts, eip712.ts
├── docs/
│   ├── OPERATOR-GUIDE.md          # Node setup, config, economics
│   ├── OPERATOR-SECURITY.md       # Key management, Safe wallets, PQ migration
│   ├── THREAT-MODEL.md            # Adversary model, traffic morphing research
│   ├── OWNERSHIP-RENOUNCEMENT.md  # Trust minimization roadmap (6 phases)
│   ├── TECH-DEBT.md               # Known deferred improvements
│   ├── anti-logging-research.md   # TEE, cover traffic, ZK-VM analysis
│   └── PROJECT-REVIEW-2026-04-09.md
├── .github/workflows/
│   ├── ci.yml                     # Contracts + node + client + frontend + audit
│   └── reproducible-build.yml     # Deterministic binary for TEE attestation
└── CLAUDE.md
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

157+ tests should pass across 18 test files:
- NodeRegistry, SessionSettlement, ZKSettlement, SlashingOracle, ChallengeManager
- CommitmentTree, EligibilityVerifier, ExecutionTraceVerifier, RelayProofVerifier
- Invariant fuzz tests for cross-contract interactions
- Test helpers in `test/helpers/TestKeys.sol`

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

**Staking is a revenue accelerator** — the client scoring algorithm weights uptime (25%), stake (25%), price (20%), slash history (15%), and session completion rate (15%). An operator who stakes 1 ETH gets meaningfully more sessions routed to them than one at the 0.1 ETH minimum.

## Security Architecture

ShieldNode addresses two hard problems in decentralized relay networks — collusion and logging — through layered defenses documented in detail in [ROADMAP.md](ROADMAP.md).

**Anti-collusion:** circuit diversity constraints prevent multiple hops from sharing infrastructure (ASN, subnet, region). Same-operator exclusion, stake concentration heuristics, and a minimum network size guard layer on top. Circuit auto-rotation limits any single correlation window. ZK node eligibility proofs (Phase 6) will hide the node set from enumeration by state actors. A dummy commitment Merkle tree obscures the real network size during bootstrapping.

**Anti-logging:** rather than attempting to prove logging doesn't occur — a problem that is fundamentally unsolvable for remote machines — ShieldNode ensures that any data an operator *could* capture is structurally useless. Nine defense layers work in concert: Sphinx onion encryption protects content, fixed-size packet normalization eliminates size fingerprinting, adaptive cover traffic obscures activity patterns, hybrid post-quantum key exchange prevents harvest-now-decrypt-later, micro-ratcheting limits key compromise to 30-second windows, TEE hardware enclaves (Phase 5) isolate traffic from the host OS, ZK-VM proofs (Phase 6) verify software integrity, ephemeral compute prevents log persistence, and traffic volume analysis detects exfiltration. The full technical analysis with citations is available in **[docs/anti-logging-research.md](docs/anti-logging-research.md)**.

**Post-quantum:** the hybrid X25519 + ML-KEM-768 handshake is already implemented, protecting circuit routes from harvest-now-decrypt-later attacks. ML-DSA signatures are verified inside ZK circuits. See the [Post-Quantum Strategy](ROADMAP.md#post-quantum-strategy) section in the roadmap for the full threat model and upgrade table.

## Design Principles

1. **Ethereum L1 native** — no L2, no sidechain, no bridge. Full Ethereum security inherited directly
2. **No trust required** — every claim is verifiable on-chain or cryptographically
3. **Privacy by architecture** — surveillance is structurally impossible, not just policy-prohibited
4. **Economic alignment** — honest operation earns ETH, misbehavior costs ETH via slashing
5. **Immutable contracts** — deploy without upgrade proxies wherever possible. If you can't upgrade the contracts, you can't rug the users
6. **Client sovereignty** — support self-hosted RPC endpoints (Reth, Geth). Never depend on a centralized API
7. **Graceful degradation** — gas spikes don't break active tunnels. Receipts accumulate locally and settle when gas drops

## Roadmap

Development is organized into 6 phases. See **[ROADMAP.md](ROADMAP.md)** for the full breakdown with completed/remaining checklists.

| Phase | Focus | Status |
|-------|-------|--------|
| **1. Single-Hop Tunnel (MVP)** | Working relay, contracts, client app | Complete |
| **2. Multi-Hop + Onion Routing** | 3-node circuits, Sphinx encryption, auto-rotation | Complete |
| **3. Staking + Slashing** | Cryptoeconomic security, progressive slashing, scoring | Complete |
| **4. Economic Hardening + ZK** | ZK settlement, PQ handshake, anti-griefing, anti-collusion | Complete |
| **5. Mainnet Launch** | Audits, hardening, TUN integration, WalletConnect, deploy | In progress |
| **6. Decentralization** | ZK-VM proofs, challenge bonds, mobile, dummy Merkle tree | Partial (ZK-VM + challenge bonds done) |

## What ShieldNode Does Not Do

- **No L2 deployment** — the entire point is L1 nativity. No Base, no Arbitrum, no rollups
- **No token** — ETH only for staking, sessions, and slashing. No governance token, no utility token
- **No free tier** — every byte costs someone money. Pay-per-use from day one
- **No centralized RPC** — encourage self-hosting. Public RPCs are convenience, not endorsed trust
- **No upgradeable contracts** — unless absolutely necessary, with a 30-day timelock minimum

## Reference Projects

| Project | Relevance |
|---------|-----------|
| [Nym](https://nymtech.net) | Mixnet with Sphinx packets, staking-based reputation. Study Sybil resistance via staking and traffic analysis resistance through packet timing obfuscation |
| [Orchid](https://orchid.com) | Pioneered crypto-payment VPN; good payment model |
| [HOPR](https://hoprnet.org) | Mixing with cover traffic; probabilistic packet relaying to resist traffic analysis |
| [Mullvad VPN](https://mullvad.net) | Gold standard VPN UX — target this quality |
| [WireGuard](https://wireguard.com) | The tunnel protocol (via boringtun userspace implementation) |
| Fuel v1 / DeGate v1 | Immutable contract model (L2Beat Stage 2) — our contract philosophy |
| [Noir (Aztec)](https://noir-lang.org) | ZK circuit language for bandwidth receipt privacy |
| [Oxen/Session](https://oxen.io) | Decentralized onion routing with service node staking. Study swarm-based node grouping and path selection |
| [Oasis Network / Sapphire](https://oasisprotocol.org) | Confidential computing runtime using TEEs. Study remote attestation verification and enclave key management |
| [Gramine](https://gramineproject.io) | Library OS for running unmodified Linux apps inside SGX enclaves. Evaluate for relay binary enclave support |
| [AWS Nitro Enclaves](https://aws.amazon.com/ec2/nitro/nitro-enclaves/) | Confidential computing offering. Study attestation document format and NSM API as reference for enclave attestation |
| [Signal PQXDH](https://signal.org/docs/specifications/pqxdh/) | Hybrid X25519 + ML-KEM in production. Closest precedent for ShieldNode's post-quantum handshake |
| [PQ Ethereum](https://pq.ethereum.org/) | EF post-quantum initiative. ShieldNode's PQ timeline stays ahead of Ethereum's own |
| [NIST FIPS 203/204](https://csrc.nist.gov/publications/fips) | ML-KEM (Kyber), ML-DSA (Dilithium) standards. FIPS-compliant implementations only |

## Contributing

This project is in early development. See [ROADMAP.md](ROADMAP.md) for milestones and progress.

## License

Dual-licensed under [MIT](LICENSE) + [Source Seppuku](https://wiki.remilia.org/Source_Seppuku_License).
