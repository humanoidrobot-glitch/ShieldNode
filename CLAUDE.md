# CLAUDE.md — ShieldNode: Decentralized VPN with Ethereum-Grade Security

## Project Identity

- **Name**: ShieldNode (working title — rename freely)
- **One-liner**: A decentralized, cryptoeconomically-secured VPN built natively on Ethereum L1. No L2 compromises, no multisig exit risk, no trust assumptions beyond Ethereum consensus itself.
- **Tech Stack**: Rust (core networking + node software), TypeScript (client UI + dashboard), Solidity (staking/slashing/payments on Ethereum L1), PostgreSQL (local node metrics), libp2p (peer discovery + relay coordination)
- **Why L1**: Post-Fusaka Ethereum averages <0.2 Gwei gas (~$0.01 per transaction). ERC-20 transfers cost $0.01–$0.02, contract interactions pennies. There is no economic reason to use an L2, and every L2 introduces trust assumptions (Security Council overrides, missing exit windows, upgradeable bridges) that contradict the project's core promise. ShieldNode inherits Ethereum's security directly — no intermediary layer, no Stage 1 caveats.

---

## Architecture Overview

ShieldNode has four major subsystems. Build them in this order:

### 1. Relay Node Software (Rust)

The node binary that independent operators run to join the network and route encrypted traffic.

**Core responsibilities:**
- Accept incoming encrypted tunnel connections from clients
- Forward traffic to destination (exit node) or next relay (multi-hop)
- Implement onion-style layered encryption: each relay peels one layer, sees only the next hop — never the full circuit
- Expose a lightweight metrics API (uptime, bandwidth served, latency) used for on-chain reputation
- Heartbeat registration with the network's discovery layer

**Key design decisions:**
- Use WireGuard protocol as the tunnel primitive (via `boringtun` crate — userspace WireGuard implementation in Rust). Do NOT use kernel WireGuard; we need cross-platform portability
- Multi-hop routing: client builds a circuit of 3 nodes (entry → relay → exit). Entry node knows the client IP but not the destination. Exit node knows the destination but not the client. Middle relay knows neither
- Circuit construction uses a Sphinx-like packet format: the client pre-computes the full onion-encrypted route, each node decrypts its layer to reveal the next hop
- Session keys are ephemeral, derived via X25519 Diffie-Hellman per circuit
- Implement bandwidth metering at the node level — nodes track bytes relayed per session for payment settlement
- No logging by design: the node software should have no mechanism to record connection metadata even if the operator wanted to. Strip source IPs from memory after circuit teardown

**File structure:**
```
node/
├── Cargo.toml
├── src/
│   ├── main.rs                 # Entry point, CLI args, config loading
│   ├── tunnel/
│   │   ├── mod.rs
│   │   ├── wireguard.rs        # boringtun integration, tunnel setup/teardown
│   │   └── circuit.rs          # Multi-hop circuit handling, onion decryption
│   ├── crypto/
│   │   ├── mod.rs
│   │   ├── sphinx.rs           # Sphinx packet format encode/decode
│   │   ├── keys.rs             # X25519 key generation, ephemeral session keys
│   │   └── noise.rs            # Noise protocol handshake (NK pattern)
│   ├── network/
│   │   ├── mod.rs
│   │   ├── discovery.rs        # libp2p peer discovery, DHT integration
│   │   ├── heartbeat.rs        # Periodic liveness proof to network
│   │   └── relay.rs            # Packet forwarding logic between hops
│   ├── metrics/
│   │   ├── mod.rs
│   │   ├── bandwidth.rs        # Per-session byte counting
│   │   └── api.rs              # Local HTTP API for metrics export
│   └── config.rs               # Node configuration (ports, stake address, etc.)
```

**Crate dependencies to start with:**
- `boringtun` — userspace WireGuard
- `x25519-dalek` — X25519 ECDH
- `chacha20poly1305` — symmetric encryption for onion layers
- `libp2p` — peer discovery, Kademlia DHT, gossipsub
- `tokio` — async runtime
- `axum` — metrics HTTP API
- `tracing` — structured logging (for node operator debugging, NOT user traffic)
- `clap` — CLI argument parsing
- `serde` / `toml` — config file parsing
- `ethers-rs` or `alloy` — Ethereum L1 interaction from node software (for heartbeats, settlement)

---

### 2. Smart Contracts — Ethereum L1 (Solidity)

All contracts deploy directly to Ethereum mainnet. At current gas prices (<0.2 Gwei), every operation in this system costs pennies. No L2, no bridge, no multisig exit risk.

**Contracts to build:**

#### `NodeRegistry.sol`
- Operators call `register(nodeId, publicKey, endpoint)` with a minimum stake (e.g., 0.1 ETH) sent as `msg.value`
- Stores: node public key, libp2p multiaddr, stake amount, registration timestamp, slash count, last heartbeat block
- Emits events on registration, deregistration, and stake changes
- `getActiveNodes()` returns the current set of staked, non-slashed nodes for client-side circuit selection — implement pagination for gas-efficient reads
- Nodes call `heartbeat()` periodically (e.g., every 6 hours). At <$0.01 per call, this is trivially cheap even for thousands of nodes. Nodes that miss 3 consecutive heartbeat windows are marked inactive
- Implements a cooldown period for unstaking (e.g., 7 days) to prevent stake-and-run attacks
- `updateEndpoint(newMultiaddr)` for nodes that change IPs or ports

#### `SlashingOracle.sol`
- Accepts slashing evidence from a set of authorized challengers (initially a multisig of early operators, with a roadmap to decentralize via a challenge bond mechanism)
- Slashing conditions:
  - **Provable logging**: if a node is caught correlating entry/exit traffic (proven via cryptographic challenge-response)
  - **Selective denial**: node drops traffic for specific destinations (censorship)
  - **Bandwidth fraud**: node claims to have relayed X bytes but settlement receipts show otherwise
- Slashed stake distribution: 50% to the challenger, 50% to a protocol treasury (a simple contract, not a DAO)
- Progressive slashing: first offense = 10% of stake, second = 25%, third = 100% + permanent ban via mapping
- All slashing is on-chain and publicly auditable — anyone can verify the slash history of any node

#### `SessionSettlement.sol`
This replaces the payment channel design from the earlier L2-oriented architecture. Because L1 gas is now cheap enough, we can use a simpler direct settlement model instead of maintaining off-chain channel state.

**How it works:**
- Client calls `openSession(nodeIds[3])` with a prepaid deposit (e.g., 0.01 ETH). This is a single L1 transaction that costs ~$0.01–$0.05. The deposit covers an estimated session duration
- During the session, bandwidth consumption is tracked off-chain by both client and nodes. Both parties sign bandwidth receipts (cumulative byte counts + timestamps) using EIP-712 typed signatures
- When the session ends, either party calls `settleSession(sessionId, signedReceipt)` to close out. The contract verifies both signatures, calculates payment based on bytes transferred × price-per-byte, pays the nodes from the deposit, and refunds any remainder to the client
- If the client disappears without settling, nodes can submit their signed receipt after a timeout (e.g., 1 hour) to claim payment unilaterally
- If there's a dispute (client and node disagree on bandwidth), the contract uses the receipt with the highest cumulative byte count that has valid signatures from both parties
- Minimum deposit enforced to prevent dust-amount griefing
- Price-per-byte is set by each node in the registry (market-driven pricing)

**Why this is better than payment channels on L1:**
- No channel open/close lifecycle to manage
- No locked capital sitting in channels between sessions
- Simpler state: each session is a standalone unit with a clear start, settlement, and end
- Gas cost per session: ~$0.02–$0.10 total (open + settle). At sub-0.2 Gwei, this is negligible
- No complex dispute resolution or watchtower requirements

#### `Treasury.sol`
- Receives 50% of slashed stakes
- Simple withdrawal function gated by a timelock + multisig (initially team, with a path to DAO governance if the project scales)
- Funds are earmarked for protocol development, audits, and bug bounties
- Fully transparent: anyone can inspect the balance and withdrawal history on-chain

**File structure:**
```
contracts/
├── foundry.toml
├── src/
│   ├── NodeRegistry.sol
│   ├── SlashingOracle.sol
│   ├── SessionSettlement.sol
│   ├── Treasury.sol
│   └── interfaces/
│       ├── INodeRegistry.sol
│       ├── ISlashingOracle.sol
│       └── ISessionSettlement.sol
├── test/
│   ├── NodeRegistry.t.sol
│   ├── SlashingOracle.t.sol
│   ├── SessionSettlement.t.sol
│   └── Integration.t.sol        # End-to-end session lifecycle tests
├── script/
│   └── Deploy.s.sol
```

**Use Foundry for development.** Solidity 0.8.24+. All contracts should be deployed as non-upgradeable (immutable) wherever possible. If upgradeability is needed for early-stage iteration, use a transparent proxy with a timelock of at least 30 days — the same exit window standard we'd demand from an L2. Document every upgradeability decision and its justification.

**Gas budget estimates at 0.2 Gwei (~$0.01/simple tx):**
| Operation | Estimated Gas | Cost at 0.2 Gwei |
|-----------|--------------|-------------------|
| Node registration | ~150,000 | ~$0.06 |
| Heartbeat | ~50,000 | ~$0.02 |
| Open session | ~100,000 | ~$0.04 |
| Settle session | ~120,000 | ~$0.05 |
| Slash proposal | ~200,000 | ~$0.08 |

These are estimates — measure actual gas on testnet and adjust. Even if gas spikes 10x to 2 Gwei, no single operation exceeds $1.

---

### 3. Client Application (TypeScript + Rust core)

The user-facing VPN client. UX goal: as simple as any commercial VPN — one toggle to connect — but with full transparency into what's actually happening under the hood.

**Architecture:**
- **Core tunnel logic in Rust** (compiled to a shared library) — circuit construction, onion encryption, WireGuard tunnel management
- **UI shell in TypeScript** — Tauri (preferred, since it uses Rust on the backend) for desktop
- **Dashboard web UI** — lightweight React app served locally showing connection status, circuit path, node reputation scores, session costs

**Client flow:**
1. User clicks "Connect"
2. Client reads active node list from `NodeRegistry` contract on Ethereum L1 (via a configurable RPC endpoint — the client should support self-hosted nodes like Reth, fully aligned with trustless principles)
3. Client scores nodes by: uptime history (heartbeat consistency), slash count, geographic diversity, latency (via ping), stake size, price-per-byte
4. Client selects 3 nodes for the circuit (entry, relay, exit) — user can also manually select or pin specific nodes
5. Client sends `openSession()` transaction to L1 with prepaid deposit. At current gas, this confirms in ~12 seconds and costs ~$0.04
6. Client constructs the Sphinx-encrypted circuit packet, performs handshakes with each node in sequence
7. Tunnel is established. All device traffic routes through the circuit
8. Bandwidth metering runs locally. Client and nodes co-sign bandwidth receipts periodically
9. On disconnect, client calls `settleSession()` on L1. Nodes are paid, remainder is refunded. Total settlement cost: ~$0.05

**Key UX features:**
- **Circuit visualization**: show the user exactly which 3 nodes they're routed through, with location, uptime, and stake info for each. Show the on-chain transaction hashes for session open/settle so users can verify on Etherscan
- **Node transparency**: clickable node details showing on-chain history (when they registered, how much stake, any slashing events, total sessions served). All data read directly from L1 — no backend API required
- **Kill switch**: if the tunnel drops, immediately cut all network traffic until reconnected
- **Auto-rotate circuits**: periodically rebuild the circuit through different nodes for forward secrecy
- **Wallet integration**: connect via WalletConnect or injected wallet (MetaMask, Rabby) for session deposits. Also support direct private key import for power users who don't want a browser wallet dependency
- **Gas price awareness**: show current L1 gas in the UI. If gas spikes above a configurable threshold (e.g., 5 Gwei), warn the user before opening a session. Display estimated session cost before confirmation
- **RPC configuration**: let users point to their own Ethereum node. Default to a set of public RPCs with fallback, but prominently feature self-hosted node support. This is philosophically important — if your VPN depends on Infura, you've just moved the trust assumption from the L2 bridge to an RPC provider

**File structure:**
```
client/
├── src-tauri/                  # Tauri Rust backend
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── tunnel.rs           # Calls into core Rust tunnel library
│       ├── circuit.rs          # Circuit construction + node selection
│       ├── wallet.rs           # Transaction signing for session open/settle
│       ├── receipts.rs         # Bandwidth receipt co-signing (EIP-712)
│       └── config.rs
├── src/                        # React frontend
│   ├── App.tsx
│   ├── components/
│   │   ├── ConnectToggle.tsx   # Main on/off switch
│   │   ├── CircuitMap.tsx      # Visual circuit path with node details
│   │   ├── NodeBrowser.tsx     # Browse/search/filter available nodes
│   │   ├── SessionCost.tsx     # Current session cost + deposit balance
│   │   ├── GasMonitor.tsx      # Live L1 gas price display
│   │   └── Settings.tsx        # RPC endpoint, auto-rotate, kill switch config
│   ├── hooks/
│   │   ├── useCircuit.ts
│   │   ├── useNodes.ts         # Reads node registry from L1
│   │   ├── useSession.ts       # Session lifecycle management
│   │   └── useGas.ts           # Gas price monitoring
│   └── lib/
│       ├── contracts.ts        # viem contract interactions (L1 direct)
│       ├── scoring.ts          # Node scoring algorithm
│       ├── eip712.ts           # Bandwidth receipt type definitions
│       └── types.ts
├── package.json
└── tauri.conf.json
```

---

### 4. Network Coordination Layer

The glue between nodes, clients, and contracts.

**Peer Discovery (libp2p DHT):**
- Nodes announce themselves on a Kademlia DHT with their public key, multiaddr, and a signed attestation linking to their on-chain registration
- Clients can discover nodes via DHT or by reading the on-chain registry directly (DHT is faster for real-time availability, L1 registry is the source of truth for stake/reputation)
- Gossipsub for real-time network health broadcasts (node going offline, slashing events)

**Bandwidth Receipts:**
- During each session, the exit node and client both sign cumulative bandwidth receipts using EIP-712 typed structured data
- Receipt format: `{ sessionId, cumulativeBytes, timestamp, nodeSignature, clientSignature }`
- Receipts are exchanged off-chain every N seconds (e.g., every 30 seconds) or every M megabytes (e.g., every 10 MB), whichever comes first
- Only the final receipt is submitted on-chain during settlement — all intermediate receipts are local only
- If there's a dispute, the contract accepts the highest-cumulative-bytes receipt with valid dual signatures

**Challenge-Response Protocol (anti-logging):**
- Periodically, the network issues challenges to random nodes: "decrypt this test packet and prove you forwarded it correctly without retaining the payload"
- Nodes that fail challenges (or don't respond) get flagged; repeated failures trigger slashing proposals
- This is the hardest part to design correctly — start with a simple version and iterate. The initial implementation can use a trusted challenger set (multisig of early operators) with a roadmap to decentralize via challenge bonds (anyone can post a bond to issue a challenge; if the challenge is valid and the node fails, the challenger earns a reward from the slash)

---

## Build Order & Milestones

### Phase 1: Single-hop tunnel (MVP)
- [ ] Rust node binary that accepts WireGuard connections and forwards traffic (single relay, no onion routing yet)
- [ ] Basic Tauri client that connects to a single node
- [ ] NodeRegistry contract deployed on Ethereum Sepolia testnet
- [ ] Node registers on-chain, client reads registry to find the node
- [ ] SessionSettlement contract: client opens session with deposit, settles on disconnect
- **Success metric**: you can browse the internet through a single ShieldNode relay and pay for it on L1 testnet

### Phase 2: Multi-hop + onion routing
- [ ] Implement Sphinx packet format
- [ ] Circuit construction (3-hop) in client
- [ ] Each node correctly peels its encryption layer and forwards
- [ ] Circuit visualization in client UI
- [ ] Bandwidth receipt co-signing between client and all 3 nodes
- **Success metric**: traffic routes through 3 independent nodes; no single node can see both source and destination

### Phase 3: Staking + slashing
- [ ] Minimum stake requirement enforced in NodeRegistry
- [ ] SlashingOracle accepts evidence and slashes misbehaving nodes
- [ ] Client factors slash history and stake size into node scoring
- [ ] Unstaking cooldown period enforced
- [ ] Progressive slashing logic (10% → 25% → 100%)
- **Success metric**: a slashed node is deprioritized by clients and loses stake on Sepolia

### Phase 4: Economic hardening + ZK settlement privacy
- [ ] Market-driven pricing: nodes set their own price-per-byte in the registry
- [ ] Client displays estimated session cost before connection
- [ ] Gas price monitoring and spike warnings in client UI
- [ ] Treasury contract receiving slash proceeds
- [ ] Stress testing: simulate 100+ concurrent sessions and measure L1 settlement throughput
- [ ] Design ZK bandwidth receipt circuit (see ZK Integration Roadmap section below): define the statement to be proved, select proving system, build initial circuit
- [ ] Implement `ZKSettlement.sol` verifier contract alongside the existing `SessionSettlement.sol` — both paths work, ZK is opt-in
- [ ] Client-side proof generation for session settlement: prove valid dual-signed receipt + correct payment calculation without revealing session ID, node identities, or timing on-chain
- **Success metric**: the economic loop works end-to-end — nodes earn ETH, clients pay ETH, misbehavior costs ETH. At least one session settles via ZK proof on testnet

### Phase 5: Mainnet launch
- [ ] Security audit of all contracts (prioritize SessionSettlement, ZKSettlement, and NodeRegistry — these hold funds)
- [ ] Security audit of node software (prioritize crypto operations and memory handling)
- [ ] Audit of ZK circuit correctness — the proof must not allow over-claiming or underpaying
- [ ] Kill switch, auto-rotate, and circuit pinning fully functional in client
- [ ] Challenge-response protocol v1 (trusted challenger set)
- [ ] Deploy contracts to Ethereum mainnet (immutable deployment — no proxy)
- [ ] ZK settlement as default for privacy-conscious users, plaintext settlement as fallback for simplicity
- [ ] Documentation site: how to run a node, how to use the client, how to verify the contracts
- [ ] At least 10 independently operated nodes live before public client release
- **Success metric**: real users browsing through ShieldNode on Ethereum mainnet, with ZK-private settlement available

### Phase 6: Decentralization + growth
- [ ] Decentralize challenge-response via challenge bonds (anyone can challenge)
- [ ] Mobile client (iOS/Android)
- [ ] Node operator onboarding tooling (one-click setup scripts, Docker image)
- [ ] Explore preconfirmations (EIP-7917 from Fusaka) for sub-slot session opening — if a proposer preconfirms the `openSession` tx, users could have tunnel establishment <1 second instead of waiting for a full block
- [ ] ZK node eligibility proofs: migrate NodeRegistry to commitment-based storage where nodes prove they meet selection criteria (stake, uptime, slash-free) without revealing which specific node they are until circuit handshake. This hardens the network against enumeration attacks
- [ ] ZK no-log compliance proofs: nodes periodically prove their state contains no connection metadata, augmenting or replacing the challenge-response protocol
- [ ] Research: ZK proof of honest relay — evaluate whether ZK-VM systems (RISC Zero, SP1, Valida) are mature enough to prove correct packet forwarding at reasonable cost. This is the long-term endgame but depends on proving cost reductions. Architect node relay logic as a cleanly separable module to enable this later

---

## Node Operator Economics & Bootstrapping

This section defines how node operators earn revenue, what it costs to run a node, and how the network bootstraps from zero to a self-sustaining flywheel. Build this analysis into the `docs/ECONOMICS.md` file early — it informs staking parameters, pricing defaults, and Phase 1 decisions.

### Revenue Model

Nodes earn ETH directly from session settlements on Ethereum L1. Revenue is a function of three variables: bandwidth served, price-per-byte, and utilization rate.

**Price-per-byte**: each node sets its own rate in the `NodeRegistry` contract. This is market-driven — nodes compete on price. The client's scoring algorithm factors price into node selection alongside uptime, stake, and latency, so nodes that price too high get fewer sessions while nodes that price too low may not cover costs. The contract should enforce a minimum price floor to prevent race-to-zero dynamics that would make the network unviable.

**Revenue scenarios** (illustrative, at ~$2,000 ETH):

| Utilization | Avg throughput | Price/GB | Daily revenue | Monthly revenue |
|-------------|---------------|----------|--------------|-----------------|
| Low (hobby) | 5 MB/s | $0.002 | ~$0.86 | ~$26 |
| Medium | 25 MB/s | $0.002 | ~$4.32 | ~$130 |
| High | 50 MB/s | $0.002 | ~$8.64 | ~$260 |
| Saturated | 100 MB/s | $0.002 | ~$17.28 | ~$518 |

These assume 24/7 operation at the stated average throughput. Real utilization will vary by time of day, geography, and network maturity. Early operators will see lower utilization but can set higher prices due to less competition.

**Revenue per session**: a typical 1-hour browsing session might transfer 500 MB–2 GB. At $0.002/GB, that's $0.001–$0.004 per session to each node in the circuit (3 nodes share the traffic). Individual sessions are tiny; volume is what matters.

### Cost Structure

**Minimum costs to operate a node:**

| Cost item | Estimate | Notes |
|-----------|----------|-------|
| Stake lockup | 0.1 ETH (~$200) | Minimum. Higher stake = better ranking. Not spent, but illiquid during operation + 7-day cooldown |
| Heartbeat gas | ~$0.02/call, 4x/day | ~$2.40/month at current gas. Negligible |
| Bandwidth | Varies by ISP | Most residential plans have sufficient upload. Some ISPs throttle or meter — operators should check. Business/datacenter connections are ideal |
| Hardware | Minimal | Any always-on machine: home server, NAS, VPS, or existing Ethereum node hardware. ~1 GB RAM, minimal CPU for relay-only (no exit). Exit nodes need more bandwidth but not more compute |
| Electricity | ~$5–15/month incremental | If running on existing hardware, the marginal power cost is small |
| Settlement gas | ~$0.05/session | Paid by client in most cases, but nodes pay if they need to force-settle after client disappears |

**Break-even analysis**: at the low end (hobby operator, ~$26/month revenue), an operator running on existing hardware with no incremental bandwidth cost breaks even easily. The main risk is stake slashing, not operational costs. At the high end, a dedicated VPS ($20–50/month) serving significant traffic can be profitable if utilization stays above ~15 MB/s average.

### Three-Hop Revenue Splitting

In a 3-node circuit, the session deposit is split across the entry, relay, and exit nodes. The split should NOT be equal — exit nodes bear more risk (their IP is visible to the destination) and more bandwidth (they handle the actual internet traffic, not just encrypted relay). Implement a configurable split ratio in the `SessionSettlement` contract:

**Suggested default split:**
- Entry node: 25%
- Relay node: 25%
- Exit node: 50%

Exit nodes earning double incentivizes operators to run exits, which is the scarce resource (same dynamic as Tor, where exits are always underrepresented). The split can be adjusted via governance or hardcoded — start with a hardcoded default and evaluate after mainnet data.

### Staking as Competitive Advantage

The client's node scoring algorithm should weight stake size meaningfully. This creates a natural incentive to stake more than the minimum:

- Minimum stake (0.1 ETH): eligible for selection, but ranked below higher-staked nodes
- Medium stake (0.5–1 ETH): noticeably higher selection priority
- High stake (2+ ETH): preferred for the entry node position (most trusted hop, first point of contact)

This means staking isn't just a security deposit — it's a revenue accelerator. An operator who stakes 1 ETH will get meaningfully more sessions routed to them than one who stakes the minimum, even if their price and latency are identical. Document this clearly in operator onboarding materials so the incentive is transparent.

### Bootstrapping Strategy (Phase 1–3)

The critical problem: users won't join without nodes providing good coverage, and nodes won't join without users generating revenue. This is the classic two-sided marketplace cold start.

**Step 1: Foundation-operated seed nodes (Phase 1)**
- Deploy 5–10 nodes across major geographic regions (US East, US West, EU West, EU Central, Asia) before public client release
- These are operated by the core team and run at cost — not for profit, but to ensure minimum viable coverage
- Clearly labeled in the registry as foundation nodes (via a metadata field) so users know the network is bootstrapping
- Foundation nodes set a reference price-per-byte that anchors the market

**Step 2: Early operator incentives (Phase 2–3)**
- Implement a temporary `BootstrapRewards` contract that distributes bonus ETH to the first N nodes (e.g., first 50) that register and maintain >95% uptime for their first 30 days
- Fund this from an initial allocation (team funds, not a token — stay ETH-only)
- Suggested: 0.05 ETH bonus per node for the first 30 days of clean operation. Total cost for 50 nodes: 2.5 ETH (~$5,000). This is cheap customer acquisition for a network
- The bonus phases out as organic revenue from user sessions replaces it
- After the bootstrap period, the `BootstrapRewards` contract can be deprecated (or its funds returned to treasury)

**Step 3: Geographic targeting (Phase 1–3)**
- Don't try to cover the globe at launch. Pick one region (Europe is a good fit — strong privacy culture, favorable legal environment, dense internet infrastructure, and Zurich is a natural starting point)
- Concentrate early nodes in that region so users there get good latency (sub-50ms to at least 3 nodes for any circuit)
- Expand to North America in Phase 4, Asia in Phase 5+

**Step 4: Operator onboarding tooling (Phase 3+)**
- One-command setup: `curl -sSf https://shieldnode.xyz/install | sh` that installs the node binary, generates keys, walks through staking, and registers on-chain
- Docker image: `docker run shieldnode/relay` with environment variables for stake wallet and config
- Dashboard: a local web UI (served by the node binary) showing earnings, sessions served, bandwidth stats, heartbeat status, and stake health
- Clear documentation on: ISP requirements (upload speed, no throttling), legal considerations for exit nodes by jurisdiction, hardware recommendations, expected earnings at different utilization levels

### Exit Node Incentive Problem

Exit nodes are the hardest to recruit because they carry legal exposure — their IP address is what the destination sees. This is the same problem Tor has. Mitigations:

- **Higher revenue share** (50% vs 25% for entry/relay, as described above)
- **Exit node staking tier**: optionally require higher minimum stake for exit nodes (e.g., 0.5 ETH vs 0.1 ETH for relay-only), which both signals commitment and provides a larger slashing buffer
- **Operator legal guide**: publish a jurisdiction-by-jurisdiction overview of the legal landscape for running a traffic relay. Partner with a crypto-friendly law firm to produce this. It won't eliminate risk but it reduces the "I don't know what I'm getting into" barrier
- **Relay-only mode as default**: the node binary should default to relay-only (middle hop). Exit mode is opt-in, with a clear explanation of what it means. This ensures most operators can participate with minimal risk while exit operators self-select
- **Exit node geographic tags**: let exit operators declare which countries they're willing to serve as an exit for. Some operators may be comfortable exiting traffic in privacy-friendly jurisdictions (Switzerland, Iceland, Netherlands) but not others

### Long-Term Sustainability

The network is self-sustaining when organic user demand generates enough session revenue that node operators earn a positive return above their costs without bootstrap subsidies. Key metrics to track:

- **Network utilization rate**: total bandwidth served / total bandwidth capacity. Below 10% means the network is over-provisioned (too many nodes for the user base). Above 70% means users are experiencing congestion and more nodes are needed
- **Operator churn**: if nodes are deregistering faster than new ones join, the economics aren't working. Investigate whether it's a pricing issue, utilization issue, or UX issue
- **Price convergence**: as the market matures, price-per-byte should converge to a narrow band across nodes. If there's wide dispersion, the scoring algorithm may need tuning
- **Exit node ratio**: healthy target is at least 30% of nodes running as exits. Below 20% means the exit incentives need to increase

Build a public analytics dashboard (read-only, pulling from L1 events) that shows these metrics. Transparency about network health builds operator confidence.

---

## Development Environment

- **Rust**: latest stable (1.77+). Use `cargo clippy` and `cargo fmt` on every change
- **Node/TypeScript**: Node 20+, pnpm as package manager
- **Solidity**: Foundry (`forge build`, `forge test`). Solidity 0.8.24+
- **Testing**: Rust unit + integration tests, Foundry fuzz tests for contracts, Playwright for client E2E
- **CI**: GitHub Actions — lint, test, build for all three subsystems on every PR
- **L1 testing**: Use Sepolia for testnet deployment. Use Foundry's `anvil` for local development (fork mainnet state for gas estimation accuracy). Before mainnet deployment, do a full dress rehearsal on Holesky
- **Monorepo structure:**

```
shieldnode/
├── CLAUDE.md                   # This file
├── node/                       # Rust relay node
├── contracts/                  # Solidity smart contracts (Ethereum L1)
├── circuits/                   # ZK circuits (circom or Noir)
├── client/                     # Tauri + React client app
├── packages/
│   └── shared-types/           # Shared TypeScript types (contract ABIs, etc.)
├── docs/                       # Architecture docs, protocol spec
│   ├── ARCHITECTURE.md         # System overview + trust model
│   ├── PROTOCOL.md             # Sphinx packet format, circuit construction
│   ├── ECONOMICS.md            # Session pricing, staking parameters, gas analysis
│   ├── ZK-DESIGN.md            # ZK integration rationale, circuit specs, proving benchmarks
│   └── THREAT-MODEL.md         # What we defend against, what we don't
├── .github/
│   └── workflows/
│       ├── node.yml
│       ├── contracts.yml
│       ├── circuits.yml        # Compile circuits, run proof tests
│       └── client.yml
└── README.md
```

---

## Key Design Principles

1. **Ethereum L1 native**: every on-chain operation happens on Ethereum mainnet. No L2, no sidechain, no bridge. Users inherit Ethereum's full security and decentralization properties directly. Post-Fusaka gas economics make this viable without compromise
2. **No trust required**: every claim a node makes must be verifiable — on-chain, cryptographically, or both. The on-chain data lives on the most battle-tested, censorship-resistant smart contract platform in existence
3. **Privacy by architecture**: the system should make surveillance structurally impossible, not just policy-prohibited. A node operator who WANTS to log should be unable to
4. **Economic alignment**: node operators earn more by being honest and reliable. Misbehavior costs real ETH via slashing on L1 — not some L2 token that might be worth nothing
5. **Immutable contracts**: deploy without upgrade proxies wherever possible. If you can't upgrade the contracts, you can't rug the users. This is the same property that made Fuel v1 and DeGate achieve Stage 2 — immutability is the strongest form of exit window. Trade off carefully: immutability means bugs are permanent, so the audit bar is higher
6. **Client sovereignty**: the client should be able to verify everything independently. Support self-hosted RPC endpoints (Reth, Geth). Never depend on a centralized API. A user running their own Ethereum node + ShieldNode client has zero external trust dependencies
7. **Graceful degradation**: if the Ethereum network is congested and gas temporarily spikes, the tunnel itself should still work. Bandwidth receipts accumulate locally and settle when gas returns to normal. Never let the payment layer break the privacy layer

---

## What NOT to Build (Scope Boundaries)

- **Mobile client**: defer to Phase 6+. Desktop first (Tauri)
- **Any L2 deployment**: the entire point is L1 nativity. Do not build on Base, Arbitrum, or any rollup. If someone asks "why not L2?", point them to the trust model documentation
- **Token**: no governance token, no utility token. ETH only for staking, sessions, and slashing. Tokens add regulatory complexity and distract from the core product
- **Browser extension**: defer. Standalone app first
- **Free tier**: every byte costs someone money. No freemium. Keep it pay-per-use from day one so the economics are honest
- **Custom RPC infrastructure**: don't run centralized RPC endpoints for users. Encourage self-hosting. Provide a curated list of public RPCs as defaults but make it clear these are convenience, not endorsed trust relationships
- **Upgradeable contracts**: avoid unless absolutely necessary for early iteration. Document the justification for any proxy pattern. If upgradeable, enforce a 30-day timelock minimum — hold yourself to the same standard you'd demand from an L2

---

## Reference Projects & Prior Art

Study these for implementation ideas (not to copy, but to understand tradeoffs):

- **Orchid (orchid.com)**: pioneered crypto-payment VPN. Good payment model, but single-hop and centralized node discovery. Built on their own L2-like system — we avoid this by going L1 direct
- **HOPR (hoprnet.org)**: mixnet with staking. Strong on privacy theory, complex in practice
- **Nym (nymtech.net)**: mixnet with Sphinx packets. Most relevant for the onion routing layer. Study their Sphinx implementation closely
- **Mullvad VPN**: gold standard for VPN UX and trust model (anonymous accounts, no email required). Target this UX quality but with cryptoeconomic verification replacing policy-based trust
- **WireGuard**: the tunnel protocol itself. Read the whitepaper. Understand why it's better than OpenVPN/IPSec
- **Fuel v1 / DeGate v1**: the only Ethereum projects to achieve L2Beat Stage 2. Both did it by deploying immutable contracts. This is the model for our contract design philosophy
- **Aztec Network / Noir**: Noir is the most developer-friendly ZK circuit language currently available. Study their documentation for circuit design patterns, especially around signature verification and Merkle proof inclusion — both are needed for our bandwidth receipt circuit
- **Tornado Cash (archived)**: the canonical example of ZK privacy on Ethereum L1. Study the deposit/withdrawal commitment scheme and nullifier pattern — our ZK settlement uses a similar conceptual model (prove you have a valid receipt without revealing which one). Be aware of the legal context around Tornado Cash when discussing ShieldNode publicly
- **RISC Zero / SP1**: ZK-VM projects that can prove arbitrary Rust program execution. Monitor their benchmark improvements — if proving costs drop 100x, Tier 4 (ZK honest relay) becomes feasible. Not a dependency today, but a key long-term enabler

---

## Ethereum L1 Considerations

Since all on-chain operations are on Ethereum mainnet, keep these in mind:

**Block time**: Ethereum L1 blocks are ~12 seconds. This means `openSession()` takes ~12 seconds to confirm (one block). For the VPN use case this is acceptable — the user clicks "Connect", sees a brief "establishing session on Ethereum..." state, and the tunnel is live within 15–20 seconds total. Phase 6 explores preconfirmations to reduce this.

**Reorg risk**: Ethereum finality takes ~15 minutes (2 epochs). For session opening, don't wait for finality — 1 confirmation is sufficient since the deposit is small. For settlement, waiting for finality is ideal but not blocking; the settlement can be re-submitted if reorged.

**Gas spikes**: while current average is <0.2 Gwei, gas can spike during NFT mints, market crashes, or network events. Design the client to:
- Show estimated cost before every L1 transaction
- Allow configurable gas price ceiling (don't submit if gas > user's threshold)
- Queue settlements during spikes and batch-settle when gas drops
- Never let gas spikes interrupt an active tunnel — the tunnel is off-chain, only opening/settlement is on-chain

**RPC dependency**: reading the NodeRegistry requires an Ethereum RPC. This is a centralization risk. Mitigate by:
- Supporting multiple fallback RPCs
- Caching the node list locally with a configurable refresh interval
- First-class support for self-hosted nodes (Reth recommended — aligns with your existing infrastructure interest)
- The DHT provides an alternative discovery path that doesn't require RPC at all

**Contract immutability vs. upgradability**: strongly prefer immutable deployment. If a critical bug is found post-deployment, the mitigation path is: deploy a new contract version, have nodes migrate their stake to the new contract, update clients to point to the new address. This is more disruptive than a proxy upgrade but preserves the trust model. Document this migration path before mainnet deployment.

---

## ZK Integration Roadmap

Zero-knowledge proofs are integrated where they improve privacy or trust properties without touching the performance-critical hot path (packet routing). The guiding principle: ZK proofs are generated *after the fact* or *periodically*, never per-packet. The tunnel must never wait on a prover.

### Tier 1: ZK Bandwidth Receipt Privacy (Phase 4–5)

**Problem**: the current `SessionSettlement` contract sees session IDs, node addresses, byte counts, and timestamps in cleartext on L1. Anyone watching the chain can reconstruct usage patterns — which wallets use which nodes, how much data they transfer, and when.

**Solution**: at settlement time, the client generates a ZK proof that says:
- "I hold a valid bandwidth receipt co-signed by both myself and the circuit nodes"
- "The receipt specifies X bytes transferred"
- "The correct payment for X bytes at the agreed price is Y ETH"
- "The payment should be split Z1/Z2/Z3 across three addresses"

The proof is verified on-chain by `ZKSettlement.sol`. The contract distributes payment without ever seeing the session ID, the specific node identities (payments go to stealth addresses or note commitments), or exact timing correlations.

**What the chain sees (before ZK)**: wallet 0xABC opened session #47 with nodes [0x1, 0x2, 0x3], transferred 1.2 GB, settled at block 19847362.

**What the chain sees (after ZK)**: a valid proof was submitted, 0.0024 ETH was distributed to three commitments, remainder refunded to a shielded address.

**Technical approach:**
- **Proving system**: evaluate Groth16 (cheapest on-chain verification, ~200K gas, but requires trusted setup per circuit) vs Plonk/HALO2 (no trusted setup, slightly higher verification cost ~300K gas, more flexible). For a single well-defined circuit like receipt verification, Groth16 is likely the pragmatic choice. Use `snarkjs` or `circom` for circuit development, or Noir (from Aztec) for a more developer-friendly Rust-like DSL
- **Circuit inputs (private)**: session ID, node public keys, cumulative byte count, both signatures, price-per-byte, payment split ratios
- **Circuit inputs (public)**: total payment amount, three payment destination commitments, refund commitment, Merkle root of registered nodes (to prove the nodes are valid without revealing which ones)
- **On-chain verifier**: auto-generated from the circuit. Deploy as `ZKSettlement.sol` alongside the existing `SessionSettlement.sol`. Both contracts share the same deposit pool; the difference is only in how settlement is proven
- **Client-side proving time**: target <5 seconds on modern hardware (M1/M2 Mac, recent x86). This runs after disconnect — the user sees "settling session privately..." for a few seconds. Acceptable UX
- **Fallback**: if ZK proving fails or the user's hardware is too slow, fall back to plaintext settlement via `SessionSettlement.sol`. Privacy is opt-in, not a hard requirement

**File structure additions:**
```
contracts/
├── src/
│   ├── ZKSettlement.sol          # Verifier contract for ZK settlement proofs
│   └── verifiers/
│       └── BandwidthVerifier.sol  # Auto-generated from circuit (Groth16 or Plonk)
├── test/
│   └── ZKSettlement.t.sol
circuits/
├── bandwidth_receipt/
│   ├── circuit.circom            # Or circuit.nr if using Noir
│   ├── input.json                # Example witness for testing
│   └── README.md                 # Circuit documentation: what's proved, what's leaked
├── scripts/
│   ├── compile.sh                # Compile circuit, generate verifier
│   ├── prove.sh                  # Generate test proof
│   └── verify.sh                 # Verify test proof
└── trusted_setup/                # Groth16 ceremony artifacts (if using Groth16)
    └── README.md                 # Document the setup ceremony process
```

**Gas budget**: ZK settlement will cost more per transaction than plaintext settlement (~200K–300K gas vs ~120K), but at <0.2 Gwei this is the difference between $0.05 and $0.12. The privacy gain is worth the extra $0.07.

### Tier 2: ZK Node Eligibility Proofs (Phase 6)

**Problem**: the `NodeRegistry` is a public list of every node in the network — their addresses, stakes, endpoints, and history. An adversary (state actor, competing VPN, DDoS attacker) can enumerate the entire network trivially by reading the contract.

**Solution**: migrate the registry to a commitment-based model:
- When a node registers, it posts a commitment (hash of: node public key, stake amount, endpoint, salt) instead of plaintext data
- When a client wants to build a circuit, available nodes provide ZK proofs that they are registered, meet minimum criteria (sufficient stake, no active slashes, recent heartbeat), and are currently online — without revealing which commitment is theirs until the encrypted handshake begins
- The client verifies the proof, establishes the circuit, and only then learns the node's actual endpoint (delivered via the encrypted handshake, not readable from the chain)

**Why this matters**: in the plaintext model, a government can subpoena or block every ShieldNode IP by reading Etherscan. In the ZK model, the node set is hidden — the network's size and composition are private. An adversary would need to compromise the DHT layer or perform active probing to discover nodes, which is significantly harder.

**Technical complexity**: this is substantially harder than Tier 1. It requires:
- A Merkle tree of node commitments maintained on-chain (gas-intensive to update, but heartbeats already touch the chain)
- Nullifier-based freshness proofs (to prevent replaying old eligibility proofs after being slashed)
- An encrypted channel for the client to learn the node's actual endpoint after verifying eligibility
- Careful design to prevent Sybil attacks (one operator pretending to be many nodes behind different commitments)

**Recommendation**: design the `NodeRegistry` from the start with a `bytes32 commitment` field alongside the plaintext fields. In Phase 1–5, both are populated. In Phase 6, the plaintext fields become optional and the commitment-based path is the default. This avoids a contract migration later.

### Tier 3: ZK No-Log Compliance Proofs (Phase 6+)

**Problem**: the challenge-response protocol for detecting logging is inherently reactive — it catches misbehavior after the fact. Nodes could log silently for weeks before a challenge exposes them.

**Solution**: nodes periodically generate a ZK proof that their operational state (memory contents, disk storage) does not contain connection metadata from previous sessions. Specifically:
- The node commits to a hash of its full memory/storage state at time T
- The node proves that this state, when searched for patterns matching IP addresses, session identifiers, or timing correlations from sessions before T minus a buffer period, returns no matches
- The proof is posted on-chain (or submitted to challengers) as evidence of compliance

**Limitations** (be honest about these):
- This only proves the *node software's declared state* is clean. A malicious operator could run a separate logging process outside the node binary that captures traffic at the OS level. ZK proofs can't prevent this
- The definition of "connection metadata patterns" must be precise and comprehensive. If the proof checks for IP address patterns but not timing correlations, a node could log timing data and pass the proof
- Proof generation over the full memory state is computationally expensive. May need to scope it to specific data structures rather than raw memory

**Practical value**: this is most useful against honest-but-curious operators — people running the standard node software who might wonder "does this thing log anything?" The proof gives them (and their users) cryptographic assurance that the software is behaving as documented. Against a state-level adversary who modifies the node binary, it provides less protection, but that threat model is partially addressed by the multi-hop architecture (compromising one node is insufficient).

**Recommendation**: begin research in Phase 6. Don't promise this as a feature until the proof system is demonstrated to be both sound and practical. This is the kind of feature that's easy to market and hard to deliver correctly.

### Tier 4: ZK Proof of Honest Relay (Research Only)

**The endgame**: instead of trusting nodes and checking after the fact, every relay operation is accompanied by a proof that the node correctly decrypted its onion layer, forwarded the payload to the next hop, and discarded the contents.

**Current state**: this requires proving general-purpose computation (WireGuard decryption, ChaCha20-Poly1305 operations, packet forwarding logic) inside a ZK circuit. Current proving systems can handle this but at prohibitive cost — generating a proof for a single packet decryption might take seconds, while packets arrive every millisecond. The math doesn't work for real-time proving.

**What could change**: ZK-VM systems (RISC Zero, SP1, Valida, Jolt) are improving rapidly. If proving costs drop 100–1000x (plausible over 2–3 years given current trajectory), batch proving becomes viable: a node could prove "I correctly relayed all N packets in the last 10 minutes" in a single proof generated during idle time. This wouldn't be real-time but would provide near-continuous compliance verification.

**Architecture prep**: even though we won't build this soon, structure the node's relay logic to be provable later:
- Keep the forwarding path (decrypt layer → extract next hop → forward payload) in a pure function with no side effects or I/O
- Use deterministic data structures (no hash maps with random ordering) in the hot path
- Log (locally, for the operator) the inputs and outputs of the forwarding function in a structured format that could serve as a ZK witness — but only when explicitly enabled in debug mode, never in production
- Avoid inline assembly or platform-specific optimizations in the forwarding path that would be hard to replicate in a ZK circuit

**Do NOT build this in any phase currently planned.** Flag it as a research direction in `docs/ARCHITECTURE.md` with the heading "Future: ZK Honest Relay" and revisit when ZK-VM benchmarks improve.

### ZK Tooling & Dependencies

| Tool | Use case | Notes |
|------|----------|-------|
| circom + snarkjs | Tier 1 circuit development (if choosing Groth16) | Mature, well-documented, large community. Circom is a DSL — not Rust, but the circuits are small enough that this is acceptable |
| Noir (Aztec) | Tier 1 circuit development (alternative) | Rust-like syntax, no trusted setup (uses UltraPlonk), better developer experience. Evaluate maturity at time of implementation |
| RISC Zero / SP1 | Tier 3–4 research | ZK-VMs that can prove arbitrary Rust execution. Monitor benchmark improvements quarterly |
| Groth16 verifier | On-chain verification | ~200K gas. Auto-generated from circuit. Well-understood security properties |
| Plonk verifier | On-chain verification (alternative) | ~300K gas. No trusted setup. Slightly more future-proof |

**Recommendation**: start with circom + Groth16 for Tier 1. It's the most gas-efficient on-chain verifier and the circuit (bandwidth receipt verification) is well-scoped enough that the trusted setup is manageable. If the project grows to need multiple circuits (Tier 2+), migrate to a universal setup system (Plonk family) to avoid per-circuit ceremonies.

---

## Notes for Claude Code

- When generating Rust code, prefer `thiserror` for error types and `anyhow` for application-level error handling
- For async Rust, use `tokio` with `#[tokio::main]` entry point. Prefer `tokio::select!` over manual future polling
- For contract interactions in TypeScript, use `viem` over `ethers.js` (newer, better typed, tree-shakeable)
- For contract interactions in Rust, evaluate `alloy` (the Rust equivalent of viem, from the same team) vs `ethers-rs`. Prefer `alloy` if mature enough at time of implementation
- All cryptographic operations should use audited crates (`dalek`, `ring`, `rustcrypto`). Never roll custom crypto
- EIP-712 typed data signing is critical for bandwidth receipts — use well-tested libraries for this on both client and node side
- Write tests as you go. Minimum: unit tests for all crypto operations, integration tests for circuit construction, fuzz tests for contract edge cases (especially SessionSettlement — this holds user funds)
- Commit messages should be conventional commits format: `feat(node): add circuit construction`, `fix(client): handle tunnel reconnection`, etc.
- If you hit an architectural decision point not covered here, bias toward simplicity and document the tradeoff for later revision
- When estimating gas costs, always measure on a Sepolia fork with `anvil` rather than guessing. Gas estimates in this document are approximate — validate them
- All contract events should be richly indexed for client-side filtering. The client reads L1 state directly; there is no backend API to paper over missing indices
- For ZK circuit development: if using circom, the circuits are small and self-contained — don't over-engineer the build system. A shell script that runs `circom`, generates the witness, and produces the verifier Solidity contract is sufficient for Phase 4. If using Noir, `nargo compile` and `nargo prove` handle the pipeline
- ZK verifier contracts are auto-generated — do not hand-edit them. Treat them as build artifacts. The source of truth is the circuit definition
- When implementing client-side proof generation, benchmark on low-end hardware (4-year-old laptop, 8 GB RAM) to ensure the proving time stays under the target (<5 seconds). If it exceeds this, the circuit may need optimization or the proving system may need to change
- The `NodeRegistry` should include a `bytes32 commitment` field from day one, even if it's unused until Phase 6. Adding a field later requires a new contract deployment and stake migration. Adding it now costs a few extra bytes of storage per node (~$0.001 at current gas)
- Keep the relay forwarding path in `node/src/tunnel/circuit.rs` as a pure function with deterministic behavior. This is not just good engineering — it's prep for potential ZK-VM proving of the forwarding logic in the long term. No hash maps, no random ordering, no side effects in the hot path
