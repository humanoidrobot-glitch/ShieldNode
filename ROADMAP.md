# ShieldNode Roadmap

This document tracks the development milestones for ShieldNode. Each phase builds on the previous one, progressing from a functional single-hop relay to a fully decentralized, ZK-private VPN network on Ethereum L1.

---

## Phase 1: Single-Hop Tunnel (MVP) `← current`

The foundation: a working relay node, on-chain contracts, and a basic client.

### Completed
- [x] **Relay node binary** — WireGuard tunnel (boringtun), UDP listener with peer management, Sphinx onion routing, HKDF-SHA256 key derivation, ChaCha20-Poly1305 encryption, libp2p discovery (Kademlia + Gossipsub + mDNS), heartbeat service, metrics HTTP API
- [x] **Node wired end-to-end** — All services orchestrated via tokio (UDP listener, metrics API, heartbeat, libp2p discovery), persistent key management (load-or-generate), graceful Ctrl+C shutdown, stale peer eviction
- [x] **NodeRegistry contract** — 0.1 ETH minimum stake, 6h heartbeat interval, 7-day unstake cooldown, paginated `getActiveNodes()`, oracle-only slashing, `commitment` field reserved for Phase 6 ZK eligibility
- [x] **SessionSettlement contract** — EIP-712 bandwidth receipts, 25/25/50 payment split (entry/relay/exit), 0.001 ETH minimum deposit, 1-hour force-settle timeout for absent clients
- [x] **SlashingOracle contract** — Authorized challengers, 24-hour grace period, progressive slashing (10% / 25% / 100% + permanent ban), 50/50 split between challenger and treasury
- [x] **Treasury contract** — Receives slash proceeds, 48-hour timelock on withdrawals
- [x] **Test suite** — 19 Foundry tests passing (12 NodeRegistry + 7 SessionSettlement)
- [x] **Tauri client scaffold** — Rust backend with 6 Tauri commands (connect, disconnect, get_status, get_nodes, get_session, get_gas_price), tunnel/circuit/wallet/receipt modules. React frontend with dark-themed UI: ConnectToggle, CircuitMap, NodeBrowser (sortable/filterable), SessionCost, GasMonitor (color-coded), Settings (RPC, kill switch, auto-rotate, gas ceiling)

### Remaining
- [x] **Contracts deployed to Sepolia** — NodeRegistry (`0xC6D9...df11`), SessionSettlement (`0xF32a...E959`), SlashingOracle (`0x28E5...8FeD`), Treasury (`0xaE76...619f`)
- [ ] Node registers on-chain, client reads registry to discover nodes
- [ ] End-to-end session lifecycle: client opens session with deposit, bandwidth receipts flow, settlement on disconnect
- [ ] TUN device / raw socket integration for actual IP packet forwarding (exit mode)

**Success metric:** Browse the internet through a single ShieldNode relay and pay for it on L1 testnet.

---

## Phase 2: Multi-Hop + Onion Routing

Privacy through layered encryption — no single node sees both source and destination.

### Completed
- [x] **Sphinx packet format** — `create()` and `peel_layer()` for building and processing onion-encrypted packets
- [x] **Circuit management** — `CircuitManager` with create/teardown lifecycle, pure `process_relay_packet()` function designed for future ZK provability
- [x] **Noise NK handshake** — Session key establishment between any two nodes using X25519 DH

### Remaining
- [ ] 3-hop circuit construction in client (entry -> relay -> exit)
- [ ] Live traffic forwarding: each node peels its encryption layer and forwards to next hop
- [ ] Circuit visualization in client UI (show which 3 nodes you're routed through)
- [ ] Bandwidth receipt co-signing between client and all 3 circuit nodes
- [ ] Auto-rotate circuits periodically for forward secrecy

**Success metric:** Traffic routes through 3 independent nodes; no single node can see both source and destination.

---

## Phase 3: Staking + Slashing

Cryptoeconomic security — honest behavior earns ETH, misbehavior costs ETH.

### Completed
- [x] **Minimum stake** — 0.1 ETH enforced in NodeRegistry
- [x] **Slashing oracle** — Accepts evidence, executes slashes with 24-hour grace period
- [x] **Unstaking cooldown** — 7-day waiting period prevents stake-and-run attacks
- [x] **Progressive slashing** — 10% first offense, 25% second, 100% + permanent ban on third

### Remaining
- [x] **Client node scoring** — Weighted algorithm (30% uptime, 25% stake via log scale, 25% price inverse, 20% slash penalty) implemented in both Rust backend and TypeScript frontend
- [ ] Stake-weighted selection: higher-staked nodes get more session routing (revenue accelerator)
- [ ] Slashing evidence verification: cryptographic proofs for logging, selective denial, bandwidth fraud

**Success metric:** A slashed node loses stake on Sepolia and is deprioritized by clients.

---

## Phase 4: Economic Hardening + ZK Settlement Privacy

Make the economics self-sustaining and add privacy to on-chain settlements.

### Completed
- [x] **Market-driven pricing** — Nodes set their own price-per-byte in the registry (`updatePricePerByte`)
- [x] **Treasury** — Receives 50% of slashed stake

### Remaining
- [ ] Client displays estimated session cost before connection
- [x] **Gas price monitoring** — GasMonitor component with color-coded Gwei display (green < 1, yellow 1-5, red > 5), polls every 30s, configurable gas ceiling in Settings
- [ ] Stress test: simulate 100+ concurrent sessions, measure L1 settlement throughput
- [ ] Design ZK bandwidth receipt circuit (circom or Noir): define the statement to prove, select proving system, build initial circuit
- [ ] Implement `ZKSettlement.sol` verifier contract alongside `SessionSettlement.sol` — both paths work, ZK is opt-in
- [ ] Client-side proof generation for private settlement (<5s on modern hardware)

### What ZK Settlement Achieves
**Before ZK:** The chain sees wallet `0xABC` opened session #47 with nodes `[0x1, 0x2, 0x3]`, transferred 1.2 GB, settled at block 19847362.

**After ZK:** A valid proof was submitted, 0.0024 ETH was distributed to three commitments, remainder refunded to a shielded address. No session ID, no node identities, no timing correlation.

**Success metric:** The economic loop works end-to-end. At least one session settles via ZK proof on testnet.

---

## Phase 5: Mainnet Launch

Security audits, hardening, and public deployment.

- [ ] Security audit of all contracts (prioritize SessionSettlement, ZKSettlement, and NodeRegistry — these hold funds)
- [ ] Security audit of node software (prioritize crypto operations and memory handling)
- [ ] Audit of ZK circuit correctness — proof must not allow over-claiming or underpaying
- [ ] Kill switch, auto-rotate circuits, and circuit pinning fully functional in client
- [ ] Challenge-response protocol v1 (trusted challenger set)
- [ ] Deploy immutable contracts to Ethereum mainnet (no proxy)
- [ ] ZK settlement as default for privacy-conscious users, plaintext settlement as fallback
- [ ] Documentation site: how to run a node, use the client, verify the contracts
- [ ] At least 10 independently operated nodes live before public client release

**Success metric:** Real users browsing through ShieldNode on Ethereum mainnet, with ZK-private settlement available.

---

## Phase 6: Decentralization + Growth

Remove all remaining centralization points and scale the network.

- [ ] **Decentralize challenge-response** — Challenge bonds replace the trusted challenger multisig; anyone can challenge by posting a bond
- [ ] **Mobile client** — iOS and Android (defer until desktop is stable)
- [ ] **Operator onboarding** — One-click setup: `docker run shieldnode/relay`, local dashboard for earnings/health
- [ ] **Preconfirmations (EIP-7917)** — Sub-slot session opening (<1s tunnel establishment vs. current 12s block time)
- [ ] **ZK node eligibility proofs** — Commitment-based registry where nodes prove they meet selection criteria (stake, uptime, no slashes) without revealing which node they are. Hardens against enumeration attacks by state actors
- [ ] **ZK no-log compliance proofs** — Nodes periodically prove their operational state contains no connection metadata. Most useful against honest-but-curious operators
- [ ] **ZK proof of honest relay (research)** — Evaluate whether ZK-VM systems (RISC Zero, SP1, Valida) are mature enough to prove correct packet forwarding. Depends on 100x proving cost reduction. Node relay logic is already structured as a pure function to enable this

---

## Bootstrapping Strategy

The cold-start problem: users need nodes for coverage, nodes need users for revenue.

1. **Foundation seed nodes** — 5-10 nodes across major regions (US East/West, EU West/Central, Asia) operated by the core team before public client release
2. **Early operator incentives** — `BootstrapRewards` contract: 0.05 ETH bonus per node for the first 50 operators maintaining >95% uptime for 30 days. Total cost: ~2.5 ETH
3. **Geographic focus** — Start in Europe (strong privacy culture, dense infrastructure), expand to North America in Phase 4, Asia in Phase 5+
4. **Exit node incentives** — 2x revenue share (50% vs 25%), optional higher stake tier, jurisdiction-by-jurisdiction legal guide, relay-only as default (exit is opt-in)

---

## Non-Goals (Scope Boundaries)

These are explicitly out of scope to maintain focus:

- **No L2 deployment** — The entire point is L1 nativity
- **No token** — ETH only for staking, sessions, and slashing
- **No free tier** — Pay-per-use from day one
- **No browser extension** — Standalone desktop app first
- **No centralized RPC infrastructure** — Encourage self-hosting
- **No upgradeable contracts** — Unless absolutely necessary, with 30-day timelock minimum
