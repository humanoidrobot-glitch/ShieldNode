# ShieldNode — Funding & Grant Options

This document tracks viable funding sources for two specific needs: **node bootstrapping incentives** (~2.5 ETH / ~$5K for first 50 operators) and **Solidity contract audits** (SessionSettlement, ZKSettlement, NodeRegistry, SlashingOracle — all fund-holding contracts).

---

## 1. Ethereum Foundation — Ecosystem Support Program (ESP)

**URL**: https://esp.ethereum.foundation
**What it is**: The EF's primary grant program. Supports open-source projects focused on infrastructure, research, tooling, and public goods. Has funded 900+ projects totaling $148M+.

**How it works now**: Restructured in late 2025 from open applications to two pathways:
- **Wishlist**: broad thematic priorities (privacy, cryptography, security, decentralized infrastructure). Builders propose how to address them.
- **RFPs**: specific scoped problems with defined deliverables and timelines.

**Why ShieldNode fits**:
- Open-source privacy infrastructure on Ethereum L1 — directly aligned with ESP's mandate
- ZK settlement research is novel application of ZK proofs on L1
- Hybrid PQ key exchange implementation is ahead of Ethereum's own PQ timeline and reusable by other projects
- Current Wishlist includes items around privacy (ZK attestations, selective disclosure) and decentralized RPC access — ShieldNode's philosophy parallels both

**What to apply for**: A single grant covering multiple deliverables:
- Node bootstrapping incentives (BootstrapRewards contract + initial 2.5 ETH allocation)
- ZK bandwidth receipt circuit development and audit
- PQ handshake implementation as reusable open-source library
- Contract security audit (ESP has funded audits for other grantees before)

**Process**:
1. Book **Office Hours** first (free, non-financial support): get feedback on framing before formal application
2. Submit Wishlist application matching the closest thematic item
3. Review takes 3-6 weeks. If selected: KYC, legal agreement, milestone-based payments
4. Grant evaluator assigned for check-ins and milestone reviews
5. Results shared publicly in a report or post at completion

**Requirements**: all funded output must be open-source. For-profit entities can apply but grant-funded work must be public good. Budget expectations are below standard market rates (non-dilutive capital).

**Estimated ask**: $30K-80K covering bootstrapping, ZK circuit development, PQ library, and audit coordination. The EF has funded similarly scoped infrastructure projects.

**Timeline**: rolling applications, no deadline for Wishlist items.

---

## 2. Gitcoin Grants (Quadratic Funding)

**URL**: https://gitcoin.co
**What it is**: Community-driven funding rounds using quadratic funding. Many small donations get amplified by a matching pool. Multiple rounds per year across different categories.

**Why ShieldNode fits**: privacy infrastructure is perennially popular with the Gitcoin community. Projects that resonate ideologically (decentralization, no token, ETH-native) tend to overperform on community donations.

**Realistic funding**: $5K-50K per round from matching pools + direct donations. Won't cover a full audit alone, but good supplemental funding and excellent for visibility/community building.

**Best use**: bootstrapping incentives specifically. The narrative ("help us fund the first 50 independent VPN nodes on Ethereum") is compelling for quadratic funding where number of contributors matters more than donation size.

**Process**: create a project profile, apply to relevant rounds (privacy, infrastructure, public goods), build community support during the round.

---

## 3. Code4rena — Competitive Audit (Zero Platform Fee)

**URL**: https://code4rena.com
**What it is**: competitive audit platform where 100+ independent security researchers examine your code simultaneously. Acquired by Zellic in 2025.

**Key development**: Code4rena now runs all audit competitions for **zero platform fee**. You only pay the prize pool (rewards for researchers who find bugs) and the judging fee. This makes it the most cost-effective path to a serious audit.

**How it works**:
- You set a prize pool (the budget). Researchers compete to find bugs. Higher-severity findings earn more.
- An independent judge triages all submissions (often hundreds of reports)
- You get a final report with all findings categorized by severity

**Estimated cost for ShieldNode**:
- ShieldNode's contracts are ~4 contracts, moderate complexity (EIP-712 signatures, payment splitting, staking/slashing logic)
- Prize pool: $15K-30K for a meaningful contest that attracts serious researchers
- Judging fee: additional (varies)
- No platform fee (currently waived)
- Total: ~$15K-35K

**Strengths**: massive researcher breadth (16,000+ registered), fast turnaround (1-2 week contest window vs months for private firms), public report builds credibility.

**Weakness**: no post-audit coverage or insurance. Quality depends on which researchers participate in your specific contest.

**Best use**: primary audit vehicle for the Solidity contracts. Pair with a private audit of the ZK circuit (see below).

---

## 4. Sherlock — Competitive Audit + Coverage

**URL**: https://sherlock.xyz
**What it is**: competitive audit platform similar to Code4rena but with a key differentiator — post-audit exploit coverage (insurance). If a Sherlock-audited project gets exploited, Sherlock provides financial coverage.

**Estimated cost**:
- Prize pool model: $20K-60K for ShieldNode's scope
- Includes post-audit coverage (unique selling point)
- Can start a contest within 48 hours (no booking queue)

**Strengths**: exploit coverage is valuable for a project holding user deposits. Faster than private firm booking queues. Senior researcher curation.

**Weakness**: more expensive than Code4rena (which is now free platform fee). Coverage terms have limits.

**Best use**: consider for a second audit round post-mainnet, especially once real funds are at stake and the coverage matters.

---

## 5. Private Audit Firms (Traditional)

For the ZK circuit audit specifically, competitive platforms are less suitable — ZK circuit security is specialized and benefits from dedicated expert review rather than broad competition.

**Top firms for ZK + Solidity**:

| Firm | Strength | Estimated Cost | Notes |
|------|----------|---------------|-------|
| **OpenZeppelin** | Gold standard, EF client | $80K-150K+ | Audited EIP-4337 for EF. Expensive but highest credibility |
| **Trail of Bits** | Deep research, formal verification | $80K-150K+ | Audited Ethereum 2.0, MakerDAO, Uniswap |
| **Nethermind** | Ethereum-native, PhD-heavy team | $40K-80K | Core EF ecosystem contributor. May be more affordable |
| **Cyfrin** | Newer, strong community presence | $30K-60K | Founded by Patrick Collins. Strong Foundry expertise |
| **ConsenSys Diligence** | Ethereum ecosystem depth | $50K-100K | MetaMask parent company. Automated + manual tools |

**Recommendation**: Nethermind or Cyfrin for best value-to-quality ratio. OpenZeppelin or Trail of Bits if the EF grant covers audit costs.

**ZK circuit audit specifically**: fewer firms specialize in this. Look at:
- **Veridise**: ZK circuit formal verification specialists
- **Zellic**: strong ZK audit track record (also owns Code4rena)
- **Nethermind**: has ZK expertise from Starknet ecosystem work

---

## 6. Bug Bounty Programs (Post-Launch)

**Immunefi** (https://immunefi.com): the dominant bug bounty platform for crypto. Set up a bounty program after mainnet launch as ongoing security.

**Cost**: you define the bounty amounts. Typical ranges:
- Critical (fund theft): $10K-100K+
- High: $5K-25K
- Medium: $1K-5K

**Best use**: complements the pre-launch audit. Audits catch known vulnerability classes; bounties catch novel attacks discovered post-deployment. Budget for this separately from the audit.

---

## 7. Other Grant Sources

### Protocol Guild
**URL**: https://protocol-guild.readthedocs.io
**What it is**: funds Ethereum core contributors. ShieldNode's PQ handshake library could qualify if framed as a contribution to Ethereum's PQ readiness. Long shot but worth exploring for the PQ component specifically.

### Gitcoin Passport / Allo Protocol Grants
Ecosystem grants that fund public goods. Similar to Gitcoin Grants but via different allocation mechanisms.

### Octant
**URL**: https://octant.build
**What it is**: Golem Foundation initiative distributing ETH staking yields to public goods. Quarterly epochs with community voting. Privacy and infrastructure projects have received funding.

### ENS DAO Grants
ENS DAO has funded privacy and infrastructure projects. ShieldNode's use of ENS names for node identity (if implemented) would strengthen the application.

---

## Recommended Strategy

### Phase 4 (Now)
1. **Book EF ESP Office Hours** — get feedback on grant framing before applying. Free, no commitment. URL: esp.ethereum.foundation
2. **Submit ESP Wishlist application** — frame around privacy infrastructure + PQ research as public goods. Ask covers: bootstrapping incentives, ZK circuit dev, PQ library, audit coordination ($30K-80K)
3. **Create Gitcoin Grants profile** — target the next relevant funding round for supplemental bootstrapping funds ($5K-20K)

### Phase 5 (Pre-Mainnet)
4. **Run Code4rena competitive audit** for Solidity contracts — $15K-30K prize pool. Zero platform fee. Covers SessionSettlement, ZKSettlement, NodeRegistry, SlashingOracle
5. **Commission private ZK circuit audit** — Veridise, Zellic, or Nethermind. $15K-40K depending on circuit complexity
6. **PQ handshake review** — can potentially be included in the ESP grant scope as a deliverable, or commissioned separately ($10K-20K)

### Phase 5+ (Post-Launch)
7. **Set up Immunefi bug bounty** — ongoing security layer. $50K-100K in bounty reserves
8. **Consider Sherlock re-audit** with exploit coverage once real TVL justifies the cost

### Budget Summary

| Item | Estimated Cost | Funding Source |
|------|---------------|----------------|
| Node bootstrapping (2.5 ETH) | ~$5K | ESP grant or Gitcoin |
| Solidity competitive audit | $15K-30K | Code4rena (self-funded or ESP) |
| ZK circuit private audit | $15K-40K | ESP grant or self-funded |
| PQ handshake review | $10K-20K | ESP grant scope |
| Bug bounty reserves | $50K-100K | Self-funded post-revenue |
| **Total pre-mainnet** | **$45K-95K** | **Mix of ESP grant + self-funding** |

The ESP grant is the highest-leverage single action. If awarded at $50K+, it could cover bootstrapping, ZK development, and audit costs in one application. Everything else is supplemental or post-launch.

---

## Key Links

- ESP Application: https://esp.ethereum.foundation/applicants
- ESP Wishlist: https://esp.ethereum.foundation/applicants/wishlist
- ESP RFPs: https://esp.ethereum.foundation/applicants/rfp
- ESP Office Hours: https://esp.ethereum.foundation (book via site)
- Gitcoin Grants: https://gitcoin.co
- Code4rena: https://code4rena.com
- Sherlock: https://sherlock.xyz
- Immunefi: https://immunefi.com
- Octant: https://octant.build
- Ethereum Grants Directory: https://ethereum.org/community/grants/
