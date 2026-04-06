# Ownership Renouncement Roadmap

ShieldNode's design philosophy is **trustless by default**. Every admin role is a temporary concession to operational reality — not a permanent feature. This document defines the timeline and prerequisites for renouncing all owner/admin keys, achieving a fully immutable, ownerless protocol.

---

## Current Admin Surface

| Contract | Role | Current Power | Timelock |
|----------|------|---------------|----------|
| **SlashingOracle** | `owner` | Add/remove challengers | 48h (add), instant (revoke) |
| **SlashingOracle** | `pauser` | Pause slash proposals and execution | Instant |
| **SessionSettlement** | `pauser` | Pause session open/settle | Instant |
| **Treasury** | `owner` | Queue/execute withdrawals, manage guardian | 48h |
| **Treasury** | `guardian` | Cancel queued withdrawals | Instant (veto only) |
| **CommitmentTree** | `owner` | Propose insert/remove commitments | 48h |
| **EligibilityVerifier** | `owner` | Propose registry root updates | 48h |
| **ZKSettlement** | `owner` | Propose registry root updates | 48h |

All owner roles are set in constructors, non-transferable (except CommitmentTree), and backed by multisig wallets with timelocks.

---

## Renouncement Timeline

### Phase 1: Launch (Day 0)

**Status: Multisig owners with timelocks.**

All admin roles active. Multisig wallets (2-of-3 or 3-of-5) hold all owner keys. Timelocks give the community 48 hours to react to any admin action.

**Rationale:** New protocol, untested in production. Emergency controls are necessary for the first months of operation.

### Phase 2: Stable Operations (Month 3-6)

**Renounce: Pauser roles on SessionSettlement and SlashingOracle.**

| Action | Contract | Effect |
|--------|----------|--------|
| Set `pauser` to `address(0)` | SessionSettlement | Protocol cannot be paused — sessions always available |
| Set `pauser` to `address(0)` | SlashingOracle | Slashing cannot be paused — misbehavior always punishable |

**Prerequisites:**
- 3+ months of mainnet operation with no emergency pauses needed
- All critical bugs found and fixed via contract migration (deploy new, migrate stakes)
- Client software stable with no settlement-breaking edge cases

**Rationale:** Pausers are the most dangerous admin power — they can DOS the entire protocol. Removing them first maximizes censorship resistance at minimal risk (the protocol has proven stable).

### Phase 3: Automated Commitment Tree (Month 6-9)

**Renounce: CommitmentTree owner by transferring to NodeRegistry.**

| Action | Contract | Effect |
|--------|----------|--------|
| `transferOwnership(address(nodeRegistry))` | CommitmentTree | Only NodeRegistry (immutable) can modify the tree |
| Add `_insertCommitment` / `_removeCommitment` | NodeRegistry | Automatically manage tree on register/deregister |

**Prerequisites:**
- NodeRegistry upgrade deployed with CommitmentTree integration
- New NodeRegistry verified and audited
- Existing nodes migrated to new registry

**Rationale:** The CommitmentTree should reflect on-chain registrations automatically. Human control over the privacy Merkle tree is a liability, not a feature.

### Phase 4: Automated Registry Roots (Month 6-9, parallel with Phase 3)

**Renounce: EligibilityVerifier and ZKSettlement owner roles.**

| Action | Contract | Effect |
|--------|----------|--------|
| Derive `registryRoot` from `CommitmentTree.root()` | EligibilityVerifier | Root updates are automatic, no admin needed |
| Derive `registryRoot` from `CommitmentTree.root()` | ZKSettlement | Same |
| Renounce owner (set to `address(0)`) | Both | No one can override the derived root |

**Prerequisites:**
- CommitmentTree ownership transferred to NodeRegistry (Phase 3)
- New EligibilityVerifier/ZKSettlement deployed that read root from CommitmentTree directly
- ZK circuits updated and re-audited for new root derivation

**Rationale:** Once the tree is automated, the root is deterministic. Admin-set roots are an unnecessary trust assumption.

### Phase 5: Permissionless Challengers (Month 9-12)

**Renounce: SlashingOracle owner.**

| Action | Contract | Effect |
|--------|----------|--------|
| Deploy ChallengeManager v2 with bonded challengers | — | Anyone can become a challenger by posting a bond |
| Register ChallengeManager v2 as sole challenger | SlashingOracle | Permissionless challenge-response replaces trusted set |
| Renounce owner (set to `address(0)`) | SlashingOracle | Challenger set frozen (only ChallengeManager v2) |

**Prerequisites:**
- ChallengeManager v2 deployed with bonded challenger mechanics
- Bond economics proven on testnet (bond size, slash/reward ratios)
- Emergency revocation path removed — bad challengers handled via bond slashing
- At least 3 months of testnet operation with permissionless challengers

**Rationale:** The trusted challenger set is the largest remaining trust assumption. Permissionless bonds make slashing credibly neutral — anyone can hold nodes accountable.

### Phase 6: Treasury Resolution (Month 12-18)

**Renounce: Treasury owner.**

Before renouncing, decide what happens to slash proceeds. Options:

| Option | Mechanism | Tradeoff |
|--------|-----------|----------|
| **Burn** | Treasury `receive()` accepts ETH, no withdrawal path | Deflationary; simple; funds are permanently removed from supply |
| **Auto-distribute** | Deploy a splitter that divides proceeds among stakers | Complex; requires staker registry and claim mechanism |
| **Community fund** | Transfer owner to a governance contract (DAO) | Requires governance infrastructure; adds new trust assumptions |
| **Accept locked funds** | Renounce with existing balance locked | Simplest; funds serve as a credible commitment to the protocol |

**Prerequisites:**
- Decision made on treasury fund disposition
- If auto-distribute: splitter contract deployed and audited
- If governance: DAO infrastructure deployed
- Minimum 6 months since last admin action on Treasury

**Rationale:** Treasury is the least urgent renouncement — funds can only be withdrawn after a 48h timelock with guardian veto, and they flow in slowly from slashing. The risk of admin abuse is low, but the principle of trustlessness demands eventual resolution.

---

## Post-Renouncement State

After all phases complete, the protocol has:

- **Zero admin keys** — no address can modify any contract parameter
- **Zero pause capability** — the protocol runs as long as Ethereum runs
- **Zero upgrade path** — contracts are immutable; bugs require migration
- **Automated state management** — registry roots, commitment tree, challenger set all self-managing
- **Full credible neutrality** — mathematically impossible to censor, pause, or rug

This matches the security model of Uniswap v2, Liquity v1, and the original Tornado Cash contracts.

---

## Risks of Full Renouncement

| Risk | Mitigation |
|------|------------|
| Critical bug discovered post-renouncement | Client-side warning; deploy new contracts and migrate stakes |
| All challengers go offline | Bonded ChallengeManager v2 incentivizes new challengers via rewards |
| Treasury funds locked permanently | Decided before renouncement (Phase 6) |
| EligibilityVerifier thresholds wrong | Deploy new verifier with corrected thresholds; update client to use it |
| Ethereum consensus changes break contracts | Monitor EF roadmap; deploy adapted contracts if needed |

The key insight: **every risk of renouncement has a migration path that doesn't require admin keys.** Deploy new, migrate stakes, update clients. The old contracts simply stop being used.

---

## Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-04-06 | Document renouncement roadmap | X-Ray audit flagged admin roles as attack surface |
| — | Phase 1 begins at mainnet launch | — |
