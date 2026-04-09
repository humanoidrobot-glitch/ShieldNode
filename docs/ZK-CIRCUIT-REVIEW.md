# ZK Circuit Design Review

Review of `circuits/bandwidth_receipt/circuit.circom` against `contracts/src/ZKSettlement.sol` and `client/src-tauri/src/zk_prove.rs`. Conducted 2026-04-08 using Theora's circuit review framework as a reference model.

---

## Critical Findings

### 1. Poseidon/keccak commitment mismatch (circuit vs contract)

**Severity**: Critical (ZK settlement path will always revert)

The circuit (Step 7, lines 268-287) constrains commitments using **Poseidon**:
```
entryCommit = Poseidon(entryAddress, entryPay)
entryCommit.out === entryCommitmentPub
```

The contract (`ZKSettlement.settleWithProof`, step 7) verifies commitments using **keccak256**:
```solidity
require(
    uint256(keccak256(abi.encode(entryAddr, entryPay))) == pubSignals[SIG_ENTRY_COMMITMENT],
    "ZKSettlement: entry addr binding"
);
```

Since `Poseidon(a, b) != keccak256(abi.encode(a, b))`, no valid proof can satisfy both constraints simultaneously. The contract's keccak check will always revert for a proof that satisfies the circuit's Poseidon constraint.

**Root cause**: The on-chain keccak binding was added during audit remediation (Finding 2) without accounting for the circuit's Poseidon commitment scheme. The original code had a long comment acknowledging this gap but no enforcement.

**Fix options** (in order of preference):

| Option | Approach | Cost | Tradeoff |
|--------|----------|------|----------|
| A | Deploy a Poseidon verifier library on-chain; contract checks Poseidon instead of keccak | ~50K gas per hash (4 hashes = ~200K extra) | Cleanest alignment; adds gas cost |
| B | Add 4 keccak commitment outputs to the circuit as additional public signals | ~1.2M extra constraints (4 × ~300K per keccak) | Heavy; 3.5M → ~4.7M constraints, slower proving |
| C | Remove on-chain commitment verification; rely solely on circuit constraints | 0 cost | Weakens defense-in-depth; addresses only bound inside the proof |

**Recommended**: Option A. Poseidon Solidity libraries exist (e.g., `poseidon-solidity` from iden3). The 200K gas overhead is acceptable alongside the 200K Groth16 verification cost.

---

### 2. `populate_inputs` missing 7 circuit signals

**Severity**: Critical (proof generation will fail at runtime)

**File**: `client/src-tauri/src/zk_prove.rs`, function `populate_inputs` (line 173)

The `PublicInputs` struct declares 6 fields and `ReceiptWitness` declares 1 field that are never pushed to the circuit builder:

| Field | Struct | Circuit signal | Status |
|-------|--------|---------------|--------|
| `nullifier` | PublicInputs | `nullifierPub` | **Missing** |
| `deposit_id` | PublicInputs | `depositIdPub` | **Missing** |
| `entry_pay` | PublicInputs | (output) | **Missing** |
| `relay_pay` | PublicInputs | (output) | **Missing** |
| `exit_pay` | PublicInputs | (output) | **Missing** |
| `refund` | PublicInputs | (output) | **Missing** |
| `deposit_id_private` | ReceiptWitness | `depositIdPrivate` | **Missing** |

Without these inputs, `ark_circom::CircomBuilder` will fail with "missing signal" errors when constructing the witness.

Note: `entry_pay`, `relay_pay`, `exit_pay`, `refund` are circuit **outputs** — they don't need to be pushed as inputs. The circuit computes them. So only 3 inputs are truly missing: `nullifierPub`, `depositIdPub`, and `depositIdPrivate`.

**Fix**: Add the 3 missing push_input calls.

---

## High Findings

### 3. Single `pricePerByte` in circuit vs per-node prices in contract

**Severity**: High (design divergence, not a runtime bug yet)

The circuit (line 86) uses a single `pricePerByte` for payment computation:
```
rawPayment = cumulativeBytes * pricePerByte
```

The plaintext settlement path (`SessionSettlement._settle`) now uses per-node prices:
```solidity
entryPay = (cumulativeBytes * s.nodePrices[0] * ENTRY_SHARE) / 100;
relayPay = (cumulativeBytes * s.nodePrices[1] * RELAY_SHARE) / 100;
exitPay  = (cumulativeBytes * s.nodePrices[2] * EXIT_SHARE) / 100;
```

The ZK path computes a flat total then splits 25/25/50. The plaintext path computes per-node payments with individual prices.

**Impact**: When a session uses ZK settlement, the payment amounts will differ from what the plaintext path would have computed if nodes have different prices. This is acceptable if documented as a deliberate design choice (ZK uses exit node's price as the reference rate), but should not silently diverge.

**Recommendation**: Document that ZK settlement uses exit node `pricePerByte` as the session rate. The client should use the exit node's price when constructing the ZK witness.

---

## Medium Findings

### 4. Only exit node signature verified in circuit

**Severity**: Medium (known, documented)

The circuit verifies ECDSA signatures from the **client** (Step 2) and **exit node** (Step 3) only. Entry and relay node identities are not proven inside the circuit. The circuit proves registry membership for the exit node only (Step 4).

This means a malicious prover could substitute entry/relay addresses in the commitments without the circuit detecting it. The addresses are bound to payments via Poseidon commitments (Step 7), but the circuit doesn't verify those addresses belong to registered or session-participating nodes.

**Mitigation**: Entry/relay nodes sign bandwidth receipts off-chain. The ZK circuit trusts the exit node as the "settlement authority" since it processes all traffic.

**Recommendation**: Acceptable for Phase 4. Consider adding entry/relay Merkle proofs in a future circuit version (~40K extra constraints).

### 5. `receiptTypehash` is a private input

**Severity**: Medium (unusual but safe)

The EIP-712 `RECEIPT_TYPEHASH` constant (line 124) is supplied as a private input by the prover, not hardcoded in the circuit. A malicious prover could supply a wrong typehash, producing a different digest.

**Why this is safe**: The circuit verifies ECDSA signatures over the digest. If the typehash is wrong, the digest is wrong, and ECDSA verification fails (the real signatures were over the correct digest). The prover cannot forge signatures for a different digest without the private keys.

**Recommendation**: No fix needed. Hardcoding would increase circuit complexity (256-bit constant wiring) for no security benefit.

---

## Low / Informational

### 6. `LessThan(128)` for payment cap

Line 221: `isOver = LessThan(128)` compares `deposit` vs `rawPayment`. 128 bits supports values up to ~3.4 × 10^38, which far exceeds any realistic deposit amount in wei. No issue.

### 7. Exit node absorbs rounding dust

Line 257: `exitPay = totalPayment - entryPay - relayPay`. The exit node absorbs any rounding remainder from the 25/25/50 split. Maximum dust: <1 wei per settlement. By design.

### 8. Merkle depth 20 supports ~1M nodes

Line 307: `BandwidthReceipt(20)` instantiates with depth 20. Sufficient for foreseeable network size. Costs ~20K constraints.

---

## Action Items

| Priority | Item | Files |
|----------|------|-------|
| ~~**P0**~~ | ~~Fix Poseidon/keccak mismatch~~ — Done. Deployed `poseidon-solidity` library, `ZKSettlement` uses `PoseidonT3.hash` | `contracts/src/ZKSettlement.sol` |
| ~~**P0**~~ | ~~Add missing `populate_inputs` signals~~ — Done. Added nullifierPub, depositIdPub, depositIdPrivate | `client/src-tauri/src/zk_prove.rs` |
| ~~**P1**~~ | ~~Document ZK vs plaintext pricing divergence~~ — Done. Added section to circuit README | `circuits/bandwidth_receipt/README.md` |
| ~~**P2**~~ | ~~Entry/relay Merkle proofs~~ — Done. All 3 nodes verified against registryRoot | `circuits/bandwidth_receipt/circuit.circom` |

---

## Review Methodology

Circuit constraints were reviewed against:
- On-chain verification logic in `ZKSettlement.settleWithProof()`
- Client witness construction in `zk_prove.rs::populate_inputs()`
- Public signal index mapping (`SIG_*` constants)
- EIP-712 domain binding (domainSeparator, nullifier, depositId)

Attack vectors considered (informed by Theora's interactive ZK demos):
- **Frozen-heart (Fiat-Shamir)**: All public signals are bound to the proof via Groth16's verification equation. Deposit ID, nullifier, and domain separator are all public inputs.
- **Underconstrained wires**: Payment split is fully constrained (entryPay via division + remainder check, relayPay = entryPay, exitPay = totalPayment - 2×entryPay). No degree of freedom for the prover.
- **Proof replay**: Nullifier = Poseidon(sessionId, clientAddress) is deterministic and tracked on-chain. Same session cannot produce two valid proofs.
- **Deposit swap**: depositIdPrivate === depositIdPub constrains the proof to a specific deposit.
