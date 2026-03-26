# ZK Node Eligibility Proofs

## What This Proves

"I am a registered node in the ShieldNode network. My stake meets the minimum, I have not been excessively slashed, and my uptime is above the threshold."

The verifier sees: a valid proof, the registry root, and the eligibility thresholds.
It does NOT see: which node, what the actual stake/uptime/slashes are, the node's endpoint, or its public key.

## Why This Matters

Without eligibility proofs, an observer can enumerate the node set by reading the public registry. A state actor could target known nodes for surveillance or censorship. With ZK eligibility proofs, nodes prove they qualify for circuit selection without revealing their identity — the registry becomes a commitment tree where membership is provable but the member set is hidden.

## Circuit Inputs

### Public
| Input | Type | Description |
|-------|------|-------------|
| `registryRoot` | uint256 | Merkle root of the commitment tree |
| `minStake` | uint256 | Minimum stake threshold |
| `maxSlashCount` | uint256 | Maximum allowed slash count |
| `minUptimeScaled` | uint256 | Minimum uptime × 1000 |
| `nullifier` | uint256 | Prevents double-use of proof |

### Private
| Input | Type | Description |
|-------|------|-------------|
| `nodeStake` | uint256 | Actual stake |
| `nodeSlashCount` | uint256 | Actual slash count |
| `nodeUptimeScaled` | uint256 | Actual uptime × 1000 |
| `nodePublicKey` | uint256 | Public key (in commitment) |
| `nodeSecret` | uint256 | Secret known only to the node |
| `merkleProof` | uint256[9] | Merkle path to registry root |
| `merkleIndex` | uint256 | Leaf index |

## Constraint Estimate

| Component | Constraints |
|-----------|------------|
| Poseidon(5) commitment | ~1.5K |
| Merkle proof (depth 9) | ~10K |
| Range checks (3×) | ~500 |
| **Total** | **~12K** |

Proving time: <1 second on modern hardware.
