# Operator Security Guide

How to protect your staking keys, manage funds safely, and prepare for Ethereum's post-quantum migration.

## Why This Matters

Your operator private key controls:
- **0.1+ ETH stake** locked in NodeRegistry
- **Heartbeat transactions** that keep your node active
- **Bandwidth receipt co-signing** for session settlement
- **Deregistration and stake withdrawal** (7-day cooldown)

A compromised key means lost stake and the ability for an attacker to impersonate your node. There is no key rotation mechanism in the current NodeRegistry — the address that registers the node is permanently the owner.

## Current Architecture

```
operator_private_key (hex in config.toml)
    ├── Signs: NodeRegistry.register()      (one-time, stakes ETH)
    ├── Signs: NodeRegistry.heartbeat()     (every 6 hours, ~$0.02)
    ├── Signs: NodeRegistry.updateEndpoint() (as needed)
    ├── Signs: EIP-712 bandwidth receipts   (per-session co-signing)
    └── Signs: NodeRegistry.deregister()    (withdrawal after 7-day cooldown)
```

The operator address is stored as `owner` in the NodeRegistry contract. Only this address can perform the above operations. It cannot be changed after registration.

## Recommendations

### 1. Use a Dedicated Hot Wallet

**Do not use your main wallet.** Create a fresh wallet used exclusively for node operations.

**Minimum funding:**
- 0.1 ETH for staking (more improves your node's score)
- 0.05 ETH gas buffer for heartbeats (~$2.40/month at 0.2 Gwei)
- Top up the gas buffer periodically — stake is locked separately

**Key storage:**
- The `operator_private_key` in `config.toml` must be the hex-encoded raw key
- This file should be readable only by the shieldnode process: `chmod 600 config.toml`
- Never commit `config.toml` to version control
- Consider using environment variables or a secrets manager (Vault, 1Password CLI) to inject the key at container startup rather than storing it on disk

**If using Docker:**
```bash
# Pass the key via environment variable instead of config file
docker run -e OPERATOR_KEY=0x... shieldnode
```
(Requires adding env-var support to the node config loader — not yet implemented. For now, mount the config file with restricted permissions.)

### 2. Smart Contract Wallets (Future)

Raw EOA keys are single points of failure. A smart contract wallet like [Safe](https://safe.global) provides:

- **Multi-signature**: 2-of-3 or 3-of-5 approval for withdrawals
- **Key rotation**: Replace compromised signers without changing the wallet address
- **Spending limits**: Cap per-transaction ETH amounts
- **Programmable verification**: Upgrade signature schemes (including post-quantum) via modules

**Current limitation:** ShieldNode's `SessionSettlement.sol` uses `ecrecover()` for receipt signature verification. This expects a standard ECDSA signature from an EOA. Safe multisig signatures use a different format and require EIP-1271 (`isValidSignature()`) support, which the contracts do not yet implement.

**What works today with Safe:**
- Registering a node (Safe sends the `register()` transaction as `msg.sender`)
- Heartbeats (Safe sends the `heartbeat()` transaction)
- Deregistration and withdrawal

**What does not work with Safe yet:**
- Bandwidth receipt co-signing (requires `ecrecover` on the node's signature)

**Workaround:** Use ZK settlement mode. The ZK circuit verifies receipts internally — the on-chain verifier only checks the ZK proof, not individual signatures. This bypasses the `ecrecover` limitation entirely.

**Planned fix:** Add EIP-1271 support to `SessionSettlement.sol` so receipt signatures from Safe wallets validate correctly on-chain. This is a contract upgrade that requires a new deployment (immutable contracts).

### 3. Migration Path: EOA to Safe

When EIP-1271 support is added to the settlement contracts:

1. Deploy a Safe multisig (e.g., 2-of-3 with hardware wallet signers)
2. Register a **new node** using the Safe as `msg.sender` (new node ID, new stake)
3. Deregister the old EOA-based node (7-day cooldown, then withdraw stake)
4. Transfer the withdrawn stake to the new Safe-based node
5. Update your `config.toml` to use the Safe's transaction relay (requires node software changes to support Safe transaction submission)

Note: Because the NodeRegistry ties `owner` to `msg.sender` at registration time with no transfer mechanism, migrating requires registering a new node. Your node's uptime history and completion rate reset. Plan the migration during a low-traffic period.

## Post-Quantum Preparedness

### The Threat

Shor's algorithm on a sufficiently powerful quantum computer can derive ECDSA private keys from public keys. For ShieldNode operators, this means:

- An attacker could derive your operator key from on-chain transaction signatures
- They could then drain your stake, impersonate your node, or deregister it
- This is a "harvest now, crack later" risk — transaction signatures are public and permanent

### What's Already Quantum-Safe

| Component | Status | Details |
|-----------|--------|---------|
| Circuit handshake | Protected | Hybrid X25519 + ML-KEM-768 (Phase 4) |
| Tunnel encryption | Protected | ChaCha20-Poly1305 (symmetric, quantum-resistant) |
| Key derivation | Protected | HKDF-SHA256 (hash-based, quantum-resistant) |
| Receipt signing (ZK path) | Protected | ML-DSA-65 verified inside ZK circuit |
| Sphinx packet format | Protected | Hybrid PQ per-hop KEM (Phase 6) |

### What Needs Upgrading

| Component | Current | Future | Depends On |
|-----------|---------|--------|------------|
| Operator staking keys | EOA (secp256k1) | Safe + PQ signature module | EIP-1271 in contracts |
| Receipt signing (plaintext) | ECDSA ecrecover | ML-DSA via precompile | Ethereum Fork J* |
| On-chain key registry | Operator address only | PQ public key field | Ethereum Fork I* |

### Ethereum's PQ Timeline

Ethereum's post-quantum roadmap (per the Ethereum Foundation, [pq.ethereum.org](https://pq.ethereum.org)):

- **Fork I* (~2027-2028)**: PQ key registry at the consensus layer. Validators register PQ public keys. ShieldNode operators could optionally mirror this pattern.
- **Fork J* (~2028-2029)**: PQ signature verification precompiles (ML-DSA). Enables on-chain ML-DSA receipt verification in a new `PQSessionSettlement.sol`. This is when plaintext settlement can fully move to PQ.
- **Full PQ consensus (longer term)**: All L1 consensus signatures move to PQ schemes. Strengthens the base layer ShieldNode settles on.

**ShieldNode does not block on any of these forks.** PQ is already implemented at the application layer for privacy-critical paths (circuit handshakes, ZK receipt signing). The Ethereum forks will strengthen the settlement layer.

### What Operators Should Do Now

1. **Use ZK settlement mode** — Receipt signatures are verified inside the ZK circuit using ML-DSA. The on-chain verifier only sees a ZK proof. This is already post-quantum for the settlement path.
2. **Minimize on-chain exposure** — Use the minimum stake needed. Don't leave excess ETH in the operator wallet.
3. **Monitor the Safe ecosystem** — Safe is actively researching PQ signature modules. When available, upgrading your Safe's signature verification to ML-DSA protects your staking keys without changing the wallet address.
4. **Plan for re-registration** — When PQ-safe operator wallets become practical, you'll need to register a new node. Keep your operator setup documented so migration is straightforward.

## Operational Checklist

- [ ] Dedicated wallet for node operations (not your main wallet)
- [ ] Minimum funding: stake + gas buffer only
- [ ] `config.toml` file permissions restricted (`chmod 600`)
- [ ] `config.toml` excluded from version control (`.gitignore`)
- [ ] Backup of operator private key in secure offline storage
- [ ] ZK settlement mode enabled (default in Settings)
- [ ] Monitor heartbeat logs — 3 consecutive misses deactivate your node
- [ ] Set up alerting on the `/health` endpoint (Docker healthcheck handles basic liveness)

## Emergency Procedures

**If your operator key is compromised:**

1. **Immediately deregister** your node via the NodeRegistry contract (can be done from any wallet that holds the compromised key — act before the attacker does)
2. Wait the 7-day unstaking cooldown
3. Withdraw stake to a new, secure wallet
4. Register a new node with a fresh key
5. Rotate any other credentials that shared the same key material

**If you suspect your node is being impersonated:**

1. Check on-chain: is your node's endpoint still correct? (`NodeRegistry.getNode()`)
2. If the endpoint was changed, your key is compromised — follow the steps above
3. If the endpoint is correct but you see unauthorized sessions, the attacker may be intercepting traffic — shut down the node and re-register on new infrastructure

**If your stake is slashed:**

Slashing is progressive: 10% first offense, 25% second, 100% + permanent ban on third. If you believe a slash was unjust, the evidence is on-chain in the `SlashingOracle` contract. Slashing requires cryptographic proof (not probabilistic suspicion), so false positives should be rare. Contact the community to review the evidence.
