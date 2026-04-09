use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::hop_codec;
use crate::kex::{self, KeyExchange, X25519Kem};

/// Metadata describing a single ShieldNode relay / exit node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub node_id: String,
    /// X25519 public key (32 bytes) or hybrid X25519+ML-KEM-768 key (1216 bytes).
    pub public_key: Vec<u8>,
    pub endpoint: String,
    pub stake: u64,
    pub uptime: f64,
    pub price_per_byte: u64,
    pub slash_count: u32,
    /// Session completion rate (0.0–1.0). Derived from on-chain settlement events.
    #[serde(default = "default_completion_rate")]
    pub completion_rate: f64,
    /// On-chain registrant address (hex). Used for same-operator exclusion.
    #[serde(default)]
    pub operator_address: String,
    /// Autonomous System Number (optional, from registry metadata).
    #[serde(default)]
    pub asn: Option<u32>,
    /// Geographic region code (optional, from registry metadata).
    #[serde(default)]
    pub region: Option<String>,
    /// Whether this node has a valid TEE attestation.
    #[serde(default)]
    pub tee_attested: bool,
}

fn default_completion_rate() -> f64 {
    1.0
}

// ── circuit diversity helpers ─────────────────────────────────────────

/// Extract a subnet prefix from an endpoint string.
///
/// IPv4: /24 prefix (e.g., "1.2.3.4:51820" → "1.2.3")
/// IPv6: /48 prefix (e.g., "[2001:db8:abcd::1]:51820" → "2001:db8:abcd")
fn subnet_prefix(endpoint: &str) -> Option<String> {
    use std::net::IpAddr;

    // Try parsing as a full SocketAddr (handles both IPv4 "1.2.3.4:port"
    // and IPv6 "[::1]:port" bracket notation).
    if let Ok(addr) = endpoint.parse::<std::net::SocketAddr>() {
        return match addr.ip() {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                Some(format!("{}.{}.{}", o[0], o[1], o[2]))
            }
            IpAddr::V6(v6) => {
                let s = v6.segments();
                Some(format!("{:x}:{:x}:{:x}", s[0], s[1], s[2]))
            }
        };
    }

    // Fallback: simple split for bare IPv4 "host:port" without brackets.
    let host = endpoint.split(':').next()?;
    let octets: Vec<&str> = host.split('.').collect();
    if octets.len() == 4 {
        Some(format!("{}.{}.{}", octets[0], octets[1], octets[2]))
    } else {
        None
    }
}

/// Check if a candidate node violates diversity constraints against already-selected nodes.
/// Returns true if the candidate is acceptable (diverse enough).
fn is_diverse(candidate: &NodeInfo, selected: &[Option<NodeInfo>]) -> bool {
    let candidate_subnet = subnet_prefix(&candidate.endpoint);

    for slot in selected.iter().flatten() {
        // Same subnet prefix (/24 for IPv4, /48 for IPv6) → reject
        if let (Some(ref a), Some(ref b)) = (&candidate_subnet, &subnet_prefix(&slot.endpoint)) {
            if a == b {
                return false;
            }
        }

        // Same ASN → reject (if both have ASN data)
        if let (Some(a), Some(b)) = (candidate.asn, slot.asn) {
            if a == b {
                return false;
            }
        }

        // Same region → reject (if both have region data)
        if let (Some(ref a), Some(ref b)) = (&candidate.region, &slot.region) {
            if a == b {
                return false;
            }
        }

        // Same operator address → reject
        if !candidate.operator_address.is_empty()
            && candidate.operator_address == slot.operator_address
        {
            return false;
        }
    }
    true
}

/// A single hop in a 3-hop circuit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitHop {
    pub node_id: String,
    pub endpoint: String,
    #[serde(skip_serializing)]
    pub session_key: [u8; 32],
    pub hop_index: u64,
    /// Random session identifier for the relay protocol.
    pub session_id: u64,
    /// Operator's Ethereum address (hex, for ZK commitments).
    pub operator_address: String,
    /// Price per byte at session open time (for ZK witness).
    pub price_per_byte: u64,
}

/// The full 3-hop circuit state with per-hop session keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitState {
    pub entry: CircuitHop,
    pub relay: CircuitHop,
    pub exit: CircuitHop,
}

/// A sanitised view of a circuit hop for the frontend (no session key).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CircuitHopInfo {
    pub node_id: String,
    pub endpoint: String,
    pub hop_index: u64,
}

/// A sanitised view of the circuit for the frontend (no session keys).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitInfo {
    pub entry: CircuitHopInfo,
    pub relay: CircuitHopInfo,
    pub exit: CircuitHopInfo,
}

/// Default relay port offset from the WireGuard port.
const RELAY_PORT: u16 = 51821;

impl CircuitState {
    /// Return a frontend-safe view that strips session keys.
    pub fn to_info(&self) -> CircuitInfo {
        CircuitInfo {
            entry: CircuitHopInfo {
                node_id: self.entry.node_id.clone(),
                endpoint: self.entry.endpoint.clone(),
                hop_index: self.entry.hop_index,
            },
            relay: CircuitHopInfo {
                node_id: self.relay.node_id.clone(),
                endpoint: self.relay.endpoint.clone(),
                hop_index: self.relay.hop_index,
            },
            exit: CircuitHopInfo {
                node_id: self.exit.node_id.clone(),
                endpoint: self.exit.endpoint.clone(),
                hop_index: self.exit.hop_index,
            },
        }
    }

    /// Build the route for `SphinxPacket::create()`.
    ///
    /// Returns a list of `(next_hop_encoding, session_key)` pairs:
    /// - Entry hop: next_hop encodes the relay node's IP + relay port
    /// - Relay hop: next_hop encodes the exit node's IP + relay port
    /// - Exit hop:  next_hop is `[0u8; 32]` (exit sentinel)
    pub fn build_sphinx_route(&self) -> Vec<([u8; 32], [u8; 32])> {
        let hops = [&self.entry, &self.relay, &self.exit];
        let mut route = Vec::with_capacity(3);

        for (i, hop) in hops.iter().enumerate() {
            let next_hop = if i + 1 < hops.len() {
                // Point to the next hop's relay port.
                hop_codec::endpoint_to_next_hop(&hops[i + 1].endpoint, RELAY_PORT)
                    .unwrap_or([0u8; 32])
            } else {
                // Exit sentinel — all zeros.
                [0u8; 32]
            };

            route.push((next_hop, hop.session_key));
        }

        route
    }
}

/// Build a 3-hop circuit from the given nodes, deriving a session key
/// for each hop via KEM encapsulate + HKDF.
///
/// Automatically selects the KEM based on public key length:
/// - 32 bytes: X25519 (classical)
/// - 1216 bytes: Hybrid X25519 + ML-KEM-768 (post-quantum safe)
pub fn build_circuit(nodes: &[NodeInfo; 3]) -> Result<CircuitState, String> {
    let mut hops: Vec<CircuitHop> = Vec::with_capacity(3);

    for (i, node) in nodes.iter().enumerate() {
        let shared_secret_bytes = encapsulate_for_key(&node.public_key, i)?;

        // Derive a 32-byte session key via HKDF-SHA256
        let hk = Hkdf::<Sha256>::new(Some(b"ShieldNode-circuit-v1"), &shared_secret_bytes);
        let mut session_key = [0u8; 32];
        hk.expand(b"session-key", &mut session_key)
            .map_err(|e| format!("HKDF expand failed for hop {i}: {e}"))?;

        let session_id: u64 = OsRng.gen();

        hops.push(CircuitHop {
            node_id: node.node_id.clone(),
            endpoint: node.endpoint.clone(),
            session_key,
            hop_index: i as u64,
            session_id,
            operator_address: node.operator_address.clone(),
            price_per_byte: node.price_per_byte,
        });
    }

    Ok(CircuitState {
        entry: hops.remove(0),
        relay: hops.remove(0),
        exit: hops.remove(0),
    })
}

/// Detect key type by length and encapsulate with the appropriate KEM.
fn encapsulate_for_key(public_key: &[u8], hop_index: usize) -> Result<Vec<u8>, String> {
    match public_key.len() {
        32 => {
            let pk = X25519Kem::public_key_from_bytes(public_key)
                .map_err(|e| format!("invalid X25519 key for hop {hop_index}: {e}"))?;
            let (ss, _ct) = X25519Kem::encapsulate(&pk)
                .map_err(|e| format!("X25519 encapsulate failed for hop {hop_index}: {e}"))?;
            Ok(ss.as_ref().to_vec())
        }
        kex::HYBRID_PK_LEN => {
            let pk = kex::HybridKem::public_key_from_bytes(public_key)
                .map_err(|e| format!("invalid hybrid key for hop {hop_index}: {e}"))?;
            let (ss, _ct) = kex::HybridKem::encapsulate(&pk)
                .map_err(|e| format!("hybrid encapsulate failed for hop {hop_index}: {e}"))?;
            Ok(ss.as_ref().to_vec())
        }
        len => Err(format!(
            "unsupported public key length for hop {hop_index}: {len} (expected 32 or {})",
            kex::HYBRID_PK_LEN
        )),
    }
}

/// Score a node for selection.
///
/// Higher is better. Weights (rebalanced for completion scoring):
///
/// ```text
/// score = 10 * sqrt(stake / 1e18)     ← 25% weight: 0.1 ETH → 3.16, 1 ETH → 10
///       + 25 * uptime                  ← 25% weight: 0..25 range
///       - 0.001 * price_per_byte       ← 20% weight: penalty for expensive nodes
///       - 15 * slash_count^2           ← 15% weight: penalty for slashed nodes
///       + 15 * completion_rate         ← 15% weight: reward for reliable sessions
/// ```
pub fn score_node(node: &NodeInfo) -> f64 {
    let stake_eth = node.stake as f64 / 1e18;
    let stake_score = 10.0 * stake_eth.sqrt();

    let uptime_score = 25.0 * node.uptime;
    let price_score = 0.001 * node.price_per_byte as f64;
    let slash_score = 15.0 * (node.slash_count as f64).powi(2);
    let completion_score = 15.0 * node.completion_rate;
    let tee_bonus = if node.tee_attested { 20.0 } else { 0.0 };

    stake_score + uptime_score - price_score - slash_score + completion_score + tee_bonus
}

/// Select a three-hop circuit (entry, relay, exit) via weighted random sampling.
///
/// `pinned_ids` optionally fixes specific positions: `[entry, relay, exit]`.
/// Empty strings mean "select randomly". For example, `["node-a", "", "node-b"]`
/// pins entry to node-a and exit to node-b, with relay chosen randomly.
///
/// When `exclude_ids` is non-empty, those nodes are deprioritized to encourage
/// diversity on circuit rotation.
pub fn select_circuit(
    nodes: &[NodeInfo],
    exclude_ids: &[&str],
) -> Result<[NodeInfo; 3], String> {
    select_circuit_with_pins(nodes, exclude_ids, &["", "", ""])
}

/// Select a circuit with optional pinning per hop.
pub fn select_circuit_with_pins(
    nodes: &[NodeInfo],
    exclude_ids: &[&str],
    pinned_ids: &[&str; 3],
) -> Result<[NodeInfo; 3], String> {
    if nodes.len() < 3 {
        return Err(format!(
            "need at least 3 nodes to form a circuit, got {}",
            nodes.len()
        ));
    }

    let mut selected: [Option<NodeInfo>; 3] = [None, None, None];
    let mut used_ids: Vec<String> = Vec::new();

    // Phase 1: Fill pinned positions.
    for (slot, pin_id) in pinned_ids.iter().enumerate() {
        if pin_id.is_empty() {
            continue;
        }
        let node = nodes
            .iter()
            .find(|n| n.node_id == *pin_id)
            .ok_or_else(|| format!("pinned node '{}' not found in available nodes", pin_id))?;
        selected[slot] = Some(node.clone());
        used_ids.push(node.node_id.clone());
    }

    // Phase 2: Fill remaining positions via weighted random sampling.
    let mut candidates: Vec<(f64, &NodeInfo)> = nodes
        .iter()
        .filter(|n| {
            !used_ids.contains(&n.node_id)
                && !exclude_ids.contains(&n.node_id.as_str())
        })
        .map(|n| (score_node(n).max(1.0), n))
        .collect();

    if candidates.len() < selected.iter().filter(|s| s.is_none()).count() {
        // Not enough non-excluded candidates — fall back to all non-pinned nodes.
        candidates = nodes
            .iter()
            .filter(|n| !used_ids.contains(&n.node_id))
            .map(|n| (score_node(n).max(1.0), n))
            .collect();
    }

    let mut rng = rand::thread_rng();

    for slot in 0..3 {
        if selected[slot].is_some() {
            continue;
        }

        // Filter candidates by diversity constraints against already-selected nodes.
        let diverse: Vec<(f64, &NodeInfo)> = candidates
            .iter()
            .filter(|(_, n)| is_diverse(n, &selected))
            .copied()
            .collect();

        // Use diverse candidates if available; fall back to all candidates if
        // diversity can't be satisfied (small networks).
        let pool = if diverse.is_empty() {
            tracing::warn!(slot, "no diverse candidates available — relaxing constraints");
            &candidates
        } else {
            &diverse
        };

        if pool.is_empty() {
            return Err("not enough nodes to fill circuit".to_string());
        }

        let total: f64 = pool.iter().map(|(w, _)| w).sum();
        let mut roll: f64 = rng.gen::<f64>() * total;

        let mut pick_idx = pool.len() - 1;
        for (i, (w, _)) in pool.iter().enumerate() {
            roll -= w;
            if roll <= 0.0 {
                pick_idx = i;
                break;
            }
        }

        let picked = pool[pick_idx].1.clone();
        // Remove from main candidates list.
        if let Some(pos) = candidates.iter().position(|(_, n)| n.node_id == picked.node_id) {
            candidates.swap_remove(pos);
        }
        selected[slot] = Some(picked);
    }

    Ok([
        selected[0].take().unwrap(),
        selected[1].take().unwrap(),
        selected[2].take().unwrap(),
    ])
}

/// Phase-1 helper: pick the single best node (no multi-hop yet).
pub fn select_single_node(nodes: &[NodeInfo]) -> Result<NodeInfo, String> {
    if nodes.is_empty() {
        return Err("no nodes available".to_string());
    }

    nodes
        .iter()
        .max_by(|a, b| {
            score_node(a)
                .partial_cmp(&score_node(b))
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .cloned()
        .ok_or_else(|| "failed to select a node".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(id: &str, stake: u64, uptime: f64, price: u64, slashes: u32) -> NodeInfo {
        NodeInfo {
            node_id: id.to_string(),
            public_key: vec![0u8; 32],
            endpoint: "127.0.0.1:51820".to_string(),
            stake,
            uptime,
            price_per_byte: price,
            slash_count: slashes,
            completion_rate: 1.0,
            operator_address: String::new(),
            asn: None,
            region: None,
            tee_attested: false,
        }
    }

    #[test]
    fn higher_stake_and_uptime_scores_higher() {
        // 1 ETH staker with good uptime vs 0.001 ETH staker with bad uptime
        let good = make_node("good", 1_000_000_000_000_000_000, 0.99, 10, 0);
        let bad = make_node("bad", 1_000_000_000_000_000, 0.50, 100, 2);
        assert!(score_node(&good) > score_node(&bad));
    }

    #[test]
    fn stake_dominates_scoring() {
        // 2 ETH staker vs 0.1 ETH staker, same uptime/price/slashes.
        // sqrt(2) ≈ 1.41, sqrt(0.1) ≈ 0.316 → 10x difference in stake_score.
        let high = make_node("high", 2_000_000_000_000_000_000, 0.95, 10, 0);
        let low = make_node("low", 100_000_000_000_000_000, 0.95, 10, 0);
        let diff = score_node(&high) - score_node(&low);
        // The stake component alone should contribute >5 points of difference.
        assert!(diff > 5.0, "stake diff was only {diff:.2}");
    }

    #[test]
    fn select_single_picks_best() {
        let nodes = vec![
            make_node("a", 100_000_000_000_000_000, 0.80, 50, 1),
            make_node("b", 1_000_000_000_000_000_000, 0.99, 10, 0),
            make_node("c", 200_000_000_000_000_000, 0.70, 30, 0),
        ];
        let best = select_single_node(&nodes).unwrap();
        assert_eq!(best.node_id, "b");
    }

    #[test]
    fn circuit_needs_three() {
        let nodes = vec![
            make_node("a", 100_000_000_000_000_000, 0.80, 50, 0),
            make_node("b", 200_000_000_000_000_000, 0.90, 40, 0),
        ];
        assert!(select_circuit(&nodes, &[]).is_err());
    }

    #[test]
    fn circuit_returns_three_distinct_nodes() {
        let nodes = vec![
            make_node("a", 100_000_000_000_000_000, 0.80, 50, 0),
            make_node("b", 1_000_000_000_000_000_000, 0.99, 10, 0),
            make_node("c", 200_000_000_000_000_000, 0.70, 30, 0),
            make_node("d", 800_000_000_000_000_000, 0.95, 15, 0),
        ];
        let circuit = select_circuit(&nodes, &[]).unwrap();
        assert_eq!(circuit.len(), 3);
        // All three must be distinct.
        assert_ne!(circuit[0].node_id, circuit[1].node_id);
        assert_ne!(circuit[1].node_id, circuit[2].node_id);
        assert_ne!(circuit[0].node_id, circuit[2].node_id);
    }

    #[test]
    fn weighted_selection_favors_high_stake() {
        // One very high-staked node among several low-staked ones.
        // Over many trials, the high-stake node should appear far more often.
        let nodes = vec![
            make_node("whale", 10_000_000_000_000_000_000, 0.99, 10, 0), // 10 ETH
            make_node("b", 100_000_000_000_000_000, 0.95, 10, 0),         // 0.1 ETH
            make_node("c", 100_000_000_000_000_000, 0.95, 10, 0),
            make_node("d", 100_000_000_000_000_000, 0.95, 10, 0),
            make_node("e", 100_000_000_000_000_000, 0.95, 10, 0),
        ];
        let mut whale_count = 0;
        let trials = 200;
        for _ in 0..trials {
            let circuit = select_circuit(&nodes, &[]).unwrap();
            if circuit.iter().any(|n| n.node_id == "whale") {
                whale_count += 1;
            }
        }
        // With 10 ETH vs 0.1 ETH nodes, whale should appear in >60% of circuits.
        // (Expected ~79% — using 60% threshold for test stability.)
        assert!(
            whale_count > trials * 60 / 100,
            "whale appeared in {whale_count}/{trials} circuits, expected >60%"
        );
    }

    #[test]
    fn build_circuit_produces_unique_keys() {
        // Use distinct non-zero public keys so DH produces different shared secrets.
        let mut nodes = [
            make_node("entry", 100_000, 0.99, 10, 0),
            make_node("relay", 75_000, 0.98, 15, 0),
            make_node("exit", 50_000, 0.96, 8, 0),
        ];
        nodes[0].public_key = vec![1u8; 32];
        nodes[1].public_key = vec![2u8; 32];
        nodes[2].public_key = vec![3u8; 32];
        let state = build_circuit(&nodes).unwrap();
        assert_eq!(state.entry.hop_index, 0);
        assert_eq!(state.relay.hop_index, 1);
        assert_eq!(state.exit.hop_index, 2);
        // Session keys must differ (overwhelmingly likely with random ephemerals)
        assert_ne!(state.entry.session_key, state.relay.session_key);
        assert_ne!(state.relay.session_key, state.exit.session_key);
    }

    #[test]
    fn circuit_info_strips_keys() {
        let nodes = [
            make_node("entry", 100_000, 0.99, 10, 0),
            make_node("relay", 75_000, 0.98, 15, 0),
            make_node("exit", 50_000, 0.96, 8, 0),
        ];
        let state = build_circuit(&nodes).unwrap();
        let info = state.to_info();
        assert_eq!(info.entry.node_id, "entry");
        assert_eq!(info.relay.node_id, "relay");
        assert_eq!(info.exit.node_id, "exit");
        // Serialised info should not contain session_key field
        let json = serde_json::to_string(&info).unwrap();
        assert!(!json.contains("session_key"));
    }

    #[test]
    fn subnet_prefix_ipv4() {
        assert_eq!(subnet_prefix("1.2.3.4:51820"), Some("1.2.3".to_string()));
        assert_eq!(subnet_prefix("10.0.0.1:51820"), Some("10.0.0".to_string()));
        assert_eq!(subnet_prefix("invalid"), None);
    }

    #[test]
    fn subnet_prefix_ipv6() {
        assert_eq!(
            subnet_prefix("[2001:db8:abcd::1]:51820"),
            Some("2001:db8:abcd".to_string())
        );
        assert_eq!(
            subnet_prefix("[2001:db8:abcd:1234::1]:51820"),
            Some("2001:db8:abcd".to_string())
        );
        // Two IPv6 addresses on the same /48 should produce the same prefix.
        assert_eq!(
            subnet_prefix("[2001:db8:abcd::1]:51820"),
            subnet_prefix("[2001:db8:abcd::2]:51820"),
        );
        // Different /48 should produce different prefixes.
        assert_ne!(
            subnet_prefix("[2001:db8:abcd::1]:51820"),
            subnet_prefix("[2001:db8:abce::1]:51820"),
        );
    }

    #[test]
    fn diversity_rejects_same_subnet() {
        let mut a = make_node("a", 100_000, 0.9, 10, 0);
        a.endpoint = "10.0.1.1:51820".to_string();
        let mut b = make_node("b", 100_000, 0.9, 10, 0);
        b.endpoint = "10.0.1.2:51820".to_string(); // same /24
        let selected = [Some(a), None, None];
        assert!(!is_diverse(&b, &selected));
    }

    #[test]
    fn diversity_accepts_different_subnet() {
        let mut a = make_node("a", 100_000, 0.9, 10, 0);
        a.endpoint = "10.0.1.1:51820".to_string();
        let mut b = make_node("b", 100_000, 0.9, 10, 0);
        b.endpoint = "10.0.2.1:51820".to_string(); // different /24
        let selected = [Some(a), None, None];
        assert!(is_diverse(&b, &selected));
    }

    #[test]
    fn diversity_rejects_same_operator() {
        let mut a = make_node("a", 100_000, 0.9, 10, 0);
        a.operator_address = "0xABC".to_string();
        a.endpoint = "10.0.1.1:51820".to_string();
        let mut b = make_node("b", 100_000, 0.9, 10, 0);
        b.operator_address = "0xABC".to_string(); // same operator
        b.endpoint = "10.0.2.1:51820".to_string(); // different subnet
        let selected = [Some(a), None, None];
        assert!(!is_diverse(&b, &selected));
    }

    #[test]
    fn diversity_rejects_same_asn() {
        let mut a = make_node("a", 100_000, 0.9, 10, 0);
        a.asn = Some(13335);
        a.endpoint = "10.0.1.1:51820".to_string();
        let mut b = make_node("b", 100_000, 0.9, 10, 0);
        b.asn = Some(13335); // same ASN
        b.endpoint = "10.0.2.1:51820".to_string();
        let selected = [Some(a), None, None];
        assert!(!is_diverse(&b, &selected));
    }

    #[test]
    fn diverse_circuit_respects_subnet_separation() {
        // 9 nodes across 3 subnets: 10.0.1.x, 10.0.2.x, 10.0.3.x
        let mut nodes = Vec::new();
        let subnets = [1, 2, 3];
        let mut op_counter = 1;
        for &subnet in &subnets {
            for host in 1..=3 {
                let id = format!("subnet{}-{}", subnet, host);
                let mut n = make_node(&id, 1_000_000_000_000_000_000, 0.95, 10, 0);
                n.node_id = id;
                n.endpoint = format!("10.0.{}.{}:51820", subnet, host);
                n.operator_address = format!("0xOp{}", op_counter);
                op_counter += 1;
                nodes.push(n);
            }
        }

        for _ in 0..100 {
            let circuit =
                select_circuit_with_pins(&nodes, &[], &["", "", ""]).unwrap();
            let prefixes: Vec<Option<String>> = circuit
                .iter()
                .map(|n| subnet_prefix(&n.endpoint))
                .collect();
            // All 3 nodes must have different subnet prefixes.
            assert_ne!(prefixes[0], prefixes[1], "entry and relay share subnet");
            assert_ne!(prefixes[1], prefixes[2], "relay and exit share subnet");
            assert_ne!(prefixes[0], prefixes[2], "entry and exit share subnet");
        }
    }

    #[test]
    fn fallback_when_all_same_asn() {
        // 6 nodes on different subnets but all sharing ASN 13335.
        let mut nodes = Vec::new();
        for i in 1..=6 {
            let id = format!("asn-node-{}", i);
            let mut n = make_node(&id, 1_000_000_000_000_000_000, 0.95, 10, 0);
            n.node_id = id;
            n.endpoint = format!("10.0.{}.1:51820", i);
            n.operator_address = format!("0xOp{}", i);
            n.asn = Some(13335);
            nodes.push(n);
        }

        // Should succeed via fallback (relaxed diversity when no diverse candidates exist).
        let result = select_circuit_with_pins(&nodes, &[], &["", "", ""]);
        assert!(result.is_ok(), "expected Ok but got: {:?}", result);
    }

    #[test]
    fn diversity_rejects_same_operator_in_circuit() {
        // 6 nodes on 6 different subnets. 3 share operator "0xSame", 3 are unique.
        let mut nodes = Vec::new();
        for i in 1..=3 {
            let id = format!("same-op-{}", i);
            let mut n = make_node(&id, 1_000_000_000_000_000_000, 0.95, 10, 0);
            n.node_id = id;
            n.endpoint = format!("10.0.{}.1:51820", i);
            n.operator_address = "0xSame".to_string();
            nodes.push(n);
        }
        for i in 4..=6 {
            let id = format!("unique-op-{}", i);
            let mut n = make_node(&id, 1_000_000_000_000_000_000, 0.95, 10, 0);
            n.node_id = id;
            n.endpoint = format!("10.0.{}.1:51820", i);
            n.operator_address = format!("0xOp{}", i);
            nodes.push(n);
        }

        for _ in 0..50 {
            let circuit =
                select_circuit_with_pins(&nodes, &[], &["", "", ""]).unwrap();
            let same_op_count = circuit
                .iter()
                .filter(|n| n.operator_address == "0xSame")
                .count();
            assert!(
                same_op_count <= 1,
                "circuit contained {} nodes from 0xSame operator (max 1 allowed): [{}, {}, {}]",
                same_op_count,
                circuit[0].node_id,
                circuit[1].node_id,
                circuit[2].node_id,
            );
        }
    }

    #[test]
    fn diverse_circuit_with_pins() {
        // 6 nodes on 6 different subnets with unique operators.
        let mut nodes = Vec::new();
        for i in 1..=6 {
            let id = format!("pin-node-{}", i);
            let mut n = make_node(&id, 1_000_000_000_000_000_000, 0.95, 10, 0);
            n.node_id = id;
            n.endpoint = format!("10.0.{}.1:51820", i);
            n.operator_address = format!("0xOp{}", i);
            nodes.push(n);
        }

        let pinned_entry = "pin-node-1";
        let pinned_exit = "pin-node-3";
        let entry_subnet = subnet_prefix("10.0.1.1:51820").unwrap();
        let exit_subnet = subnet_prefix("10.0.3.1:51820").unwrap();

        for _ in 0..50 {
            let circuit = select_circuit_with_pins(
                &nodes,
                &[],
                &[pinned_entry, "", pinned_exit],
            )
            .unwrap();

            // Verify pinned positions are respected.
            assert_eq!(circuit[0].node_id, pinned_entry);
            assert_eq!(circuit[2].node_id, pinned_exit);

            // Relay must not share subnet with pinned entry or exit.
            let relay_subnet = subnet_prefix(&circuit[1].endpoint).unwrap();
            assert_ne!(
                relay_subnet, entry_subnet,
                "relay shares subnet with pinned entry"
            );
            assert_ne!(
                relay_subnet, exit_subnet,
                "relay shares subnet with pinned exit"
            );
        }
    }

    #[test]
    fn fallback_all_same_subnet_and_operator() {
        // 4 nodes all on 10.0.1.x with the same operator — worst-case diversity.
        let mut nodes = Vec::new();
        for i in 1..=4 {
            let id = format!("shared-{}", i);
            let mut n = make_node(&id, 1_000_000_000_000_000_000, 0.95, 10, 0);
            n.node_id = id;
            n.endpoint = format!("10.0.1.{}:51820", i);
            n.operator_address = "0xShared".to_string();
            nodes.push(n);
        }

        // Should succeed via fallback despite zero diversity.
        let result = select_circuit_with_pins(&nodes, &[], &["", "", ""]);
        assert!(result.is_ok(), "expected Ok but got: {:?}", result);

        let circuit = result.unwrap();
        // All 3 node IDs must be distinct.
        let mut ids: Vec<&str> = circuit.iter().map(|n| n.node_id.as_str()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(
            ids.len(),
            3,
            "expected 3 distinct node_ids, got: {:?}",
            circuit.iter().map(|n| &n.node_id).collect::<Vec<_>>()
        );
    }
}
