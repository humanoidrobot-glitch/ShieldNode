use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::hop_codec;

/// Metadata describing a single ShieldNode relay / exit node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub public_key: [u8; 32],
    pub endpoint: String,
    pub stake: u64,
    pub uptime: f64,
    pub price_per_byte: u64,
    pub slash_count: u32,
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

/// Build a 3-hop circuit from the given nodes, deriving a placeholder
/// session key for each hop via ephemeral X25519 + HKDF.
///
/// Real Noise NK handshakes will replace this in Phase 2+.
pub fn build_circuit(nodes: &[NodeInfo; 3]) -> Result<CircuitState, String> {
    let mut hops: Vec<CircuitHop> = Vec::with_capacity(3);

    for (i, node) in nodes.iter().enumerate() {
        let eph_secret = StaticSecret::random_from_rng(OsRng);
        let peer_public = PublicKey::from(node.public_key);

        // Perform a single DH: eph_secret * peer_public
        let shared = eph_secret.diffie_hellman(&peer_public);

        // Derive a 32-byte session key via HKDF-SHA256
        let hk = Hkdf::<Sha256>::new(Some(b"ShieldNode-circuit-v1"), shared.as_bytes());
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
        });
    }

    Ok(CircuitState {
        entry: hops.remove(0),
        relay: hops.remove(0),
        exit: hops.remove(0),
    })
}

/// Score a node for selection.
///
/// Higher is better.  Stake is the dominant factor (square-root scaling)
/// so that higher-staked nodes get meaningfully more sessions routed to
/// them, making staking a revenue accelerator.
///
/// ```text
/// score = 10 * sqrt(stake / 1e18)     ← dominant: 0.1 ETH → 3.16, 1 ETH → 10, 4 ETH → 20
///       + 30 * uptime                  ← 0..30 range
///       - 0.001 * price_per_byte       ← small penalty for expensive nodes
///       - 20 * slash_count^2           ← harsh penalty for slashed nodes
/// ```
pub fn score_node(node: &NodeInfo) -> f64 {
    // Stake is stored in wei-like units (1e18 per ETH).
    let stake_eth = node.stake as f64 / 1e18;
    let stake_score = 10.0 * stake_eth.sqrt();

    let uptime_score = 30.0 * node.uptime;
    let price_score = 0.001 * node.price_per_byte as f64;
    let slash_score = 20.0 * (node.slash_count as f64).powi(2);

    stake_score + uptime_score - price_score - slash_score
}

/// Select a three-hop circuit (entry, relay, exit) via weighted random sampling.
///
/// Each node's selection probability is proportional to its score (clamped to
/// a minimum of 1.0 so even low-scored nodes have *some* chance).  This means
/// higher-staked nodes are picked more often — staking is a revenue accelerator
/// — but the network still distributes load across all viable nodes.
///
/// When `exclude_ids` is non-empty, those nodes receive a heavy score penalty
/// to encourage diversity on circuit rotation.
pub fn select_circuit(
    nodes: &[NodeInfo],
    exclude_ids: &[&str],
) -> Result<[NodeInfo; 3], String> {
    if nodes.len() < 3 {
        return Err(format!(
            "need at least 3 nodes to form a circuit, got {}",
            nodes.len()
        ));
    }

    // Filter out excluded nodes entirely, score the rest.
    let mut candidates: Vec<(f64, &NodeInfo)> = nodes
        .iter()
        .filter(|n| !exclude_ids.contains(&n.node_id.as_str()))
        .map(|n| {
            let weight = score_node(n).max(1.0);
            (weight, n)
        })
        .collect();

    if candidates.len() < 3 {
        // Not enough non-excluded nodes — fall back to scoring all nodes.
        candidates = nodes
            .iter()
            .map(|n| (score_node(n).max(1.0), n))
            .collect();
    }

    let mut selected = Vec::with_capacity(3);
    let mut rng = rand::thread_rng();

    for _ in 0..3 {
        let total: f64 = candidates.iter().map(|(w, _)| w).sum();
        let mut roll: f64 = rng.gen::<f64>() * total;

        let mut pick_idx = candidates.len() - 1;
        for (i, (w, _)) in candidates.iter().enumerate() {
            roll -= w;
            if roll <= 0.0 {
                pick_idx = i;
                break;
            }
        }

        selected.push(candidates[pick_idx].1.clone());
        candidates.swap_remove(pick_idx);
    }

    Ok([
        selected.remove(0),
        selected.remove(0),
        selected.remove(0),
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
            public_key: [0u8; 32],
            endpoint: "127.0.0.1:51820".to_string(),
            stake,
            uptime,
            price_per_byte: price,
            slash_count: slashes,
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
        nodes[0].public_key = [1u8; 32];
        nodes[1].public_key = [2u8; 32];
        nodes[2].public_key = [3u8; 32];
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
}
