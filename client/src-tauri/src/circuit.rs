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
/// Higher is better.  The formula rewards high stake and uptime while
/// penalising high price and previous slashes.
///
/// ```text
/// score = (stake_weight * ln(1 + stake))
///       + (uptime_weight * uptime)
///       - (price_weight  * price_per_byte)
///       - (slash_penalty  * slash_count^2)
/// ```
pub fn score_node(node: &NodeInfo) -> f64 {
    let stake_weight: f64 = 1.0;
    let uptime_weight: f64 = 50.0;
    let price_weight: f64 = 0.001;
    let slash_penalty: f64 = 20.0;

    let stake_score = stake_weight * ((1.0 + node.stake as f64).ln());
    let uptime_score = uptime_weight * node.uptime;
    let price_score = price_weight * node.price_per_byte as f64;
    let slash_score = slash_penalty * (node.slash_count as f64).powi(2);

    stake_score + uptime_score - price_score - slash_score
}

/// Select a three-hop circuit (entry, relay, exit) from the candidate list.
///
/// Nodes are ranked by [`score_node`] and the top three *distinct* nodes are
/// returned.  In the future this will also enforce geographic / AS diversity.
pub fn select_circuit(nodes: &[NodeInfo]) -> Result<[NodeInfo; 3], String> {
    if nodes.len() < 3 {
        return Err(format!(
            "need at least 3 nodes to form a circuit, got {}",
            nodes.len()
        ));
    }

    let mut scored: Vec<(f64, &NodeInfo)> = nodes.iter().map(|n| (score_node(n), n)).collect();

    // Sort descending by score.
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

    Ok([
        scored[0].1.clone(), // entry
        scored[1].1.clone(), // relay
        scored[2].1.clone(), // exit
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
    fn higher_stake_and_uptime_wins() {
        let good = make_node("good", 100_000, 0.99, 10, 0);
        let bad = make_node("bad", 1_000, 0.50, 100, 2);
        assert!(score_node(&good) > score_node(&bad));
    }

    #[test]
    fn select_single_picks_best() {
        let nodes = vec![
            make_node("a", 500, 0.80, 50, 1),
            make_node("b", 100_000, 0.99, 10, 0),
            make_node("c", 2_000, 0.70, 30, 0),
        ];
        let best = select_single_node(&nodes).unwrap();
        assert_eq!(best.node_id, "b");
    }

    #[test]
    fn circuit_needs_three() {
        let nodes = vec![
            make_node("a", 500, 0.80, 50, 0),
            make_node("b", 600, 0.90, 40, 0),
        ];
        assert!(select_circuit(&nodes).is_err());
    }

    #[test]
    fn circuit_returns_three() {
        let nodes = vec![
            make_node("a", 500, 0.80, 50, 0),
            make_node("b", 100_000, 0.99, 10, 0),
            make_node("c", 2_000, 0.70, 30, 0),
            make_node("d", 80_000, 0.95, 15, 0),
        ];
        let circuit = select_circuit(&nodes).unwrap();
        assert_eq!(circuit.len(), 3);
        // Best node should be entry
        assert_eq!(circuit[0].node_id, "b");
    }

    #[test]
    fn build_circuit_produces_unique_keys() {
        let nodes = [
            make_node("entry", 100_000, 0.99, 10, 0),
            make_node("relay", 75_000, 0.98, 15, 0),
            make_node("exit", 50_000, 0.96, 8, 0),
        ];
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
