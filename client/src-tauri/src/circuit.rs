use serde::{Deserialize, Serialize};

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
}
