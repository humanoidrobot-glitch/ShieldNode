//! Local node reputation cache for the client.
//!
//! Tracks nodes that consistently deliver poor bandwidth. If a session
//! settles with <1MB transferred over >5 minutes, the node gets a
//! low-bandwidth flag. Nodes with 3+ flags in 24 hours receive a score
//! penalty equivalent to a minor slash.
//!
//! This is entirely client-side — no contract changes needed. It acts
//! as a fast local signal before on-chain completion rate data accumulates.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tracing::info;

/// Minimum bytes for a session to count as "completed" (1 MB).
const MIN_BYTES_COMPLETED: u64 = 1_000_000;

/// Minimum session duration for a low-bandwidth flag (5 minutes).
const MIN_DURATION_FOR_FLAG: Duration = Duration::from_secs(5 * 60);

/// Number of flags in the window that triggers a score penalty.
const FLAG_THRESHOLD: usize = 3;

/// Time window for counting flags (24 hours).
const FLAG_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

/// Score penalty per flagged node (equivalent to a minor slash).
pub const LOW_BW_SCORE_PENALTY: f64 = 15.0;

/// Score penalty for traffic volume anomalies (higher — security signal).
pub const ANOMALY_SCORE_PENALTY: f64 = 25.0;

/// A record of low-bandwidth flags for a single node.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NodeReputation {
    /// Timestamps of recent low-bandwidth flags.
    #[serde(skip)]
    flags: Vec<Instant>,
    /// Timestamps of recent traffic anomaly flags (separate from bandwidth).
    #[serde(skip)]
    anomaly_flags: Vec<Instant>,
}

impl NodeReputation {
    fn new() -> Self {
        Self {
            flags: Vec::new(),
            anomaly_flags: Vec::new(),
        }
    }

    fn add_flag(&mut self) {
        self.flags.push(Instant::now());
    }

    fn add_anomaly_flag(&mut self) {
        self.anomaly_flags.push(Instant::now());
    }

    fn recent_flag_count(&self) -> usize {
        let cutoff = Instant::now() - FLAG_WINDOW;
        self.flags.iter().filter(|&&t| t > cutoff).count()
    }

    fn recent_anomaly_count(&self) -> usize {
        let cutoff = Instant::now() - FLAG_WINDOW;
        self.anomaly_flags.iter().filter(|&&t| t > cutoff).count()
    }

    fn evict_stale(&mut self) {
        let cutoff = Instant::now() - FLAG_WINDOW;
        self.flags.retain(|&t| t > cutoff);
        self.anomaly_flags.retain(|&t| t > cutoff);
    }

    fn is_penalized(&self) -> bool {
        self.recent_flag_count() >= FLAG_THRESHOLD
    }

    fn is_anomaly_penalized(&self) -> bool {
        self.recent_anomaly_count() >= FLAG_THRESHOLD
    }

    fn has_any_flags(&self) -> bool {
        !self.flags.is_empty() || !self.anomaly_flags.is_empty()
    }
}

/// Client-local reputation cache for all known nodes.
#[derive(Debug, Default)]
pub struct ReputationCache {
    nodes: HashMap<String, NodeReputation>,
}

impl ReputationCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the outcome of a settled session. If the session transferred
    /// <1MB over >5 minutes, flag all circuit nodes as low-bandwidth.
    pub fn record_session(
        &mut self,
        node_ids: &[String],
        bytes_transferred: u64,
        duration: Duration,
    ) {
        let is_low_bw = bytes_transferred < MIN_BYTES_COMPLETED
            && duration >= MIN_DURATION_FOR_FLAG;

        if !is_low_bw {
            return;
        }

        for node_id in node_ids {
            let rep = self
                .nodes
                .entry(node_id.clone())
                .or_insert_with(NodeReputation::new);
            rep.add_flag();
            info!(
                node_id,
                flags = rep.recent_flag_count(),
                "low-bandwidth flag recorded"
            );
        }
    }

    /// Record a suspicious traffic volume verdict for a relay node.
    /// Treated the same as a low-bandwidth flag — 3 verdicts in 24h = penalized.
    pub fn record_traffic_anomaly(&mut self, relay_node_id: &str) {
        let rep = self
            .nodes
            .entry(relay_node_id.to_string())
            .or_insert_with(NodeReputation::new);
        rep.add_anomaly_flag();
        info!(
            relay_node_id,
            anomaly_flags = rep.recent_anomaly_count(),
            "traffic volume anomaly flag recorded"
        );
    }

    /// Get the score penalty for a node. Returns 0.0 if the node is not
    /// penalized, or LOW_BW_SCORE_PENALTY if it has 3+ flags in 24h.
    pub fn score_penalty(&self, node_id: &str) -> f64 {
        match self.nodes.get(node_id) {
            Some(rep) => {
                let bw = if rep.is_penalized() { LOW_BW_SCORE_PENALTY } else { 0.0 };
                let anomaly = if rep.is_anomaly_penalized() { ANOMALY_SCORE_PENALTY } else { 0.0 };
                bw.max(anomaly)
            }
            None => 0.0,
        }
    }

    /// Evict stale flags across all nodes. Call periodically.
    pub fn evict_stale(&mut self) {
        for rep in self.nodes.values_mut() {
            rep.evict_stale();
        }
        // Remove nodes with no remaining flags.
        self.nodes.retain(|_, rep| rep.has_any_flags());
    }

    /// Number of currently penalized nodes.
    pub fn penalized_count(&self) -> usize {
        self.nodes.values().filter(|r| r.is_penalized()).count()
    }

    /// Analyze a set of nodes for suspicious stake concentration patterns.
    /// Flags clusters that share: identical stake amounts registered in a
    /// short time window, or correlated uptime patterns.
    /// Returns node IDs that should receive a scoring penalty.
    pub fn detect_stake_clusters(
        &mut self,
        nodes: &[crate::circuit::NodeInfo],
    ) -> Vec<String> {
        let mut flagged = Vec::new();

        // Heuristic 1: identical stakes from different operators.
        // Group by stake amount — if 3+ nodes have the exact same stake
        // (beyond the 0.1 ETH minimum), flag them.
        let min_stake: u64 = 100_000_000_000_000_000; // 0.1 ETH
        let mut stake_groups: HashMap<u64, Vec<&str>> = HashMap::new();
        for node in nodes {
            if node.stake > min_stake {
                stake_groups
                    .entry(node.stake)
                    .or_default()
                    .push(&node.node_id);
            }
        }
        for (_, group) in &stake_groups {
            if group.len() >= 3 {
                for id in group {
                    if !flagged.contains(&id.to_string()) {
                        flagged.push(id.to_string());
                    }
                }
            }
        }

        // Heuristic 2: correlated uptime (all within ±1% of each other).
        // Nodes operated by the same entity on the same infra tend to have
        // near-identical uptime values.
        if nodes.len() >= 3 {
            for i in 0..nodes.len() {
                let mut correlated = vec![&nodes[i]];
                for j in (i + 1)..nodes.len() {
                    if (nodes[i].uptime - nodes[j].uptime).abs() < 0.01
                        && !nodes[i].operator_address.is_empty()
                        && !nodes[j].operator_address.is_empty()
                        && nodes[i].operator_address != nodes[j].operator_address
                    {
                        correlated.push(&nodes[j]);
                    }
                }
                if correlated.len() >= 3 {
                    for n in &correlated {
                        if !flagged.contains(&n.node_id) {
                            flagged.push(n.node_id.clone());
                        }
                    }
                }
            }
        }

        // Record flags for penalized nodes.
        for id in &flagged {
            let rep = self
                .nodes
                .entry(id.clone())
                .or_insert_with(NodeReputation::new);
            rep.add_flag();
        }

        flagged
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_flag_for_completed_session() {
        let mut cache = ReputationCache::new();
        cache.record_session(
            &["node-a".to_string()],
            2_000_000, // 2MB — above threshold
            Duration::from_secs(600),
        );
        assert_eq!(cache.score_penalty("node-a"), 0.0);
    }

    #[test]
    fn no_flag_for_short_session() {
        let mut cache = ReputationCache::new();
        cache.record_session(
            &["node-a".to_string()],
            500_000, // <1MB
            Duration::from_secs(60), // <5min — too short to flag
        );
        assert_eq!(cache.score_penalty("node-a"), 0.0);
    }

    #[test]
    fn flag_for_low_bandwidth_long_session() {
        let mut cache = ReputationCache::new();
        let nodes = vec!["node-a".to_string()];

        // 3 bad sessions → penalized
        for _ in 0..3 {
            cache.record_session(&nodes, 100_000, Duration::from_secs(600));
        }
        assert_eq!(cache.score_penalty("node-a"), LOW_BW_SCORE_PENALTY);
    }

    #[test]
    fn below_threshold_not_penalized() {
        let mut cache = ReputationCache::new();
        let nodes = vec!["node-a".to_string()];

        // Only 2 flags — below threshold
        for _ in 0..2 {
            cache.record_session(&nodes, 100_000, Duration::from_secs(600));
        }
        assert_eq!(cache.score_penalty("node-a"), 0.0);
    }

    #[test]
    fn stake_cluster_detected_for_identical_stakes() {
        use crate::circuit::NodeInfo;
        let mut cache = ReputationCache::new();
        let nodes: Vec<NodeInfo> = (0..4)
            .map(|i| NodeInfo {
                node_id: format!("node-{i}"),
                public_key: vec![0u8; 32],
                endpoint: format!("10.0.{i}.1:51820"),
                stake: 500_000_000_000_000_000, // 0.5 ETH — above minimum
                uptime: 0.5 + (i as f64 * 0.1),  // varied uptime
                price_per_byte: 10,
                slash_count: 0,
                completion_rate: 1.0,
                operator_address: format!("0xOp{i}"),
                asn: None,
                region: None,
                tee_attested: false,
            })
            .collect();
        let flagged = cache.detect_stake_clusters(&nodes);
        // 4 nodes with identical stake > min → all flagged
        assert_eq!(flagged.len(), 4);
    }

    #[test]
    fn stake_cluster_not_detected_below_threshold() {
        use crate::circuit::NodeInfo;
        let mut cache = ReputationCache::new();
        let nodes: Vec<NodeInfo> = (0..2)
            .map(|i| NodeInfo {
                node_id: format!("node-{i}"),
                public_key: vec![0u8; 32],
                endpoint: format!("10.0.{i}.1:51820"),
                stake: 500_000_000_000_000_000,
                uptime: 0.9,
                price_per_byte: 10,
                slash_count: 0,
                completion_rate: 1.0,
                operator_address: format!("0xOp{i}"),
                asn: None,
                region: None,
                tee_attested: false,
            })
            .collect();
        let flagged = cache.detect_stake_clusters(&nodes);
        // Only 2 nodes — below threshold of 3
        assert!(flagged.is_empty());
    }

    #[test]
    fn flags_all_circuit_nodes() {
        let mut cache = ReputationCache::new();
        let nodes = vec![
            "entry".to_string(),
            "relay".to_string(),
            "exit".to_string(),
        ];

        for _ in 0..3 {
            cache.record_session(&nodes, 100_000, Duration::from_secs(600));
        }

        assert_eq!(cache.score_penalty("entry"), LOW_BW_SCORE_PENALTY);
        assert_eq!(cache.score_penalty("relay"), LOW_BW_SCORE_PENALTY);
        assert_eq!(cache.score_penalty("exit"), LOW_BW_SCORE_PENALTY);
    }
}
