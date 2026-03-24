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

/// A record of low-bandwidth flags for a single node.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NodeReputation {
    /// Timestamps of recent low-bandwidth flags.
    #[serde(skip)]
    flags: Vec<Instant>,
}

impl NodeReputation {
    fn new() -> Self {
        Self { flags: Vec::new() }
    }

    fn add_flag(&mut self) {
        self.flags.push(Instant::now());
    }

    /// Count flags within the rolling window.
    fn recent_flag_count(&self) -> usize {
        let cutoff = Instant::now() - FLAG_WINDOW;
        self.flags.iter().filter(|&&t| t > cutoff).count()
    }

    /// Evict flags older than the window.
    fn evict_stale(&mut self) {
        let cutoff = Instant::now() - FLAG_WINDOW;
        self.flags.retain(|&t| t > cutoff);
    }

    fn is_penalized(&self) -> bool {
        self.recent_flag_count() >= FLAG_THRESHOLD
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

    /// Get the score penalty for a node. Returns 0.0 if the node is not
    /// penalized, or LOW_BW_SCORE_PENALTY if it has 3+ flags in 24h.
    pub fn score_penalty(&self, node_id: &str) -> f64 {
        match self.nodes.get(node_id) {
            Some(rep) if rep.is_penalized() => LOW_BW_SCORE_PENALTY,
            _ => 0.0,
        }
    }

    /// Evict stale flags across all nodes. Call periodically.
    pub fn evict_stale(&mut self) {
        for rep in self.nodes.values_mut() {
            rep.evict_stale();
        }
        // Remove nodes with no remaining flags.
        self.nodes.retain(|_, rep| !rep.flags.is_empty());
    }

    /// Number of currently penalized nodes.
    pub fn penalized_count(&self) -> usize {
        self.nodes.values().filter(|r| r.is_penalized()).count()
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
