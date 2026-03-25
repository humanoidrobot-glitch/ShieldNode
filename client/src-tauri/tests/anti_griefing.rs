//! Anti-griefing integration tests.
//!
//! Tests the full pipeline: reputation flags → scoring deprioritization →
//! circuit selection avoidance. Simulates adversarial node behavior and
//! verifies the client-side defenses respond correctly.

use std::time::Duration;

// Re-export from lib crate.
use shieldnode_client_lib::circuit::{self, NodeInfo};
use shieldnode_client_lib::reputation::ReputationCache;

fn make_test_node(id: &str, endpoint: &str, operator: &str) -> NodeInfo {
    NodeInfo {
        node_id: id.to_string(),
        public_key: vec![0u8; 32],
        endpoint: endpoint.to_string(),
        stake: 1_000_000_000_000_000_000, // 1 ETH
        uptime: 0.99,
        price_per_byte: 10,
        slash_count: 0,
        completion_rate: 1.0,
        operator_address: operator.to_string(),
        asn: None,
        region: None,
        tee_attested: false,
    }
}

// ── Test: Completion scoring deprioritizes bad nodes ─────────────────

#[test]
fn low_completion_rate_reduces_score() {
    let good = {
        let mut n = make_test_node("good", "10.0.1.1:51820", "0xA");
        n.completion_rate = 1.0;
        n
    };
    let bad = {
        let mut n = make_test_node("bad", "10.0.2.1:51820", "0xB");
        n.completion_rate = 0.2; // most sessions abandoned
        n
    };

    let good_score = circuit::score_node(&good);
    let bad_score = circuit::score_node(&bad);

    // Bad node should score significantly lower due to low completion rate.
    assert!(
        good_score > bad_score + 10.0,
        "good={good_score:.1} bad={bad_score:.1} — completion rate penalty insufficient"
    );
}

// ── Test: Bandwidth flag accumulation and penalty ─────────────────────

#[test]
fn three_low_bandwidth_sessions_trigger_penalty() {
    let mut cache = ReputationCache::new();
    let nodes = vec!["node-a".to_string()];

    // Two bad sessions — below threshold.
    for _ in 0..2 {
        cache.record_session(&nodes, 500_000, Duration::from_secs(600));
    }
    assert_eq!(cache.score_penalty("node-a"), 0.0, "2 flags should not penalize");

    // Third bad session — triggers penalty.
    cache.record_session(&nodes, 500_000, Duration::from_secs(600));
    assert!(
        cache.score_penalty("node-a") > 0.0,
        "3 flags should trigger penalty"
    );
}

#[test]
fn good_sessions_dont_flag() {
    let mut cache = ReputationCache::new();
    let nodes = vec!["node-a".to_string()];

    // 10 good sessions (>1MB each).
    for _ in 0..10 {
        cache.record_session(&nodes, 5_000_000, Duration::from_secs(600));
    }
    assert_eq!(cache.score_penalty("node-a"), 0.0);
}

#[test]
fn short_sessions_dont_flag_even_with_low_bytes() {
    let mut cache = ReputationCache::new();
    let nodes = vec!["node-a".to_string()];

    // Short sessions (<5 min) with low bytes — not flagged.
    for _ in 0..5 {
        cache.record_session(&nodes, 100, Duration::from_secs(30));
    }
    assert_eq!(cache.score_penalty("node-a"), 0.0);
}

// ── Test: Traffic anomaly flags are separate from bandwidth flags ─────

#[test]
fn traffic_anomaly_uses_separate_counter() {
    let mut cache = ReputationCache::new();

    // 2 bandwidth flags + 2 anomaly flags = neither reaches threshold of 3.
    let nodes = vec!["node-a".to_string()];
    cache.record_session(&nodes, 500_000, Duration::from_secs(600));
    cache.record_session(&nodes, 500_000, Duration::from_secs(600));
    cache.record_traffic_anomaly("node-a");
    cache.record_traffic_anomaly("node-a");

    // Neither category has 3 flags — should not be penalized.
    // (bandwidth=2, anomaly=2, threshold=3 each)
    assert_eq!(cache.score_penalty("node-a"), 0.0);
}

#[test]
fn anomaly_penalty_is_higher_than_bandwidth() {
    let mut cache = ReputationCache::new();

    // 3 anomaly flags triggers the anomaly penalty.
    for _ in 0..3 {
        cache.record_traffic_anomaly("node-a");
    }
    let penalty = cache.score_penalty("node-a");
    assert!(penalty > 15.0, "anomaly penalty ({penalty}) should be > bandwidth penalty (15)");
}

// ── Test: Penalized node gets lower score in circuit selection ────────

#[test]
fn penalized_node_deprioritized_in_selection() {
    let mut good = make_test_node("good", "10.0.1.1:51820", "0xA");
    good.completion_rate = 1.0;

    let mut penalized = make_test_node("penalized", "10.0.2.1:51820", "0xB");
    penalized.completion_rate = 0.0; // reputation penalty applied

    let good_score = circuit::score_node(&good);
    let penalized_score = circuit::score_node(&penalized);

    assert!(
        good_score > penalized_score,
        "penalized node should score lower: good={good_score:.1} penalized={penalized_score:.1}"
    );
}

// ── Test: Stake concentration flags suspicious clusters ───────────────

#[test]
fn identical_stake_cluster_detected() {
    let mut cache = ReputationCache::new();
    let nodes: Vec<NodeInfo> = (0..4)
        .map(|i| {
            let mut n = make_test_node(
                &format!("node-{i}"),
                &format!("10.0.{i}.1:51820"),
                &format!("0xOp{i}"),
            );
            n.stake = 500_000_000_000_000_000; // all identical (0.5 ETH)
            n
        })
        .collect();

    let flagged = cache.detect_stake_clusters(&nodes);
    assert_eq!(flagged.len(), 4, "all 4 nodes with identical stake should be flagged");
}

#[test]
fn diverse_stakes_not_flagged() {
    let mut cache = ReputationCache::new();
    let nodes: Vec<NodeInfo> = vec![
        {
            let mut n = make_test_node("a", "10.0.1.1:51820", "0xA");
            n.stake = 500_000_000_000_000_000;
            n.uptime = 0.95;
            n
        },
        {
            let mut n = make_test_node("b", "10.0.2.1:51820", "0xB");
            n.stake = 750_000_000_000_000_000;
            n.uptime = 0.85;
            n
        },
        {
            let mut n = make_test_node("c", "10.0.3.1:51820", "0xC");
            n.stake = 1_000_000_000_000_000_000;
            n.uptime = 0.75;
            n
        },
    ];

    let flagged = cache.detect_stake_clusters(&nodes);
    assert!(flagged.is_empty(), "diverse stakes should not be flagged");
}

// ── Test: Circuit diversity rejects same-infra nodes ─────────────────

#[test]
fn circuit_selection_avoids_same_subnet() {
    // 3 nodes on different subnets + 2 on the same subnet as node-a.
    let nodes = vec![
        make_test_node("a", "10.0.1.1:51820", "0xA"),
        make_test_node("b", "10.0.2.1:51820", "0xB"),
        make_test_node("c", "10.0.3.1:51820", "0xC"),
        make_test_node("d", "10.0.1.2:51820", "0xD"), // same /24 as 'a'
        make_test_node("e", "10.0.1.3:51820", "0xE"), // same /24 as 'a'
    ];

    // Run selection 50 times. Nodes 'a', 'd', 'e' share a /24.
    // Diversity constraints should prevent all three from being in one circuit.
    for _ in 0..50 {
        let selected = circuit::select_circuit(&nodes, &[]).unwrap();
        let subnets: Vec<String> = selected
            .iter()
            .filter_map(|n| {
                let host = n.endpoint.split(':').next()?;
                let octets: Vec<&str> = host.split('.').collect();
                Some(format!("{}.{}.{}", octets[0], octets[1], octets[2]))
            })
            .collect();

        // No two hops should share a /24.
        assert_ne!(subnets[0], subnets[1], "entry and relay share subnet");
        assert_ne!(subnets[1], subnets[2], "relay and exit share subnet");
        assert_ne!(subnets[0], subnets[2], "entry and exit share subnet");
    }
}

#[test]
fn circuit_selection_avoids_same_operator() {
    let nodes = vec![
        make_test_node("a", "10.0.1.1:51820", "0xSameOp"),
        make_test_node("b", "10.0.2.1:51820", "0xSameOp"), // same operator
        make_test_node("c", "10.0.3.1:51820", "0xOtherOp1"),
        make_test_node("d", "10.0.4.1:51820", "0xOtherOp2"),
        make_test_node("e", "10.0.5.1:51820", "0xOtherOp3"),
    ];

    for _ in 0..50 {
        let selected = circuit::select_circuit(&nodes, &[]).unwrap();
        let ops: Vec<&str> = selected.iter().map(|n| n.operator_address.as_str()).collect();

        // No two hops should share an operator.
        assert_ne!(ops[0], ops[1], "entry and relay share operator");
        assert_ne!(ops[1], ops[2], "relay and exit share operator");
        assert_ne!(ops[0], ops[2], "entry and exit share operator");
    }
}
