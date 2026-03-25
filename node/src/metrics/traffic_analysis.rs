//! Traffic volume analysis for relay exfiltration detection.
//!
//! Entry and exit nodes in a circuit independently measure total bytes the
//! relay node receives and sends. If the relay is forwarding honestly,
//! bytes_out ≈ bytes_in (minus Sphinx layer overhead per hop). If the relay
//! is exfiltrating captured data to a logging server, bytes_out > bytes_in
//! by a measurable margin.
//!
//! This is a weak signal individually — catches obvious real-time exfiltration
//! but not sophisticated covert channels. Additive with other defense layers.

use serde::{Deserialize, Serialize};

/// Maximum acceptable divergence between bytes sent to relay and bytes
/// received from relay, expressed as a fraction. Accounts for Sphinx layer
/// overhead (~80 bytes/packet) and protocol control messages.
const MAX_DIVERGENCE_RATIO: f64 = 0.15; // 15%

/// Minimum bytes transferred before analysis is meaningful.
/// Below this threshold, noise dominates the signal.
const MIN_BYTES_FOR_ANALYSIS: u64 = 100_000; // 100 KB

/// Report from one side of a relay link (entry or exit perspective).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficReport {
    /// Session ID this report covers.
    pub session_id: u64,
    /// Node ID of the relay being observed.
    pub relay_node_id: String,
    /// Total bytes sent TO the relay by this node.
    pub bytes_sent_to_relay: u64,
    /// Total bytes received FROM the relay by this node.
    pub bytes_received_from_relay: u64,
}

/// Result of analyzing traffic volume for a relay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TrafficVerdict {
    /// Traffic volumes are within acceptable bounds.
    Normal,
    /// Not enough data to make a determination.
    InsufficientData,
    /// Relay is sending significantly more data than expected (possible exfiltration).
    SuspiciousExcess {
        /// The observed divergence ratio (bytes_out / bytes_in - 1.0).
        divergence_ratio: f64,
    },
}

/// Analyze a pair of traffic reports (entry + exit perspective on the same relay).
///
/// If only one report is available, analyze it alone (weaker signal).
pub fn analyze_relay_traffic(
    entry_report: Option<&TrafficReport>,
    exit_report: Option<&TrafficReport>,
) -> TrafficVerdict {
    // Combine available data.
    let (total_sent_to_relay, total_received_from_relay) = match (entry_report, exit_report) {
        (Some(e), Some(x)) => (
            e.bytes_sent_to_relay + x.bytes_sent_to_relay,
            e.bytes_received_from_relay + x.bytes_received_from_relay,
        ),
        (Some(r), None) | (None, Some(r)) => (
            r.bytes_sent_to_relay,
            r.bytes_received_from_relay,
        ),
        (None, None) => return TrafficVerdict::InsufficientData,
    };

    if total_sent_to_relay < MIN_BYTES_FOR_ANALYSIS {
        return TrafficVerdict::InsufficientData;
    }

    // A honest relay: bytes_out ≈ bytes_in (slightly less due to Sphinx peeling).
    // An exfiltrating relay: bytes_out > bytes_in (sending captured data elsewhere).
    //
    // We measure from the perspective of the entry/exit: bytes they sent to the
    // relay vs bytes they received from the relay. For a honest relay forwarding
    // a bidirectional tunnel, sent ≈ received within protocol overhead.
    let sent = total_sent_to_relay as f64;
    let received = total_received_from_relay as f64;

    // Check if the relay is sending back significantly more than it received.
    // This could indicate the relay is injecting extra traffic (unlikely attack)
    // or the relay is forwarding exfiltrated data through the circuit (more likely).
    // Only flag excess: relay sending more than it received indicates exfiltration.
    // received < sent is normal for asymmetric traffic (downloads, streaming).
    let divergence = if sent > 0.0 && received > sent {
        (received - sent) / sent
    } else {
        0.0
    };

    if divergence > MAX_DIVERGENCE_RATIO {
        TrafficVerdict::SuspiciousExcess {
            divergence_ratio: divergence,
        }
    } else {
        TrafficVerdict::Normal
    }
}

/// Generate a traffic report from a bandwidth tracker for a specific session.
pub fn generate_report(
    session_id: u64,
    relay_node_id: &str,
    bytes_sent: u64,
    bytes_received: u64,
) -> TrafficReport {
    TrafficReport {
        session_id,
        relay_node_id: relay_node_id.to_string(),
        bytes_sent_to_relay: bytes_sent,
        bytes_received_from_relay: bytes_received,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_traffic_passes() {
        let report = TrafficReport {
            session_id: 1,
            relay_node_id: "relay-1".into(),
            bytes_sent_to_relay: 1_000_000,
            bytes_received_from_relay: 1_050_000, // 5% divergence — within 15%
        };
        assert_eq!(
            analyze_relay_traffic(Some(&report), None),
            TrafficVerdict::Normal
        );
    }

    #[test]
    fn suspicious_excess_detected() {
        let report = TrafficReport {
            session_id: 1,
            relay_node_id: "relay-1".into(),
            bytes_sent_to_relay: 1_000_000,
            bytes_received_from_relay: 1_300_000, // 30% divergence — suspicious
        };
        match analyze_relay_traffic(Some(&report), None) {
            TrafficVerdict::SuspiciousExcess { divergence_ratio } => {
                assert!(divergence_ratio > 0.15);
            }
            other => panic!("expected SuspiciousExcess, got {other:?}"),
        }
    }

    #[test]
    fn insufficient_data_below_threshold() {
        let report = TrafficReport {
            session_id: 1,
            relay_node_id: "relay-1".into(),
            bytes_sent_to_relay: 50_000, // below 100KB threshold
            bytes_received_from_relay: 80_000,
        };
        assert_eq!(
            analyze_relay_traffic(Some(&report), None),
            TrafficVerdict::InsufficientData
        );
    }

    #[test]
    fn combined_entry_exit_reports() {
        let entry = TrafficReport {
            session_id: 1,
            relay_node_id: "relay-1".into(),
            bytes_sent_to_relay: 500_000,
            bytes_received_from_relay: 520_000,
        };
        let exit = TrafficReport {
            session_id: 1,
            relay_node_id: "relay-1".into(),
            bytes_sent_to_relay: 500_000,
            bytes_received_from_relay: 510_000,
        };
        // Combined: sent 1M, received 1.03M → 3% divergence → normal
        assert_eq!(
            analyze_relay_traffic(Some(&entry), Some(&exit)),
            TrafficVerdict::Normal
        );
    }

    #[test]
    fn no_reports_is_insufficient() {
        assert_eq!(
            analyze_relay_traffic(None, None),
            TrafficVerdict::InsufficientData
        );
    }

    #[test]
    fn generate_report_works() {
        let r = generate_report(42, "relay-x", 1000, 2000);
        assert_eq!(r.session_id, 42);
        assert_eq!(r.relay_node_id, "relay-x");
        assert_eq!(r.bytes_sent_to_relay, 1000);
        assert_eq!(r.bytes_received_from_relay, 2000);
    }
}
