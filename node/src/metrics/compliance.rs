//! Compliance snapshot serializer for ZK no-log proofs.
//!
//! Reads the node's `RelayService` session registry and `BandwidthTracker`
//! state, serializes them into the format expected by the ZK-VM compliance
//! guest (mode 2), and returns the witness data ready for proof generation.

use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::metrics::bandwidth::BandwidthTracker;
use crate::network::relay::SessionState;

/// Serialized compliance snapshot ready for ZK-VM witness input.
///
/// Fields match the guest's `env::read()` sequence in mode 2.
pub struct ComplianceWitness {
    pub node_id: [u8; 32],
    pub timestamp: u64,
    pub session_entries: Vec<SessionEntry>,
    pub bandwidth_entries: Vec<BandwidthEntry>,
}

pub struct SessionEntry {
    pub session_id: u64,
    /// SHA-256 of the session key (proves key exists without revealing it).
    pub key_hash: [u8; 32],
}

pub struct BandwidthEntry {
    pub session_id: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

impl ComplianceWitness {
    /// Build a compliance witness from live node state.
    ///
    /// `node_id` is the node's public key hash or on-chain address.
    /// `sessions` is a snapshot of the relay service's session map.
    /// `bandwidth` is a snapshot of the bandwidth tracker.
    pub fn from_state(
        node_id: [u8; 32],
        sessions: &HashMap<u64, SessionState>,
        bandwidth: &BandwidthTracker,
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_secs();

        let mut session_entries = Vec::with_capacity(sessions.len());
        for s in sessions.values() {
            session_entries.push(SessionEntry {
                session_id: s.session_id,
                key_hash: hash_key(&s.session_key),
            });
        }

        let mut bandwidth_entries = Vec::with_capacity(bandwidth.sessions().len());
        for (id, bc) in bandwidth.sessions() {
            bandwidth_entries.push(BandwidthEntry {
                session_id: *id,
                bytes_in: bc.bytes_in,
                bytes_out: bc.bytes_out,
            });
        }

        Self {
            node_id,
            timestamp,
            session_entries,
            bandwidth_entries,
        }
    }
}

/// SHA-256 hash of a session key (never reveal the key itself in the proof).
fn hash_key(key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(key);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::bandwidth::BandwidthTracker;
    use crate::network::relay::SessionState;

    #[test]
    fn witness_from_empty_state() {
        let sessions = HashMap::new();
        let bw = BandwidthTracker::new();
        let w = ComplianceWitness::from_state([0xAA; 32], &sessions, &bw);

        assert_eq!(w.node_id, [0xAA; 32]);
        assert!(w.session_entries.is_empty());
        assert!(w.bandwidth_entries.is_empty());
        assert!(w.timestamp > 0);
    }

    #[test]
    fn witness_captures_sessions_and_bandwidth() {
        let mut sessions = HashMap::new();
        sessions.insert(
            1,
            SessionState {
                session_id: 1,
                session_key: [0x42; 32],
                hop_index: 0,
                prev_hop: None,
            },
        );
        sessions.insert(
            2,
            SessionState {
                session_id: 2,
                session_key: [0x43; 32],
                hop_index: 1,
                prev_hop: None,
            },
        );

        let mut bw = BandwidthTracker::new();
        bw.record_bytes(1, 1000, 950);
        bw.record_bytes(2, 500, 480);

        let w = ComplianceWitness::from_state([0xBB; 32], &sessions, &bw);

        assert_eq!(w.session_entries.len(), 2);
        assert_eq!(w.bandwidth_entries.len(), 2);

        // Key hashes should not be zero (real keys are non-zero).
        for entry in &w.session_entries {
            assert_ne!(entry.key_hash, [0u8; 32]);
        }
    }

    #[test]
    fn key_hash_is_deterministic() {
        let key = [0x42u8; 32];
        let h1 = hash_key(&key);
        let h2 = hash_key(&key);
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_keys_produce_different_hashes() {
        let h1 = hash_key(&[0x42; 32]);
        let h2 = hash_key(&[0x43; 32]);
        assert_ne!(h1, h2);
    }
}
