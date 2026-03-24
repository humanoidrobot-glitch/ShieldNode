use std::collections::HashMap;
use std::sync::Arc;

use thiserror::Error;
use tokio::sync::Mutex;
use tracing::{info, warn};
use zeroize::Zeroize;

use crate::crypto::sphinx::{SphinxError, SphinxPacket};
use crate::metrics::bandwidth::BandwidthTracker;

// ── errors ─────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("unknown session: {0}")]
    UnknownSession(u64),
    #[error("sphinx error: {0}")]
    Sphinx(#[from] SphinxError),
    #[error("send failed: {0}")]
    SendFailed(String),
}

// ── session state ──────────────────────────────────────────────────────

/// Per-session relay state kept by this node.
///
/// `session_key` is zeroed from memory when the session is dropped.
#[derive(Debug, Clone)]
pub struct SessionState {
    pub session_id: u64,
    pub session_key: [u8; 32],
    pub hop_index: u64,
}

impl Drop for SessionState {
    fn drop(&mut self) {
        self.session_key.zeroize();
    }
}

// ── relay service ──────────────────────────────────────────────────────

/// Handles packet forwarding between hops.
///
/// The forwarding path is kept as deterministic and side-effect-free as
/// possible so that it can be proven inside a ZK circuit in a future
/// release.
pub struct RelayService {
    sessions: HashMap<u64, SessionState>,
    bandwidth: Arc<Mutex<BandwidthTracker>>,
}

impl RelayService {
    pub fn new(bandwidth: Arc<Mutex<BandwidthTracker>>) -> Self {
        Self {
            sessions: HashMap::new(),
            bandwidth,
        }
    }

    /// Register a new relay session. Returns false if the session_id
    /// already exists (collision).
    pub fn add_session(&mut self, state: SessionState) -> bool {
        use std::collections::hash_map::Entry;
        match self.sessions.entry(state.session_id) {
            Entry::Occupied(_) => {
                warn!(session_id = state.session_id, "session ID collision — rejecting duplicate");
                false
            }
            Entry::Vacant(e) => {
                info!(session_id = state.session_id, "relay session registered");
                e.insert(state);
                true
            }
        }
    }

    /// Remove a relay session.
    pub fn remove_session(&mut self, session_id: u64) {
        self.sessions.remove(&session_id);
    }

    /// Forward a single packet for `session_id`.
    ///
    /// 1. Look up the session's symmetric key.
    /// 2. Peel one Sphinx layer.
    /// 3. Record bandwidth.
    /// 4. Return `(next_hop_public_key, inner_packet)` for the caller to
    ///    actually transmit.
    pub async fn forward_packet(
        &self,
        session_id: u64,
        packet: &SphinxPacket,
    ) -> Result<([u8; 32], SphinxPacket), RelayError> {
        let session = self
            .sessions
            .get(&session_id)
            .ok_or(RelayError::UnknownSession(session_id))?;

        let incoming_size = packet.payload.len() as u64;

        // Pure, deterministic peel — candidate for ZK proving.
        let (next_hop, inner) = packet.peel_layer(&session.session_key, session.hop_index)?;

        let outgoing_size = inner.payload.len() as u64;

        // Record bandwidth (async, but does not affect the forwarding
        // result).
        {
            let mut bw = self.bandwidth.lock().await;
            bw.record_bytes(session_id, incoming_size, outgoing_size);
        }

        info!(session_id, incoming_size, outgoing_size, "packet forwarded");

        Ok((next_hop, inner))
    }

    /// Check whether a session with the given ID exists.
    pub fn has_session(&self, session_id: u64) -> bool {
        self.sessions.contains_key(&session_id)
    }

    /// Number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}
