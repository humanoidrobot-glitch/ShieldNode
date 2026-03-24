use std::collections::HashMap;
use std::time::Instant;

use serde::Serialize;

/// Per-session byte counters.
#[derive(Debug, Clone, Serialize)]
pub struct ByteCount {
    pub bytes_in: u64,
    pub bytes_out: u64,
    #[serde(skip)]
    pub last_updated: Option<Instant>,
}

/// Aggregates bandwidth metrics across all relay sessions.
#[derive(Debug, Default)]
pub struct BandwidthTracker {
    sessions: HashMap<u64, ByteCount>,
    total_in: u64,
    total_out: u64,
}

impl BandwidthTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_bytes(&mut self, session_id: u64, bytes_in: u64, bytes_out: u64) {
        self.total_in += bytes_in;
        self.total_out += bytes_out;

        let entry = self.sessions.entry(session_id).or_insert(ByteCount {
            bytes_in: 0,
            bytes_out: 0,
            last_updated: None,
        });
        entry.bytes_in += bytes_in;
        entry.bytes_out += bytes_out;
        entry.last_updated = Some(Instant::now());
    }

    pub fn get_session_bytes(&self, session_id: u64) -> Option<&ByteCount> {
        self.sessions.get(&session_id)
    }

    /// O(1) running totals instead of iterating all sessions.
    pub fn get_total_bytes(&self) -> (u64, u64) {
        (self.total_in, self.total_out)
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn sessions(&self) -> &HashMap<u64, ByteCount> {
        &self.sessions
    }

    /// Remove sessions not updated within `max_age`.
    pub fn evict_stale(&mut self, max_age: std::time::Duration) {
        let now = Instant::now();
        self.sessions.retain(|_, v| {
            v.last_updated
                .map(|t| now.duration_since(t) < max_age)
                .unwrap_or(false)
        });
    }
}
