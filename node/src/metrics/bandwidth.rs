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
    /// Unix-epoch seconds of last update (serialisable alternative).
    pub last_updated_secs_ago: Option<u64>,
}

impl ByteCount {
    fn new() -> Self {
        Self {
            bytes_in: 0,
            bytes_out: 0,
            last_updated: None,
            last_updated_secs_ago: None,
        }
    }

    fn touch(&mut self) {
        let now = Instant::now();
        self.last_updated_secs_ago =
            self.last_updated.map(|t| now.duration_since(t).as_secs());
        self.last_updated = Some(now);
    }
}

/// Aggregates bandwidth metrics across all relay sessions.
#[derive(Debug)]
pub struct BandwidthTracker {
    sessions: HashMap<u64, ByteCount>,
}

impl BandwidthTracker {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Record `bytes_in` received and `bytes_out` forwarded for a given
    /// session.
    pub fn record_bytes(
        &mut self,
        session_id: u64,
        bytes_in: u64,
        bytes_out: u64,
    ) {
        let entry = self
            .sessions
            .entry(session_id)
            .or_insert_with(ByteCount::new);
        entry.bytes_in += bytes_in;
        entry.bytes_out += bytes_out;
        entry.touch();
    }

    /// Retrieve counters for a single session.
    pub fn get_session_bytes(&self, session_id: u64) -> Option<&ByteCount> {
        self.sessions.get(&session_id)
    }

    /// Sum of all bytes across every session.
    pub fn get_total_bytes(&self) -> (u64, u64) {
        self.sessions.values().fold((0, 0), |(ai, ao), c| {
            (ai + c.bytes_in, ao + c.bytes_out)
        })
    }

    /// Number of tracked sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Snapshot of all sessions (cloned for serialisation).
    pub fn all_sessions(&self) -> HashMap<u64, ByteCount> {
        self.sessions.clone()
    }
}

impl Default for BandwidthTracker {
    fn default() -> Self {
        Self::new()
    }
}
