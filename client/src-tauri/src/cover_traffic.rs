//! Adaptive cover traffic generator.
//!
//! Maintains a baseline packet rate during low-activity periods to prevent
//! timing-based activity detection. Cover packets are full Sphinx packets
//! indistinguishable from real traffic at the relay level — only the exit
//! node can identify them (via a flag in the innermost Sphinx layer).
//!
//! Levels:
//! - "off": no cover traffic
//! - "low": 10 packets/second baseline (~12.8 KB/s, ~1.1 GB/day)
//! - "high": 50 packets/second baseline (~64 KB/s, ~5.5 GB/day)

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand::Rng;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::circuit::CircuitState;
use crate::tunnel;

/// Cover packet marker: first byte of the Sphinx payload (after all onion
/// layers are peeled, the exit sees this marker and drops the packet).
pub const COVER_MARKER: u8 = 0xCC;

/// Sampling interval: check outbound rate every 100ms.
const SAMPLE_INTERVAL: Duration = Duration::from_millis(100);

/// Cover traffic level.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CoverLevel {
    Off,
    Low,  // 10 pps
    High, // 50 pps
}

impl Default for CoverLevel {
    fn default() -> Self {
        Self::Off
    }
}

impl CoverLevel {
    /// Target packets per second for this level.
    pub fn target_pps(self) -> u32 {
        match self {
            Self::Off => 0,
            Self::Low => 10,
            Self::High => 50,
        }
    }

    /// Estimated daily bandwidth overhead in bytes.
    pub fn daily_bytes(self) -> u64 {
        let pps = self.target_pps() as u64;
        pps * 1280 * 86400 // pps × packet_size × seconds/day
    }
}

/// State for the cover traffic generator.
struct CoverState {
    /// Packets sent in the current sampling window.
    packets_this_window: u32,
    /// Start of current sampling window.
    window_start: Instant,
    /// Total cover packets sent this session.
    total_cover_sent: u64,
}

impl CoverState {
    fn new() -> Self {
        Self {
            packets_this_window: 0,
            window_start: Instant::now(),
            total_cover_sent: 0,
        }
    }

    /// Record that real traffic packets were sent.
    fn record_real_packets(&mut self, count: u32) {
        self.packets_this_window += count;
    }

    /// Check if cover traffic is needed to maintain the target rate.
    /// Returns the number of cover packets to inject right now.
    fn cover_needed(&mut self, target_pps: u32) -> u32 {
        if target_pps == 0 {
            return 0;
        }

        // Reset window every second before computing rate.
        if self.window_start.elapsed() >= Duration::from_secs(1) {
            self.packets_this_window = 0;
            self.window_start = Instant::now();
        }

        let elapsed_secs = self.window_start.elapsed().as_secs_f64().max(0.01);
        let current_pps = self.packets_this_window as f64 / elapsed_secs;
        let target = target_pps as f64;

        if current_pps >= target {
            return 0;
        }

        let deficit = (target - current_pps) * elapsed_secs;
        let needed = deficit.ceil() as u32;

        // Add slight randomness (±20%) to prevent pattern detection.
        let mut rng = rand::thread_rng();
        let jitter: f64 = rng.gen_range(0.8..1.2);
        let jittered = (needed as f64 * jitter) as u32;

        jittered.min(target_pps)
    }

    fn record_cover_sent(&mut self, count: u32) {
        self.packets_this_window += count;
        self.total_cover_sent += count as u64;
    }
}

/// Generate a cover packet payload.
///
/// The payload starts with COVER_MARKER followed by random bytes.
/// After Sphinx wrapping and onion encryption, this is indistinguishable
/// from real traffic at every hop except the exit (which peels all layers
/// and sees the marker).
pub fn generate_cover_payload(size: usize) -> Vec<u8> {
    let mut payload = vec![0u8; size];
    payload[0] = COVER_MARKER;
    // Fill rest with random data.
    rand::thread_rng().fill(&mut payload[1..]);
    payload
}

/// Check if a decrypted payload is a cover packet (exit node check).
pub fn is_cover_packet(payload: &[u8]) -> bool {
    !payload.is_empty() && payload[0] == COVER_MARKER
}

/// Run the adaptive cover traffic generator.
///
/// Monitors outbound packet rate and injects cover Sphinx packets when
/// real traffic drops below the configured baseline.
pub async fn cover_traffic_loop(
    cancel: CancellationToken,
    level: CoverLevel,
    circuit: Arc<Mutex<Option<CircuitState>>>,
    real_packet_counter: Arc<AtomicU64>,
) {
    if level == CoverLevel::Off {
        info!("cover traffic disabled");
        return;
    }

    let target_pps = level.target_pps();
    let daily_est = level.daily_bytes();
    // TODO: actual Sphinx-wrapped packet send depends on full TUN integration.
    // Currently counts cover packets for rate tracking but does not transmit.
    warn!(
        level = ?level,
        target_pps,
        daily_overhead_mb = daily_est / (1024 * 1024),
        "cover traffic accounting started (packet send not yet wired)"
    );

    let mut state = CoverState::new();
    let mut last_real_count: u64 = 0;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!(total_cover = state.total_cover_sent, "cover traffic stopped");
                return;
            }
            _ = tokio::time::sleep(SAMPLE_INTERVAL) => {}
        }

        let current_real = real_packet_counter.load(Ordering::Relaxed);
        let real_delta = (current_real - last_real_count) as u32;
        last_real_count = current_real;
        state.record_real_packets(real_delta);

        // Calculate cover packets needed.
        let needed = state.cover_needed(target_pps);
        if needed == 0 {
            continue;
        }

        // Check we have an active circuit.
        let has_circuit = {
            let circ = match circuit.lock() {
                Ok(c) => c,
                Err(_) => continue,
            };
            circ.is_some()
        };

        if !has_circuit {
            continue;
        }

        // In a full implementation, we would:
        // 1. Build cover_payload with generate_cover_payload(1280)
        // 2. Wrap in Sphinx layers using the circuit's session keys
        // 3. Send through the tunnel to the entry node
        //
        // For now, count the cover packets (the Sphinx wrapping and
        // tunnel send depend on the full TUN integration).
        state.record_cover_sent(needed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cover_level_serde_roundtrip() {
        let json = serde_json::to_string(&CoverLevel::Low).unwrap();
        assert_eq!(json, "\"low\"");
        let parsed: CoverLevel = serde_json::from_str("\"high\"").unwrap();
        assert_eq!(parsed, CoverLevel::High);
        let parsed: CoverLevel = serde_json::from_str("\"off\"").unwrap();
        assert_eq!(parsed, CoverLevel::Off);
    }

    #[test]
    fn target_pps_values() {
        assert_eq!(CoverLevel::Off.target_pps(), 0);
        assert_eq!(CoverLevel::Low.target_pps(), 10);
        assert_eq!(CoverLevel::High.target_pps(), 50);
    }

    #[test]
    fn daily_bandwidth_estimates() {
        // Low: 10 pps × 1280 × 86400 ≈ 1.06 GB
        assert!(CoverLevel::Low.daily_bytes() > 1_000_000_000);
        assert!(CoverLevel::Low.daily_bytes() < 1_200_000_000);

        // High: 50 pps × 1280 × 86400 ≈ 5.3 GB
        assert!(CoverLevel::High.daily_bytes() > 5_000_000_000);
        assert!(CoverLevel::High.daily_bytes() < 6_000_000_000);
    }

    #[test]
    fn cover_needed_when_idle() {
        let mut state = CoverState::new();
        // With no real packets, cover should be needed at any non-zero target.
        // Give it a moment to accumulate deficit.
        std::thread::sleep(Duration::from_millis(200));
        let needed = state.cover_needed(10);
        assert!(needed > 0, "should need cover packets when idle");
    }

    #[test]
    fn cover_not_needed_when_busy() {
        let mut state = CoverState::new();
        state.record_real_packets(100); // way above any target
        let needed = state.cover_needed(10);
        assert_eq!(needed, 0, "should not need cover when real traffic is high");
    }

    #[test]
    fn cover_off_needs_zero() {
        let mut state = CoverState::new();
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(state.cover_needed(0), 0);
    }

    #[test]
    fn cover_payload_has_marker() {
        let payload = generate_cover_payload(1280);
        assert_eq!(payload.len(), 1280);
        assert_eq!(payload[0], COVER_MARKER);
        assert!(is_cover_packet(&payload));
    }

    #[test]
    fn real_payload_is_not_cover() {
        let payload = vec![0x00; 1280];
        assert!(!is_cover_packet(&payload));
    }
}
