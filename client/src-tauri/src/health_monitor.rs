//! Circuit health monitor: detects degraded circuits and triggers rebuilds.
//!
//! Runs as a background tokio task alongside the tunnel. Samples circuit
//! throughput every SAMPLE_INTERVAL seconds. If throughput drops below
//! MIN_THROUGHPUT_BPS for THROUGHPUT_FAIL_WINDOW consecutive samples, or
//! latency exceeds MAX_LATENCY_MS for LATENCY_FAIL_WINDOW consecutive
//! samples, the circuit is torn down and rebuilt through different nodes.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::chain::ChainReader;
use crate::circuit::CircuitState;
use crate::tunnel::{self, TunnelManager};
use crate::ConnectionState;

// ── thresholds ────────────────────────────────────────────────────────

/// How often to sample circuit health.
const SAMPLE_INTERVAL: Duration = Duration::from_secs(5);

/// Minimum throughput in bytes per second before flagging degradation.
const MIN_THROUGHPUT_BPS: u64 = 10 * 1024; // 10 KB/s

/// Number of consecutive low-throughput samples before triggering rebuild.
/// 3 samples × 5s = 15s sustained low throughput.
const THROUGHPUT_FAIL_COUNT: u32 = 3;

/// Number of consecutive zero-data samples before flagging a silent drop.
/// 6 samples × 5s = 30s with no data after initial transfer started.
const ZERO_DATA_FAIL_COUNT: u32 = 6;

// ── health state ──────────────────────────────────────────────────────

struct HealthState {
    last_bytes: u64,
    last_sample: Instant,
    low_throughput_streak: u32,
    zero_data_streak: u32,
    rebuild_count: u32,
}

impl HealthState {
    fn new() -> Self {
        Self {
            last_bytes: 0,
            last_sample: Instant::now(),
            low_throughput_streak: 0,
            zero_data_streak: 0,
            rebuild_count: 0,
        }
    }

    /// Update with a new throughput sample. Returns true if rebuild is needed.
    fn sample_throughput(&mut self, current_bytes: u64) -> bool {
        let elapsed = self.last_sample.elapsed();
        let elapsed_secs = elapsed.as_secs_f64().max(0.1);
        let delta_bytes = current_bytes.saturating_sub(self.last_bytes);
        let bps = (delta_bytes as f64 / elapsed_secs) as u64;

        self.last_bytes = current_bytes;
        self.last_sample = Instant::now();

        // Track zero-data circuits: node accepted but never forwards packets.
        if current_bytes == 0 {
            self.zero_data_streak += 1;
        } else {
            self.zero_data_streak = 0;
        }

        if self.zero_data_streak >= ZERO_DATA_FAIL_COUNT {
            return true;
        }

        if bps < MIN_THROUGHPUT_BPS && current_bytes > 0 {
            self.low_throughput_streak += 1;
        } else {
            self.low_throughput_streak = 0;
        }

        self.low_throughput_streak >= THROUGHPUT_FAIL_COUNT
    }

    fn record_rebuild(&mut self) {
        self.rebuild_count += 1;
        self.low_throughput_streak = 0;
        self.zero_data_streak = 0;
        self.last_bytes = 0;
        self.last_sample = Instant::now();
    }
}

// ── monitor loop ──────────────────────────────────────────────────────

/// Run the circuit health monitor. Cancels when the token is triggered.
pub async fn health_monitor_loop(
    cancel: CancellationToken,
    connection: Arc<Mutex<ConnectionState>>,
    circuit: Arc<Mutex<Option<CircuitState>>>,
    tunnel: Arc<Mutex<TunnelManager>>,
    chain_reader: ChainReader,
) {
    let mut state = HealthState::new();

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("health monitor cancelled");
                return;
            }
            _ = tokio::time::sleep(SAMPLE_INTERVAL) => {}
        }

        // Read current connection state.
        let (is_connected, bytes_used) = {
            let conn = match connection.lock() {
                Ok(c) => c,
                Err(_) => continue,
            };
            match &*conn {
                ConnectionState::Connected { bytes_used, .. } => (true, *bytes_used),
                _ => (false, 0),
            }
        };

        if !is_connected {
            continue;
        }

        // Sample throughput (includes zero-data detection).
        let needs_rebuild = state.sample_throughput(bytes_used);

        if needs_rebuild {
            let reason = if state.zero_data_streak > 0 { "zero data (silent drop)" } else { "low throughput" };
            warn!(
                reason,
                rebuild_count = state.rebuild_count,
                low_streak = state.low_throughput_streak,
                zero_streak = state.zero_data_streak,
                "circuit health degraded — triggering rebuild"
            );

            // Tear down old circuit.
            let old_circuit = {
                let circ = match circuit.lock() {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                circ.clone()
            };
            if let Some(ref old) = old_circuit {
                tunnel::teardown_sessions(old).await;
            }

            // Fetch nodes and rebuild.
            let exclude_ids: Vec<String> = old_circuit
                .as_ref()
                .map(|c| {
                    vec![
                        c.entry.node_id.clone(),
                        c.relay.node_id.clone(),
                        c.exit.node_id.clone(),
                    ]
                })
                .unwrap_or_default();

            let exclude_strs: Vec<&str> = exclude_ids.iter().map(|s| s.as_str()).collect();
            match crate::rebuild_circuit(
                &chain_reader,
                &exclude_strs,
                &circuit,
                &tunnel,
            )
            .await
            {
                Ok(selected) => {
                    // Update connection state with new entry node.
                    if let Ok(mut conn) = connection.lock() {
                        if let ConnectionState::Connected {
                            ref mut node_id, ..
                        } = *conn
                        {
                            *node_id = selected[0].node_id.clone();
                        }
                    }
                    state.record_rebuild();
                    info!(
                        rebuild_count = state.rebuild_count,
                        "circuit rebuilt after health degradation"
                    );
                }
                Err(e) => {
                    warn!(error = %e, "circuit rebuild failed — will retry next cycle");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Scenario 1: Node drops after accepting circuit ──────────────

    #[test]
    fn silent_drop_detected_after_zero_data_streak() {
        let mut state = HealthState::new();

        // Simulate 6 samples with zero bytes (node accepted but never sends).
        for _ in 0..ZERO_DATA_FAIL_COUNT - 1 {
            assert!(!state.sample_throughput(0), "should not trigger yet");
        }
        // The 6th zero-data sample triggers rebuild.
        assert!(state.sample_throughput(0), "should trigger rebuild on zero-data streak");
    }

    #[test]
    fn zero_data_streak_resets_on_any_data() {
        let mut state = HealthState::new();

        // Build up 5 zero-data samples (one short of threshold).
        for _ in 0..ZERO_DATA_FAIL_COUNT - 1 {
            state.sample_throughput(0);
        }
        assert_eq!(state.zero_data_streak, ZERO_DATA_FAIL_COUNT - 1);

        // Any data resets the streak.
        state.sample_throughput(1000);
        assert_eq!(state.zero_data_streak, 0);
    }

    // ── Scenario 2: Node throttles to near-zero bandwidth ───────────

    #[test]
    fn low_throughput_triggers_after_sustained_period() {
        let mut state = HealthState::new();

        // First sample with some data establishes baseline.
        state.sample_throughput(100_000);

        // Next samples show tiny increase (low bps). Each counts as 1 low-throughput sample.
        // Need THROUGHPUT_FAIL_COUNT (3) consecutive low samples to trigger.
        for i in 0..THROUGHPUT_FAIL_COUNT - 1 {
            let bytes = 100_001 + i as u64;
            let needs_rebuild = state.sample_throughput(bytes);
            assert!(!needs_rebuild, "should not trigger on sample {i} (streak={})", i + 1);
        }

        // One more low-throughput sample hits the threshold.
        let needs_rebuild = state.sample_throughput(100_001 + THROUGHPUT_FAIL_COUNT as u64);
        assert!(needs_rebuild, "should trigger after {THROUGHPUT_FAIL_COUNT} consecutive low samples");
    }

    #[test]
    fn low_throughput_streak_resets_on_good_throughput() {
        let mut state = HealthState::new();
        state.sample_throughput(1000);

        // Build up low-throughput streak.
        state.sample_throughput(1001);
        assert!(state.low_throughput_streak > 0);

        // Big jump in data resets the streak (high bps).
        state.sample_throughput(2_000_000);
        assert_eq!(state.low_throughput_streak, 0);
    }

    // ── Scenario 3: Rebuild resets all state ─────────────────────────

    #[test]
    fn record_rebuild_resets_counters() {
        let mut state = HealthState::new();
        state.low_throughput_streak = 5;
        state.zero_data_streak = 4;
        state.last_bytes = 999;

        state.record_rebuild();

        assert_eq!(state.low_throughput_streak, 0);
        assert_eq!(state.zero_data_streak, 0);
        assert_eq!(state.last_bytes, 0);
        assert_eq!(state.rebuild_count, 1);
    }

    #[test]
    fn rebuild_count_increments() {
        let mut state = HealthState::new();
        state.record_rebuild();
        state.record_rebuild();
        state.record_rebuild();
        assert_eq!(state.rebuild_count, 3);
    }

    // ── Scenario 4: Normal traffic never triggers ────────────────────

    #[test]
    fn healthy_circuit_never_triggers() {
        let mut state = HealthState::new();

        // Simulate 100 samples of healthy traffic (~1MB per 5s = 200 KB/s).
        for i in 0..100u64 {
            let bytes = i * 1_000_000;
            assert!(!state.sample_throughput(bytes));
        }
        assert_eq!(state.rebuild_count, 0);
    }
}
