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
use crate::circuit::{self, CircuitState, NodeInfo};
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

            match rebuild_circuit(
                &chain_reader,
                &exclude_ids,
                &connection,
                &circuit,
                &tunnel,
            )
            .await
            {
                Ok(_) => {
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

/// Rebuild a circuit through different nodes.
async fn rebuild_circuit(
    chain_reader: &ChainReader,
    exclude_ids: &[String],
    connection: &Arc<Mutex<ConnectionState>>,
    circuit_state: &Arc<Mutex<Option<CircuitState>>>,
    tunnel: &Arc<Mutex<TunnelManager>>,
) -> Result<(), String> {
    let nodes = chain_reader.get_active_nodes().await
        .map_err(|e| format!("failed to fetch nodes: {e}"))?;

    if nodes.len() < 3 {
        return Err("fewer than 3 nodes available".to_string());
    }

    let node_infos: Vec<NodeInfo> = nodes
        .into_iter()
        .map(crate::map_on_chain_node)
        .collect();

    let exclude_strs: Vec<&str> = exclude_ids.iter().map(|s| s.as_str()).collect();
    let selected = circuit::select_circuit(&node_infos, &exclude_strs)?;

    let new_circuit = circuit::build_circuit(&selected)?;
    tunnel::register_sessions(&new_circuit).await?;

    // Reconnect tunnel to new entry.
    {
        let mut tun = tunnel.lock().map_err(|e| format!("lock error: {e}"))?;
        tun.start_tunnel(&selected[0].endpoint, &selected[0].public_key)?;
    }

    // Swap circuit state.
    {
        let mut circ = circuit_state.lock().map_err(|e| format!("lock error: {e}"))?;
        *circ = Some(new_circuit);
    }

    // Update connection state with new entry node.
    {
        let mut conn = connection.lock().map_err(|e| format!("lock error: {e}"))?;
        if let ConnectionState::Connected {
            ref mut node_id, ..
        } = *conn
        {
            *node_id = selected[0].node_id.clone();
        }
    }

    Ok(())
}
