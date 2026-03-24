use std::sync::Arc;
use std::time::{Duration, Instant};

use thiserror::Error;
use tracing::{info, warn};

use super::chain::ChainService;

// ── errors ─────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum HeartbeatError {
    #[error("RPC call failed: {0}")]
    RpcFailed(String),
    #[error("contract interaction failed: {0}")]
    ContractFailed(String),
}

// ── service ────────────────────────────────────────────────────────────

/// Periodically posts an on-chain heartbeat proving liveness.
pub struct HeartbeatService {
    /// Optional chain service for real on-chain heartbeats.
    chain: Option<Arc<ChainService>>,
    /// How often to heartbeat.
    interval: Duration,
    /// When the last heartbeat was sent.
    last_heartbeat: Option<Instant>,
}

impl HeartbeatService {
    pub fn new(chain: Option<Arc<ChainService>>, interval_secs: u64) -> Self {
        Self {
            chain,
            interval: Duration::from_secs(interval_secs),
            last_heartbeat: None,
        }
    }

    /// Spawn a background task that sends heartbeats at the configured
    /// interval.  The task runs until the provided `cancel` token is
    /// dropped.
    pub fn spawn(self, cancel: tokio::sync::watch::Receiver<bool>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            self.run(cancel).await;
        })
    }

    async fn run(mut self, mut cancel: tokio::sync::watch::Receiver<bool>) {
        info!(
            interval_secs = self.interval.as_secs(),
            has_chain = self.chain.is_some(),
            "heartbeat service started"
        );

        let mut ticker = tokio::time::interval(self.interval);

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    match self.send_heartbeat().await {
                        Ok(()) => {
                            self.last_heartbeat = Some(Instant::now());
                            info!("heartbeat sent successfully");
                        }
                        Err(e) => {
                            warn!(%e, "heartbeat failed");
                        }
                    }
                }
                _ = cancel.changed() => {
                    info!("heartbeat service stopping");
                    break;
                }
            }
        }
    }

    /// Actually submit the heartbeat transaction.
    async fn send_heartbeat(&self) -> Result<(), HeartbeatError> {
        let chain = match &self.chain {
            Some(c) => c,
            None => {
                info!("no chain service configured — skipping on-chain heartbeat");
                return Ok(());
            }
        };

        let tx_hash = chain
            .heartbeat()
            .await
            .map_err(|e| HeartbeatError::ContractFailed(e.to_string()))?;

        info!(tx_hash = %tx_hash, "on-chain heartbeat confirmed");
        Ok(())
    }

    /// Elapsed time since the last successful heartbeat, if any.
    pub fn since_last_heartbeat(&self) -> Option<Duration> {
        self.last_heartbeat.map(|t| t.elapsed())
    }
}
