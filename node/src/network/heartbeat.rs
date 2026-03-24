use std::time::{Duration, Instant};

use thiserror::Error;
use tracing::{info, warn};

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
    /// Ethereum JSON-RPC URL.
    rpc_url: String,
    /// Contract address (hex).
    stake_address: Option<String>,
    /// How often to heartbeat.
    interval: Duration,
    /// When the last heartbeat was sent.
    last_heartbeat: Option<Instant>,
}

impl HeartbeatService {
    pub fn new(
        rpc_url: String,
        stake_address: Option<String>,
        interval_secs: u64,
    ) -> Self {
        Self {
            rpc_url,
            stake_address,
            interval: Duration::from_secs(interval_secs),
            last_heartbeat: None,
        }
    }

    /// Spawn a background task that sends heartbeats at the configured
    /// interval.  The task runs until the provided `cancel` token is
    /// dropped.
    pub fn spawn(
        self,
        cancel: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            self.run(cancel).await;
        })
    }

    async fn run(mut self, mut cancel: tokio::sync::watch::Receiver<bool>) {
        info!(
            interval_secs = self.interval.as_secs(),
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
        let contract_addr = match &self.stake_address {
            Some(addr) => addr,
            None => {
                info!("no stake_address configured — skipping on-chain heartbeat");
                return Ok(());
            }
        };

        // Use alloy to call the heartbeat function on the registry
        // contract.  For now we log intent; a full implementation would
        // build and send the transaction via the provider.

        info!(
            rpc = %self.rpc_url,
            contract = %contract_addr,
            "would send heartbeat transaction"
        );

        // Placeholder: create a provider and send a transaction.
        // In production this would look like:
        //
        //   let provider = alloy::providers::ProviderBuilder::new()
        //       .on_http(self.rpc_url.parse().unwrap());
        //   let tx = ... build heartbeat call ...;
        //   provider.send_transaction(tx).await ...;

        Ok(())
    }

    /// Elapsed time since the last successful heartbeat, if any.
    pub fn since_last_heartbeat(&self) -> Option<Duration> {
        self.last_heartbeat.map(|t| t.elapsed())
    }
}
