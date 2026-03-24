use tracing::{info, warn};

/// Manages the lifecycle of a WireGuard tunnel to a ShieldNode exit node.
///
/// In Phase 1 this is a stub — real WireGuard integration will be added later.
pub struct TunnelManager {
    connected: bool,
    endpoint: Option<String>,
}

impl TunnelManager {
    pub fn new() -> Self {
        Self {
            connected: false,
            endpoint: None,
        }
    }

    /// Start a WireGuard tunnel to the given node.
    ///
    /// `node_endpoint` — e.g. "203.0.113.10:51820"
    /// `node_pubkey`   — the 32-byte Curve25519 public key of the remote peer
    pub fn start_tunnel(
        &mut self,
        node_endpoint: &str,
        _node_pubkey: &[u8; 32],
    ) -> Result<(), String> {
        if self.connected {
            warn!("tunnel already active — tearing down before reconnecting");
            self.stop_tunnel()?;
        }

        info!(endpoint = node_endpoint, "starting WireGuard tunnel (stub)");

        // TODO: invoke platform-specific WireGuard userspace or kernel module
        self.endpoint = Some(node_endpoint.to_string());
        self.connected = true;

        info!("tunnel marked as connected (stub — no real tunnel created yet)");
        Ok(())
    }

    /// Tear down the active tunnel.
    pub fn stop_tunnel(&mut self) -> Result<(), String> {
        if !self.connected {
            info!("no active tunnel to stop");
            return Ok(());
        }

        info!(
            endpoint = self.endpoint.as_deref().unwrap_or("unknown"),
            "stopping WireGuard tunnel (stub)"
        );

        // TODO: tear down the real tunnel
        self.connected = false;
        self.endpoint = None;

        info!("tunnel stopped");
        Ok(())
    }

    /// Returns `true` when a tunnel is (believed to be) active.
    pub fn is_connected(&self) -> bool {
        self.connected
    }
}

impl Default for TunnelManager {
    fn default() -> Self {
        Self::new()
    }
}
