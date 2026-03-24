use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tracing::{info, warn};

use crate::circuit::CircuitState;

pub struct TunnelManager {
    connected: bool,
    endpoint: Option<String>,
    /// Cached UDP socket for relay traffic (created once per session).
    pub relay_socket: Option<Arc<UdpSocket>>,
}

impl TunnelManager {
    pub fn new() -> Self {
        Self {
            connected: false,
            endpoint: None,
            relay_socket: None,
        }
    }

    pub fn start_tunnel(
        &mut self,
        node_endpoint: &str,
        _node_pubkey: &[u8; 32],
    ) -> Result<(), String> {
        if self.connected {
            warn!("tunnel already active -- tearing down before reconnecting");
            self.stop_tunnel()?;
        }
        info!(endpoint = node_endpoint, "starting tunnel (stub)");
        self.endpoint = Some(node_endpoint.to_string());
        self.connected = true;
        Ok(())
    }

    pub fn stop_tunnel(&mut self) -> Result<(), String> {
        if !self.connected {
            return Ok(());
        }
        info!(endpoint = self.endpoint.as_deref().unwrap_or("?"), "stopping tunnel");
        self.connected = false;
        self.endpoint = None;
        self.relay_socket = None;
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Get or create the cached relay socket.
    pub async fn get_relay_socket(&mut self) -> Result<Arc<UdpSocket>, String> {
        if let Some(ref sock) = self.relay_socket {
            return Ok(Arc::clone(sock));
        }
        let sock = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| format!("failed to bind relay socket: {e}"))?;
        let arc = Arc::new(sock);
        self.relay_socket = Some(Arc::clone(&arc));
        Ok(arc)
    }
}

impl Default for TunnelManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── relay protocol helpers ──────────────────────────────────────────────

fn relay_addr_for(endpoint: &str) -> Result<SocketAddr, String> {
    let addr: SocketAddr = endpoint
        .parse()
        .map_err(|e| format!("invalid endpoint '{endpoint}': {e}"))?;
    Ok(SocketAddr::new(addr.ip(), addr.port() + 1))
}

fn build_session_setup(session_id: u64, session_key: &[u8; 32], hop_index: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + 1 + 8 + 32 + 8);
    buf.extend_from_slice(&0u64.to_be_bytes());
    buf.push(0x01);
    buf.extend_from_slice(&session_id.to_be_bytes());
    buf.extend_from_slice(session_key);
    buf.extend_from_slice(&hop_index.to_le_bytes());
    buf
}

/// Register session keys with each hop in the circuit.
pub async fn register_sessions(circuit: &CircuitState) -> Result<(), String> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("failed to bind UDP socket: {e}"))?;

    for hop in [&circuit.entry, &circuit.relay, &circuit.exit] {
        let relay_addr = relay_addr_for(&hop.endpoint)?;
        let msg = build_session_setup(hop.session_id, &hop.session_key, hop.hop_index);

        info!(
            node_id = %hop.node_id,
            session_id = hop.session_id,
            hop_index = hop.hop_index,
            relay_addr = %relay_addr,
            "sending SESSION_SETUP"
        );

        socket.send_to(&msg, relay_addr).await
            .map_err(|e| format!("failed to send SESSION_SETUP to {relay_addr}: {e}"))?;

        let mut ack_buf = [0u8; 64];
        match tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut ack_buf)).await {
            Ok(Ok((n, from))) => {
                info!(node_id = %hop.node_id, bytes = n, from = %from, "received SESSION_SETUP ACK");
            }
            Ok(Err(e)) => {
                warn!(node_id = %hop.node_id, error = %e, "SESSION_SETUP ACK recv error (continuing)");
            }
            Err(_) => {
                warn!(node_id = %hop.node_id, relay_addr = %relay_addr, "SESSION_SETUP ACK timed out (continuing)");
            }
        }
    }

    info!("all session registrations sent");
    Ok(())
}

/// Send a framed relay packet using a cached socket.
pub async fn send_sphinx_packet(
    socket: &UdpSocket,
    entry_endpoint: &str,
    session_id: u64,
    packet_bytes: &[u8],
) -> Result<(), String> {
    let relay_addr = relay_addr_for(entry_endpoint)?;

    let mut frame = Vec::with_capacity(8 + packet_bytes.len());
    frame.extend_from_slice(&session_id.to_be_bytes());
    frame.extend_from_slice(packet_bytes);

    socket.send_to(&frame, relay_addr).await
        .map_err(|e| format!("failed to send relay packet to {relay_addr}: {e}"))?;

    Ok(())
}
