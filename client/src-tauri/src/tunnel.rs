use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tracing::{info, warn};

use crate::circuit::CircuitState;

/// Manages session registration and packet sending over the relay protocol.
///
/// Control messages (session setup) use `session_id = 0`:
/// ```text
/// [session_id=0 (8 bytes)][0x01][8-byte real_session_id][32-byte session_key][8-byte hop_index LE]
/// ```
///
/// Traffic messages:
/// ```text
/// [8-byte session_id][SphinxPacket bytes]
/// ```
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

    /// Start a WireGuard tunnel to the given node (stub retained for
    /// backward compatibility with single-hop mode).
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

        info!("tunnel marked as connected");
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
            "stopping tunnel"
        );

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

// ── relay protocol helpers ──────────────────────────────────────────────

/// Compute the relay port address for a given WireGuard endpoint.
///
/// The relay port is the WireGuard port + 1 (e.g., 51820 -> 51821).
fn relay_addr_for(endpoint: &str) -> Result<SocketAddr, String> {
    let addr: SocketAddr = endpoint
        .parse()
        .map_err(|e| format!("invalid endpoint '{endpoint}': {e}"))?;
    let relay_port = addr.port() + 1;
    Ok(SocketAddr::new(addr.ip(), relay_port))
}

/// Build a SESSION_SETUP control message.
///
/// Wire format:
/// ```text
/// [session_id=0 (8 bytes)][0x01 (1 byte)][8-byte real_session_id BE]
/// [32-byte session_key][8-byte hop_index LE]
/// ```
fn build_session_setup(session_id: u64, session_key: &[u8; 32], hop_index: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + 1 + 8 + 32 + 8);
    buf.extend_from_slice(&0u64.to_be_bytes()); // session_id = 0 (control)
    buf.push(0x01); // SESSION_SETUP opcode
    buf.extend_from_slice(&session_id.to_be_bytes());
    buf.extend_from_slice(session_key);
    buf.extend_from_slice(&hop_index.to_le_bytes());
    buf
}

/// Register session keys with each hop in the circuit.
///
/// For each hop, sends a SESSION_SETUP control message to the node's relay
/// port (endpoint IP, WireGuard port + 1) and waits for an ACK.
pub async fn register_sessions(circuit: &CircuitState) -> Result<(), String> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("failed to bind UDP socket: {e}"))?;

    let hops = [&circuit.entry, &circuit.relay, &circuit.exit];

    for hop in hops {
        let relay_addr = relay_addr_for(&hop.endpoint)?;
        let msg = build_session_setup(hop.session_id, &hop.session_key, hop.hop_index);

        info!(
            node_id = %hop.node_id,
            session_id = hop.session_id,
            hop_index = hop.hop_index,
            relay_addr = %relay_addr,
            "sending SESSION_SETUP"
        );

        socket
            .send_to(&msg, relay_addr)
            .await
            .map_err(|e| format!("failed to send SESSION_SETUP to {relay_addr}: {e}"))?;

        // Wait for ACK (with timeout).
        let mut ack_buf = [0u8; 64];
        let ack_result = tokio::time::timeout(
            Duration::from_secs(5),
            socket.recv_from(&mut ack_buf),
        )
        .await;

        match ack_result {
            Ok(Ok((n, from))) => {
                info!(
                    node_id = %hop.node_id,
                    bytes = n,
                    from = %from,
                    "received SESSION_SETUP ACK"
                );
            }
            Ok(Err(e)) => {
                warn!(
                    node_id = %hop.node_id,
                    error = %e,
                    "SESSION_SETUP ACK recv error (continuing)"
                );
            }
            Err(_) => {
                warn!(
                    node_id = %hop.node_id,
                    relay_addr = %relay_addr,
                    "SESSION_SETUP ACK timed out after 5s (continuing)"
                );
            }
        }
    }

    info!("all session registrations sent");
    Ok(())
}

/// Send a framed relay packet to the entry node's relay port.
///
/// Wire format: `[8-byte session_id BE][SphinxPacket bytes]`
pub async fn send_sphinx_packet(
    entry_endpoint: &str,
    session_id: u64,
    packet_bytes: &[u8],
) -> Result<(), String> {
    let relay_addr = relay_addr_for(entry_endpoint)?;

    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("failed to bind UDP socket: {e}"))?;

    let mut frame = Vec::with_capacity(8 + packet_bytes.len());
    frame.extend_from_slice(&session_id.to_be_bytes());
    frame.extend_from_slice(packet_bytes);

    socket
        .send_to(&frame, relay_addr)
        .await
        .map_err(|e| format!("failed to send relay packet to {relay_addr}: {e}"))?;

    info!(
        session_id,
        relay_addr = %relay_addr,
        frame_len = frame.len(),
        "sent relay packet to entry node"
    );

    Ok(())
}
