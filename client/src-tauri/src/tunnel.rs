use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use crate::circuit::CircuitState;

/// Manages the WireGuard tunnel to the entry node.
///
/// Uses boringtun for noise protocol handshakes and encryption.
/// Traffic flow: client → WireGuard encapsulate → Sphinx wrap → entry node.
pub struct TunnelManager {
    connected: bool,
    endpoint: Option<String>,
    /// boringtun tunnel state for WireGuard encryption/decryption.
    tunnel: Option<WgTunnel>,
    /// Cached UDP socket for relay traffic (created once per session).
    pub relay_socket: Option<Arc<UdpSocket>>,
    /// Running byte counter for bandwidth metering.
    pub bytes_sent: Arc<AtomicU64>,
    pub bytes_received: Arc<AtomicU64>,
}

/// WireGuard tunnel wrapper using boringtun.
struct WgTunnel {
    tunn: Tunn,
    local_public_key: [u8; 32],
}

// Tunn is Send but not Sync. WgTunnel is single-owner.
unsafe impl Send for WgTunnel {}

impl WgTunnel {
    fn new(peer_public_key: &[u8]) -> Result<Self, String> {
        if peer_public_key.len() != 32 {
            return Err(format!("peer key must be 32 bytes, got {}", peer_public_key.len()));
        }
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let local_public_key = x25519_dalek::PublicKey::from(&secret).to_bytes();

        let mut peer_key = [0u8; 32];
        peer_key.copy_from_slice(peer_public_key);
        let peer = x25519_dalek::PublicKey::from(peer_key);

        let index: u32 = rand::random();
        let tunn = Tunn::new(secret, peer, None, None, index, None);

        Ok(Self { tunn, local_public_key })
    }

    /// Encapsulate an outgoing IP packet into WireGuard.
    fn encapsulate<'a>(&mut self, src: &[u8], dst: &'a mut [u8]) -> Result<&'a [u8], String> {
        match self.tunn.encapsulate(src, dst) {
            TunnResult::WriteToNetwork(data) => Ok(data),
            TunnResult::Done => Err("encapsulate: nothing to write".to_string()),
            TunnResult::Err(e) => Err(format!("encapsulate failed: {e:?}")),
            _ => Err("encapsulate: unexpected result".to_string()),
        }
    }

    /// Decapsulate an incoming WireGuard message.
    fn decapsulate<'a>(&mut self, src: &[u8], dst: &'a mut [u8]) -> Result<DecapResult<'a>, String> {
        match self.tunn.decapsulate(None, src, dst) {
            TunnResult::Done => Ok(DecapResult::Handshake),
            TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                Ok(DecapResult::Data(data))
            }
            TunnResult::WriteToNetwork(data) => Ok(DecapResult::WriteBack(data)),
            TunnResult::Err(e) => Err(format!("decapsulate failed: {e:?}")),
        }
    }

    /// Drive the initial handshake, returning the handshake initiation message.
    fn handshake_init<'a>(&mut self, dst: &'a mut [u8]) -> Result<&'a [u8], String> {
        match self.tunn.format_handshake_initiation(dst, false) {
            TunnResult::WriteToNetwork(data) => Ok(data),
            TunnResult::Err(e) => Err(format!("handshake init failed: {e:?}")),
            _ => Err("handshake init: unexpected result".to_string()),
        }
    }
}

enum DecapResult<'a> {
    Handshake,
    Data(&'a [u8]),
    WriteBack(&'a [u8]),
}

/// Result of decapsulating an incoming WireGuard message.
pub enum DecapOutput<'a> {
    /// Decrypted IP packet — inject into TUN device.
    Data(&'a [u8]),
    /// Handshake response — MUST be sent back to the peer over UDP.
    WriteBack(&'a [u8]),
    /// Internal state update — no action required.
    Nothing,
}

impl TunnelManager {
    pub fn new() -> Self {
        Self {
            connected: false,
            endpoint: None,
            tunnel: None,
            relay_socket: None,
            bytes_sent: Arc::new(AtomicU64::new(0)),
            bytes_received: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Start a WireGuard tunnel to the entry node.
    ///
    /// Creates a boringtun Tunn with an ephemeral keypair and performs
    /// the noise handshake over UDP.
    pub fn start_tunnel(
        &mut self,
        node_endpoint: &str,
        node_pubkey: &[u8],
    ) -> Result<(), String> {
        if self.connected {
            warn!("tunnel already active — tearing down before reconnecting");
            self.stop_tunnel()?;
        }

        info!(endpoint = node_endpoint, "starting WireGuard tunnel");

        let wg = WgTunnel::new(node_pubkey)?;
        info!(
            local_pk = %hex::encode(&wg.local_public_key),
            "ephemeral WireGuard keypair generated"
        );

        self.tunnel = Some(wg);
        self.endpoint = Some(node_endpoint.to_string());
        self.connected = true;
        self.bytes_sent.store(0, Ordering::Relaxed);
        self.bytes_received.store(0, Ordering::Relaxed);

        Ok(())
    }

    /// Encapsulate an outgoing IP packet through the WireGuard tunnel.
    pub fn encapsulate(&mut self, plaintext: &[u8], buf: &mut [u8]) -> Result<usize, String> {
        let wg = self.tunnel.as_mut().ok_or("tunnel not active")?;
        let encrypted = wg.encapsulate(plaintext, buf)?;
        self.bytes_sent.fetch_add(plaintext.len() as u64, Ordering::Relaxed);
        Ok(encrypted.len())
    }

    /// Decapsulate an incoming WireGuard message.
    ///
    /// Returns:
    /// - `DecapOutput::Data(slice)` — decrypted IP packet for TUN injection
    /// - `DecapOutput::WriteBack(slice)` — handshake response that MUST be sent back over UDP
    /// - `DecapOutput::Nothing` — handshake state update, no action needed
    pub fn decapsulate<'a>(&mut self, ciphertext: &[u8], buf: &'a mut [u8]) -> Result<DecapOutput<'a>, String> {
        let wg = self.tunnel.as_mut().ok_or("tunnel not active")?;
        match wg.decapsulate(ciphertext, buf)? {
            DecapResult::Data(data) => {
                self.bytes_received.fetch_add(data.len() as u64, Ordering::Relaxed);
                Ok(DecapOutput::Data(data))
            }
            DecapResult::Handshake => Ok(DecapOutput::Nothing),
            DecapResult::WriteBack(data) => Ok(DecapOutput::WriteBack(data)),
        }
    }

    /// Generate the WireGuard handshake initiation message.
    pub fn handshake_init(&mut self, buf: &mut [u8]) -> Result<usize, String> {
        let wg = self.tunnel.as_mut().ok_or("tunnel not active")?;
        let data = wg.handshake_init(buf)?;
        Ok(data.len())
    }

    pub fn stop_tunnel(&mut self) -> Result<(), String> {
        if !self.connected {
            return Ok(());
        }
        info!(endpoint = self.endpoint.as_deref().unwrap_or("?"), "stopping WireGuard tunnel");
        self.connected = false;
        self.endpoint = None;
        self.tunnel = None;
        self.relay_socket = None;
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Get total bytes sent through the tunnel.
    pub fn total_bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Get total bytes received through the tunnel.
    pub fn total_bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
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

/// Send SESSION_TEARDOWN (0x02) to all hops in the circuit concurrently.
///
/// Fire-and-forget — best effort, errors are logged but not propagated.
pub async fn teardown_sessions(circuit: &CircuitState) {
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "failed to bind socket for SESSION_TEARDOWN");
            return;
        }
    };

    let send_teardown = |hop: &crate::circuit::CircuitHop| {
        let relay_addr = relay_addr_for(&hop.endpoint);
        let node_id = hop.node_id.clone();
        let session_id = hop.session_id;
        let socket = &socket;
        async move {
            let addr = match relay_addr {
                Ok(a) => a,
                Err(e) => {
                    warn!(node_id = %node_id, error = %e, "skipping teardown for bad endpoint");
                    return;
                }
            };
            let mut msg = Vec::with_capacity(8 + 1 + 8);
            msg.extend_from_slice(&0u64.to_be_bytes());
            msg.push(0x02);
            msg.extend_from_slice(&session_id.to_be_bytes());

            if let Err(e) = socket.send_to(&msg, addr).await {
                warn!(node_id = %node_id, error = %e, "failed to send SESSION_TEARDOWN");
            } else {
                info!(node_id = %node_id, session_id, "sent SESSION_TEARDOWN");
            }
        }
    };

    tokio::join!(
        send_teardown(&circuit.entry),
        send_teardown(&circuit.relay),
        send_teardown(&circuit.exit),
    );
}

/// Request the exit node to co-sign a bandwidth receipt.
///
/// Sends a RECEIPT_SIGN control message (0x03) to the exit node's relay port
/// and waits for a 65-byte co-signature response.
///
/// Wire format sent:
/// ```text
/// [session_id=0 (8 bytes)][0x03][8-byte session_id BE][8-byte cumulative_bytes BE][8-byte timestamp BE][65-byte client_sig]
/// ```
///
/// Expected response: 65 bytes (node signature) on success, or 1 byte (error code) on failure.
/// Request the exit node's EIP-712 co-signature on a bandwidth receipt.
///
/// After receiving the 65-byte signature, verifies it by recovering the
/// secp256k1 public key and checking that the derived address matches the
/// expected exit node operator.
pub async fn request_receipt_cosign(
    exit_endpoint: &str,
    session_id: u64,
    cumulative_bytes: u64,
    timestamp: u64,
    client_signature: &[u8], // 65 bytes
    digest: &[u8; 32],              // EIP-712 receipt digest
    expected_operator: &str,         // hex address of exit node operator
) -> Result<Vec<u8>, String> {
    if client_signature.len() != 65 {
        return Err(format!(
            "client_signature must be 65 bytes, got {}",
            client_signature.len()
        ));
    }

    let relay_addr = relay_addr_for(exit_endpoint)?;

    // Build the RECEIPT_SIGN control message.
    let mut msg = Vec::with_capacity(8 + 1 + 8 + 8 + 8 + 65);
    msg.extend_from_slice(&0u64.to_be_bytes()); // session_id = 0 (control)
    msg.push(0x03); // RECEIPT_SIGN command
    msg.extend_from_slice(&session_id.to_be_bytes());
    msg.extend_from_slice(&cumulative_bytes.to_be_bytes());
    msg.extend_from_slice(&timestamp.to_be_bytes());
    msg.extend_from_slice(client_signature);

    info!(
        exit_endpoint,
        relay_addr = %relay_addr,
        session_id,
        cumulative_bytes,
        timestamp,
        msg_len = msg.len(),
        "sending RECEIPT_SIGN to exit node"
    );

    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("failed to bind UDP socket for receipt cosign: {e}"))?;

    socket
        .send_to(&msg, relay_addr)
        .await
        .map_err(|e| format!("failed to send RECEIPT_SIGN to {relay_addr}: {e}"))?;

    // Wait for the node's co-signature response.
    let mut resp_buf = [0u8; 128];
    match tokio::time::timeout(Duration::from_secs(10), socket.recv_from(&mut resp_buf)).await {
        Ok(Ok((n, from))) => {
            if n == 65 {
                let node_sig = resp_buf[..65].to_vec();

                // Verify the co-signature: recover pubkey → derive address → match.
                let recovered_addr = crate::zk_witness::recover_address(&node_sig, digest)?;
                let expected = expected_operator.strip_prefix("0x")
                    .unwrap_or(expected_operator)
                    .to_lowercase();
                if recovered_addr.to_lowercase() != expected {
                    return Err(format!(
                        "node co-signature address mismatch: recovered {recovered_addr}, expected {expected}"
                    ));
                }

                info!(
                    from = %from,
                    recovered_addr,
                    "verified 65-byte node co-signature"
                );
                Ok(node_sig)
            } else if n == 1 {
                Err(format!(
                    "exit node rejected receipt co-sign with error code: 0x{:02x}",
                    resp_buf[0]
                ))
            } else {
                Err(format!(
                    "unexpected response size from exit node: {n} bytes (expected 65)"
                ))
            }
        }
        Ok(Err(e)) => Err(format!("failed to receive RECEIPT_SIGN response: {e}")),
        Err(_) => Err("RECEIPT_SIGN response timed out (10s)".to_string()),
    }
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
