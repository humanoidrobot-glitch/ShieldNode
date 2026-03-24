use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::metrics::bandwidth::BandwidthTracker;
use super::wireguard::WireguardTunnel;

/// Per-peer state tracked by the listener.
struct PeerState {
    tunnel: WireguardTunnel,
    /// Monotonically increasing session id for bandwidth tracking.
    session_id: u64,
}

/// UDP listener that accepts WireGuard handshakes and tunnels traffic.
///
/// In single-hop (Phase 1) mode, decapsulated packets are forwarded to
/// a raw socket or TUN device. For now, we log the inner packets and
/// echo-respond (proving the tunnel works end-to-end).
pub struct TunnelListener {
    /// The UDP socket bound to the WireGuard listen port.
    socket: Arc<UdpSocket>,
    /// Node's static private key (X25519, 32 bytes).
    private_key: [u8; 32],
    /// Connected peers keyed by remote address.
    peers: HashMap<SocketAddr, PeerState>,
    /// Next session id to assign.
    next_session_id: u64,
    /// Shared bandwidth tracker.
    bandwidth: Arc<Mutex<BandwidthTracker>>,
    /// Whether this node acts as an exit (forwards to internet) or relay-only.
    exit_mode: bool,
}

impl TunnelListener {
    pub async fn bind(
        listen_port: u16,
        private_key: [u8; 32],
        bandwidth: Arc<Mutex<BandwidthTracker>>,
        exit_mode: bool,
    ) -> anyhow::Result<Self> {
        let addr: SocketAddr = format!("0.0.0.0:{listen_port}").parse()?;
        let socket = UdpSocket::bind(addr).await?;
        info!(%addr, "WireGuard UDP listener bound");

        Ok(Self {
            socket: Arc::new(socket),
            private_key,
            peers: HashMap::new(),
            next_session_id: 1,
            bandwidth,
            exit_mode,
        })
    }

    /// Run the tunnel listener loop. Receives UDP datagrams, routes them
    /// through boringtun, and handles the results.
    pub async fn run(&mut self) -> anyhow::Result<()> {
        let mut recv_buf = vec![0u8; 65536];
        let mut send_buf = vec![0u8; 65536];

        info!(
            exit_mode = self.exit_mode,
            "tunnel listener running"
        );

        loop {
            let (n, peer_addr) = self.socket.recv_from(&mut recv_buf).await?;
            let packet = &recv_buf[..n];

            debug!(peer = %peer_addr, bytes = n, "received UDP packet");

            // Get or create tunnel state for this peer.
            let peer = self.get_or_create_peer(peer_addr);
            let session_id = peer.session_id;

            // Decapsulate the WireGuard packet.
            match peer.tunnel.handle_incoming(packet, &mut send_buf) {
                Ok(0) => {
                    // No data to forward (e.g., keepalive). But boringtun
                    // may have produced a handshake response in send_buf
                    // via a subsequent call — drive the state machine.
                    self.drive_handshake(peer_addr, &mut send_buf).await;
                }
                Ok(payload_len) => {
                    let inner = &send_buf[..payload_len];
                    debug!(
                        peer = %peer_addr,
                        inner_len = payload_len,
                        "decapsulated inner packet"
                    );

                    // Record bandwidth.
                    {
                        let mut bw = self.bandwidth.lock().await;
                        bw.record_bytes(session_id, n as u64, payload_len as u64);
                    }

                    if self.exit_mode {
                        // Phase 1: log the inner packet. Full exit forwarding
                        // (TUN device / raw socket) is a later step.
                        debug!(
                            dst = ?&inner[..inner.len().min(20)],
                            "exit mode: would forward inner IP packet to internet"
                        );
                    } else {
                        debug!("relay mode: would forward to next hop");
                    }
                }
                Err(e) => {
                    debug!(peer = %peer_addr, error = %e, "decapsulation error (expected during handshake)");
                    // During initial handshake, decapsulate may fail — that's
                    // normal. boringtun's state machine handles retries.
                    self.drive_handshake(peer_addr, &mut send_buf).await;
                }
            }
        }
    }

    /// Get existing peer state or create a new tunnel for an unknown peer.
    fn get_or_create_peer(&mut self, addr: SocketAddr) -> &mut PeerState {
        if !self.peers.contains_key(&addr) {
            let session_id = self.next_session_id;
            self.next_session_id += 1;

            // For a fresh peer we don't know their public key yet —
            // boringtun handles the handshake. We use a placeholder
            // peer key (all zeros); boringtun will negotiate the real
            // key during the Noise IK handshake.
            //
            // In production, the client would pre-register its public key
            // via the session opening flow, and we'd look it up here.
            // For Phase 1, accept any incoming handshake.
            let tunnel = WireguardTunnel::new(
                self.private_key,
                [0u8; 32], // placeholder — handshake will establish real keys
                Some(addr),
            );

            info!(peer = %addr, session_id, "new peer tunnel created");

            self.peers.insert(addr, PeerState {
                tunnel,
                session_id,
            });
        }

        self.peers.get_mut(&addr).unwrap()
    }

    /// Drive boringtun's handshake state machine by calling
    /// `encapsulate(&[], ...)` repeatedly until there's nothing more to send.
    async fn drive_handshake(&mut self, peer_addr: SocketAddr, buf: &mut [u8]) {
        let peer = match self.peers.get_mut(&peer_addr) {
            Some(p) => p,
            None => return,
        };

        // boringtun may have queued handshake responses. Pump them out.
        loop {
            match peer.tunnel.handle_outgoing(&[], buf) {
                Ok(data) if !data.is_empty() => {
                    if let Err(e) = self.socket.send_to(data, peer_addr).await {
                        warn!(peer = %peer_addr, error = %e, "failed to send handshake response");
                    } else {
                        debug!(peer = %peer_addr, bytes = data.len(), "sent handshake response");
                    }
                }
                _ => break,
            }
        }
    }

    /// Number of currently connected peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }
}
