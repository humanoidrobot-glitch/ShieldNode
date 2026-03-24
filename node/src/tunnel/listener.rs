use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::metrics::bandwidth::BandwidthTracker;
use super::wireguard::WireguardTunnel;

/// Per-peer state tracked by the listener.
struct PeerState {
    tunnel: WireguardTunnel,
    session_id: u64,
    last_active: Instant,
}

/// How long a peer can be idle before being evicted.
const PEER_IDLE_TIMEOUT_SECS: u64 = 300; // 5 minutes
/// How often to check for stale peers.
const EVICTION_INTERVAL_SECS: u64 = 60;

/// UDP listener that accepts WireGuard handshakes and tunnels traffic.
///
/// In single-hop (Phase 1) mode, decapsulated packets are forwarded to
/// a raw socket or TUN device. For now, we log the inner packets
/// (proving the tunnel works end-to-end).
pub struct TunnelListener {
    socket: UdpSocket,
    private_key: [u8; 32],
    peers: HashMap<SocketAddr, PeerState>,
    next_session_id: u64,
    bandwidth: Arc<Mutex<BandwidthTracker>>,
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
            socket,
            private_key,
            peers: HashMap::new(),
            next_session_id: 1,
            bandwidth,
            exit_mode,
        })
    }

    /// Run the tunnel listener loop.
    pub async fn run(&mut self) -> anyhow::Result<()> {
        let mut recv_buf = vec![0u8; 65536];
        let mut send_buf = vec![0u8; 65536];
        let mut last_eviction = Instant::now();

        info!(exit_mode = self.exit_mode, "tunnel listener running");

        loop {
            let (n, peer_addr) = self.socket.recv_from(&mut recv_buf).await?;
            let packet = &recv_buf[..n];

            debug!(peer = %peer_addr, bytes = n, "received UDP packet");

            // Periodic stale peer eviction.
            if last_eviction.elapsed().as_secs() >= EVICTION_INTERVAL_SECS {
                self.evict_stale_peers();
                last_eviction = Instant::now();
            }

            let session_id = self.get_or_create_peer(peer_addr);

            let peer = self.peers.get_mut(&peer_addr).unwrap();
            peer.last_active = Instant::now();

            match peer.tunnel.handle_incoming(packet, &mut send_buf) {
                Ok(0) => {
                    // Keepalive or handshake — drive boringtun's state machine.
                    self.drive_handshake(peer_addr, &mut send_buf).await;
                }
                Ok(payload_len) => {
                    debug!(
                        peer = %peer_addr,
                        inner_len = payload_len,
                        "decapsulated inner packet"
                    );

                    {
                        let mut bw = self.bandwidth.lock().await;
                        bw.record_bytes(session_id, n as u64, payload_len as u64);
                    }

                    if self.exit_mode {
                        debug!("exit mode: would forward inner IP packet to internet");
                    } else {
                        debug!("relay mode: would forward to next hop");
                    }
                }
                Err(e) => {
                    debug!(peer = %peer_addr, error = %e, "decapsulation error (expected during handshake)");
                    self.drive_handshake(peer_addr, &mut send_buf).await;
                }
            }
        }
    }

    /// Get the session_id for a peer, creating a new tunnel if needed.
    fn get_or_create_peer(&mut self, addr: SocketAddr) -> u64 {
        use std::collections::hash_map::Entry;
        match self.peers.entry(addr) {
            Entry::Occupied(e) => e.get().session_id,
            Entry::Vacant(e) => {
                let session_id = self.next_session_id;
                self.next_session_id += 1;

                // For Phase 1, accept any incoming handshake. In production,
                // clients pre-register their public key via the session
                // opening flow.
                let tunnel = WireguardTunnel::new(
                    self.private_key,
                    [0u8; 32],
                    Some(addr),
                );

                info!(peer = %addr, session_id, "new peer tunnel created");

                e.insert(PeerState {
                    tunnel,
                    session_id,
                    last_active: Instant::now(),
                });
                session_id
            }
        }
    }

    /// Drive boringtun's handshake state machine — pump queued responses.
    async fn drive_handshake(&mut self, peer_addr: SocketAddr, buf: &mut [u8]) {
        let peer = match self.peers.get_mut(&peer_addr) {
            Some(p) => p,
            None => return,
        };

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

    /// Remove peers that haven't been active recently.
    fn evict_stale_peers(&mut self) {
        let timeout = std::time::Duration::from_secs(PEER_IDLE_TIMEOUT_SECS);
        let before = self.peers.len();
        self.peers.retain(|_, p| p.last_active.elapsed() < timeout);
        let evicted = before - self.peers.len();
        if evicted > 0 {
            info!(evicted, remaining = self.peers.len(), "evicted stale peers");
        }
    }
}
