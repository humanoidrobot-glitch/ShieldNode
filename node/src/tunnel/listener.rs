use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use super::tun_device::TunDevice;
use super::wireguard::WireguardTunnel;
use crate::metrics::bandwidth::BandwidthTracker;

struct PeerState {
    tunnel: WireguardTunnel,
    session_id: u64,
    last_active: Instant,
}

const PEER_IDLE_TIMEOUT_SECS: u64 = 300;
const EVICTION_INTERVAL_SECS: u64 = 60;

/// UDP listener that accepts WireGuard handshakes and tunnels traffic.
///
/// In exit mode, decapsulated packets are written to a TUN device which
/// injects them into the OS network stack. Response packets read from the
/// TUN are encapsulated and sent back to the most recently active peer.
pub struct TunnelListener {
    socket: UdpSocket,
    private_key: [u8; 32],
    peers: HashMap<SocketAddr, PeerState>,
    next_session_id: u64,
    bandwidth: Arc<Mutex<BandwidthTracker>>,
    exit_mode: bool,
    tun: Option<Arc<TunDevice>>,
    /// Last active peer for TUN return path routing.
    last_active_peer: Option<SocketAddr>,
}

impl TunnelListener {
    /// Create a tunnel listener.
    ///
    /// If an `Arc<TunDevice>` is provided it will be used for exit-mode
    /// forwarding. This allows the TUN device to be shared with other
    /// subsystems such as the relay listener.
    pub async fn bind(
        listen_port: u16,
        private_key: [u8; 32],
        bandwidth: Arc<Mutex<BandwidthTracker>>,
        exit_mode: bool,
        tun: Option<Arc<TunDevice>>,
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
            tun,
            last_active_peer: None,
        })
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        let mut recv_buf = vec![0u8; 65536];
        let mut send_buf = vec![0u8; 65536];
        let mut tun_buf = vec![0u8; 65536];
        let mut last_eviction = Instant::now();

        info!(
            exit_mode = self.exit_mode,
            has_tun = self.tun.is_some(),
            "tunnel listener running"
        );

        loop {
            // Use select! to read from both UDP and TUN concurrently.
            tokio::select! {
                // ── Incoming from client (UDP) ──────────────────────────
                result = self.socket.recv_from(&mut recv_buf) => {
                    let (n, peer_addr) = result?;
                    let packet = &recv_buf[..n];

                    debug!(peer = %peer_addr, bytes = n, "received UDP packet");

                    if last_eviction.elapsed().as_secs() >= EVICTION_INTERVAL_SECS {
                        self.evict_stale_peers();
                        last_eviction = Instant::now();
                    }

                    let session_id = self.get_or_create_peer(peer_addr);
                    self.last_active_peer = Some(peer_addr);

                    let peer = self.peers.get_mut(&peer_addr)
                        .expect("peer must exist after get_or_create_peer");
                    peer.last_active = Instant::now();

                    match peer.tunnel.handle_incoming(packet, &mut send_buf) {
                        Ok(0) => {
                            self.drive_handshake(peer_addr, &mut send_buf).await;
                        }
                        Ok(payload_len) => {
                            let inner = &send_buf[..payload_len];
                            debug!(peer = %peer_addr, inner_len = payload_len, "decapsulated inner packet");

                            {
                                let mut bw = self.bandwidth.lock().await;
                                bw.record_bytes(session_id, n as u64, payload_len as u64);
                            }

                            if self.exit_mode {
                                if let Some(tun) = &self.tun {
                                    if let Err(e) = tun.write_packet(inner).await {
                                        warn!(error = %e, "failed to write to TUN");
                                    }
                                }
                            } else {
                                debug!("relay mode: would forward to next hop");
                            }
                        }
                        Err(e) => {
                            debug!(peer = %peer_addr, error = %e, "decapsulation error");
                            self.drive_handshake(peer_addr, &mut send_buf).await;
                        }
                    }
                }

                // ── Response from TUN (return path) ─────────────────────
                result = async {
                    if let Some(ref tun) = self.tun {
                        tun.read_packet(&mut tun_buf).await
                    } else {
                        // No TUN device — sleep forever (never selected).
                        std::future::pending::<Result<usize, super::tun_device::TunError>>().await
                    }
                } => {
                    match result {
                        Ok(n) if n > 0 => {
                            if let Some(peer_addr) = self.last_active_peer {
                                if let Some(peer) = self.peers.get_mut(&peer_addr) {
                                    // Encapsulate the TUN response in WireGuard.
                                    match peer.tunnel.handle_outgoing(&tun_buf[..n], &mut send_buf) {
                                        Ok(encrypted) if !encrypted.is_empty() => {
                                            if let Err(e) = self.socket.send_to(encrypted, peer_addr).await {
                                                warn!(error = %e, "failed to send TUN response to peer");
                                            } else {
                                                debug!(peer = %peer_addr, tun_bytes = n, enc_bytes = encrypted.len(), "sent TUN response");
                                            }
                                        }
                                        Ok(_) => {}
                                        Err(e) => {
                                            debug!(error = %e, "WireGuard encapsulation failed for TUN response");
                                        }
                                    }
                                }
                            }
                        }
                        Ok(_) => {}
                        Err(e) => {
                            warn!(error = %e, "TUN read error");
                        }
                    }
                }
            }
        }
    }

    fn get_or_create_peer(&mut self, addr: SocketAddr) -> u64 {
        use std::collections::hash_map::Entry;
        match self.peers.entry(addr) {
            Entry::Occupied(e) => e.get().session_id,
            Entry::Vacant(e) => {
                let session_id = self.next_session_id;
                self.next_session_id += 1;

                let tunnel = WireguardTunnel::new(self.private_key, [0u8; 32], Some(addr));

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

    fn evict_stale_peers(&mut self) {
        let timeout = std::time::Duration::from_secs(PEER_IDLE_TIMEOUT_SECS);
        let before = self.peers.len();
        self.peers.retain(|_, p| p.last_active.elapsed() < timeout);
        let evicted = before - self.peers.len();
        if evicted > 0 {
            // Clear stale last_active_peer if the peer was evicted.
            if let Some(ref addr) = self.last_active_peer {
                if !self.peers.contains_key(addr) {
                    self.last_active_peer = None;
                }
            }
            info!(evicted, remaining = self.peers.len(), "evicted stale peers");
        }
    }
}
