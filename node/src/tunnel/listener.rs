use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::metrics::bandwidth::BandwidthTracker;
use super::tun_device::{TunConfig, TunDevice};
use super::wireguard::WireguardTunnel;

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
/// injects them into the OS network stack. Responses are read back from
/// the TUN and encapsulated for return to the client.
pub struct TunnelListener {
    socket: Arc<UdpSocket>,
    private_key: [u8; 32],
    peers: HashMap<SocketAddr, PeerState>,
    next_session_id: u64,
    bandwidth: Arc<Mutex<BandwidthTracker>>,
    exit_mode: bool,
    tun: Option<Arc<TunDevice>>,
    /// Track the last peer that sent a packet (for return path routing).
    last_peer_addr: Option<SocketAddr>,
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

        // Create TUN device in exit mode.
        let tun = if exit_mode {
            match TunDevice::create(&TunConfig::default(), bandwidth.clone()).await {
                Ok(dev) => {
                    info!("TUN device ready for exit-mode forwarding");
                    Some(Arc::new(dev))
                }
                Err(e) => {
                    warn!(error = %e, "failed to create TUN device — exit forwarding disabled. \
                          Run as administrator/root to enable TUN.");
                    None
                }
            }
        } else {
            None
        };

        Ok(Self {
            socket: Arc::new(socket),
            private_key,
            peers: HashMap::new(),
            next_session_id: 1,
            bandwidth,
            exit_mode,
            tun,
            last_peer_addr: None,
        })
    }

    /// Run the tunnel listener. In exit mode with a TUN device, this
    /// spawns a return-path task that reads responses from the TUN and
    /// sends them back through WireGuard.
    pub async fn run(&mut self) -> anyhow::Result<()> {
        // Spawn TUN return-path task if we have a TUN device.
        if let Some(tun) = &self.tun {
            let tun = Arc::clone(tun);
            let socket = Arc::clone(&self.socket);
            // For Phase 1 single-peer, we route TUN responses back to the
            // last known peer. Multi-peer routing (Phase 2+) needs a proper
            // routing table mapping destination IPs to peer addresses.
            let last_peer = Arc::new(Mutex::new(self.last_peer_addr));
            let last_peer_for_task = Arc::clone(&last_peer);

            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                let mut encap_buf = vec![0u8; 65536];
                loop {
                    match tun.read_packet(&mut buf).await {
                        Ok(0) => continue,
                        Ok(n) => {
                            let _peer = last_peer_for_task.lock().await;
                            // TODO: encapsulate through WireGuard and send back.
                            // This requires access to the peer's tunnel, which
                            // needs refactoring to share tunnel state between
                            // the inbound and return paths. For now, log.
                            debug!(len = n, "TUN response packet (return path stub)");
                            let _ = &encap_buf; // suppress unused warning
                        }
                        Err(e) => {
                            warn!(error = %e, "TUN read error");
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    }
                }
            });
        }

        let mut recv_buf = vec![0u8; 65536];
        let mut send_buf = vec![0u8; 65536];
        let mut last_eviction = Instant::now();

        info!(exit_mode = self.exit_mode, has_tun = self.tun.is_some(), "tunnel listener running");

        loop {
            let (n, peer_addr) = self.socket.recv_from(&mut recv_buf).await?;
            let packet = &recv_buf[..n];

            debug!(peer = %peer_addr, bytes = n, "received UDP packet");

            if last_eviction.elapsed().as_secs() >= EVICTION_INTERVAL_SECS {
                self.evict_stale_peers();
                last_eviction = Instant::now();
            }

            let session_id = self.get_or_create_peer(peer_addr);

            let peer = self.peers.get_mut(&peer_addr).unwrap();
            peer.last_active = Instant::now();
            self.last_peer_addr = Some(peer_addr);

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
                        } else {
                            debug!("exit mode but no TUN device — packet dropped");
                        }
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

    fn get_or_create_peer(&mut self, addr: SocketAddr) -> u64 {
        use std::collections::hash_map::Entry;
        match self.peers.entry(addr) {
            Entry::Occupied(e) => e.get().session_id,
            Entry::Vacant(e) => {
                let session_id = self.next_session_id;
                self.next_session_id += 1;

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
            info!(evicted, remaining = self.peers.len(), "evicted stale peers");
        }
    }
}
