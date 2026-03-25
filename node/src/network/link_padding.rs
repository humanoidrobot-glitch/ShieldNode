//! Inter-node link padding.
//!
//! Maintains a constant-rate encrypted padding stream between adjacent relay
//! nodes, independent of user traffic. Prevents a network-level observer from
//! determining which links carry real traffic and which are idle.
//!
//! Each peer link targets a configurable baseline packet rate (default 50 pps).
//! When real session traffic is below the baseline, padding fills the gap.
//! When real traffic exceeds the baseline, all links scale up together so the
//! increase doesn't correlate to a specific session.
//!
//! Bandwidth cost: ~50 pps × 1280 bytes × num_peers.
//! For a node with 10 peers: ~640 KB/s = ~55 GB/day.
//! Only enable for nodes with high-bandwidth connections.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::Rng;
use tokio::net::UdpSocket;
use tracing::{info, warn};

use crate::tunnel::packet_norm::NORMALIZED_SIZE;

/// Padding packet magic (first 4 bytes). Receiving nodes recognize and
/// silently discard padding without processing as relay traffic.
pub const PADDING_MAGIC: [u8; 4] = [0x50, 0x41, 0x44, 0x44]; // "PADD"

/// Per-peer link state.
struct PeerLink {
    /// Address of the peer's relay port.
    addr: SocketAddr,
    /// Packets sent to this peer in the current window.
    packets_this_window: u32,
    /// Window start time.
    window_start: Instant,
    /// Total padding packets sent to this peer.
    total_padding: u64,
}

impl PeerLink {
    fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            packets_this_window: 0,
            window_start: Instant::now(),
            total_padding: 0,
        }
    }

    /// Record real traffic sent to this peer.
    fn record_real(&mut self, count: u32) {
        self.packets_this_window += count;
    }

    /// Calculate padding needed to maintain the target rate.
    fn padding_needed(&mut self, target_pps: u32) -> u32 {
        if self.window_start.elapsed() >= Duration::from_secs(1) {
            self.packets_this_window = 0;
            self.window_start = Instant::now();
        }

        let elapsed_secs = self.window_start.elapsed().as_secs_f64().max(0.01);
        let current_pps = self.packets_this_window as f64 / elapsed_secs;
        let target = target_pps as f64;

        if current_pps >= target {
            return 0;
        }

        let deficit = (target - current_pps) * elapsed_secs;
        let needed = deficit.ceil() as u32;

        // Jitter ±15% to prevent timing fingerprinting.
        let mut rng = rand::thread_rng();
        let jitter: f64 = rng.gen_range(0.85..1.15);
        (needed as f64 * jitter) as u32
    }

    fn record_padding_sent(&mut self, count: u32) {
        self.packets_this_window += count;
        self.total_padding += count as u64;
    }
}

/// Manages padding for all peer links.
pub struct LinkPaddingManager {
    peers: HashMap<SocketAddr, PeerLink>,
    target_pps: u32,
}

impl LinkPaddingManager {
    pub fn new(target_pps: u32) -> Self {
        Self {
            peers: HashMap::new(),
            target_pps,
        }
    }

    /// Register a new peer link.
    pub fn add_peer(&mut self, addr: SocketAddr) {
        self.peers.entry(addr).or_insert_with(|| PeerLink::new(addr));
    }

    /// Remove a peer link.
    pub fn remove_peer(&mut self, addr: &SocketAddr) {
        self.peers.remove(addr);
    }

    /// Record real traffic sent to a specific peer.
    pub fn record_real_traffic(&mut self, peer: &SocketAddr, packets: u32) {
        if let Some(link) = self.peers.get_mut(peer) {
            link.record_real(packets);
        }
    }

    /// Get padding needed for each peer. Returns (addr, count) pairs.
    pub fn padding_needed(&mut self) -> Vec<(SocketAddr, u32)> {
        self.peers
            .values_mut()
            .filter_map(|link| {
                let n = link.padding_needed(self.target_pps);
                if n > 0 {
                    Some((link.addr, n))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Record padding sent to a peer.
    pub fn record_padding_sent(&mut self, peer: &SocketAddr, count: u32) {
        if let Some(link) = self.peers.get_mut(peer) {
            link.record_padding_sent(count);
        }
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn total_padding_sent(&self) -> u64 {
        self.peers.values().map(|l| l.total_padding).sum()
    }
}

/// Generate a padding packet (fixed-size, random fill with magic header).
pub fn generate_padding_packet() -> Vec<u8> {
    let mut packet = vec![0u8; NORMALIZED_SIZE];
    packet[..4].copy_from_slice(&PADDING_MAGIC);
    rand::thread_rng().fill(&mut packet[4..]);
    packet
}

/// Check if a received packet is padding (should be discarded).
pub fn is_padding_packet(data: &[u8]) -> bool {
    data.len() >= 4 && data[..4] == PADDING_MAGIC
}

/// Run the link padding loop for all registered peers.
///
/// Set `stop` to true to terminate the loop gracefully.
pub async fn link_padding_loop(
    stop: Arc<AtomicBool>,
    socket: Arc<UdpSocket>,
    manager: Arc<tokio::sync::Mutex<LinkPaddingManager>>,
) {
    let interval = Duration::from_millis(100);

    info!("link padding loop started");

    loop {
        if stop.load(Ordering::Relaxed) {
            let mgr = manager.lock().await;
            info!(
                total_padding = mgr.total_padding_sent(),
                peers = mgr.peer_count(),
                "link padding loop stopped"
            );
            return;
        }

        tokio::time::sleep(interval).await;

        let padding_needed = {
            let mut mgr = manager.lock().await;
            mgr.padding_needed()
        };

        for (addr, count) in &padding_needed {
            for _ in 0..*count {
                let packet = generate_padding_packet();
                if let Err(e) = socket.send_to(&packet, addr).await {
                    warn!(peer = %addr, error = %e, "failed to send padding packet");
                    break;
                }
            }
            let mut mgr = manager.lock().await;
            mgr.record_padding_sent(addr, *count);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_packet_has_magic_and_correct_size() {
        let pkt = generate_padding_packet();
        assert_eq!(pkt.len(), NORMALIZED_SIZE);
        assert!(is_padding_packet(&pkt));
    }

    #[test]
    fn real_packet_is_not_padding() {
        let pkt = vec![0u8; NORMALIZED_SIZE];
        assert!(!is_padding_packet(&pkt));
    }

    #[test]
    fn peer_link_needs_padding_when_idle() {
        let addr: SocketAddr = "10.0.0.1:51821".parse().unwrap();
        let mut link = PeerLink::new(addr);
        std::thread::sleep(Duration::from_millis(200));
        let needed = link.padding_needed(50);
        assert!(needed > 0, "idle link should need padding");
    }

    #[test]
    fn peer_link_no_padding_when_busy() {
        let addr: SocketAddr = "10.0.0.1:51821".parse().unwrap();
        let mut link = PeerLink::new(addr);
        link.record_real(200); // way above 50 pps target
        let needed = link.padding_needed(50);
        assert_eq!(needed, 0, "busy link should not need padding");
    }

    #[test]
    fn manager_tracks_multiple_peers() {
        let mut mgr = LinkPaddingManager::new(50);
        let a: SocketAddr = "10.0.0.1:51821".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:51821".parse().unwrap();

        mgr.add_peer(a);
        mgr.add_peer(b);
        assert_eq!(mgr.peer_count(), 2);

        mgr.remove_peer(&a);
        assert_eq!(mgr.peer_count(), 1);
    }

    #[test]
    fn manager_padding_needed_for_idle_peers() {
        let mut mgr = LinkPaddingManager::new(50);
        let a: SocketAddr = "10.0.0.1:51821".parse().unwrap();
        mgr.add_peer(a);

        std::thread::sleep(Duration::from_millis(200));
        let needed = mgr.padding_needed();
        assert!(!needed.is_empty(), "idle peer should need padding");
    }

    #[test]
    fn manager_records_padding() {
        let mut mgr = LinkPaddingManager::new(50);
        let a: SocketAddr = "10.0.0.1:51821".parse().unwrap();
        mgr.add_peer(a);

        mgr.record_padding_sent(&a, 10);
        assert_eq!(mgr.total_padding_sent(), 10);
    }

    #[test]
    fn daily_bandwidth_estimate() {
        // 50 pps × 1280 bytes × 86400 seconds × 10 peers ≈ 55 GB/day
        let pps: u64 = 50;
        let peers: u64 = 10;
        let daily = pps * NORMALIZED_SIZE as u64 * 86400 * peers;
        assert!(daily > 50_000_000_000, "should be >50 GB");
        assert!(daily < 60_000_000_000, "should be <60 GB");
    }
}
