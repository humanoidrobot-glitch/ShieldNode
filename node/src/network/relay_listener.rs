use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::crypto::sphinx::SphinxPacket;
use crate::metrics::bandwidth::BandwidthTracker;
use crate::tunnel::tun_device::TunDevice;

use super::relay::RelayService;

/// Minimum packet size: 8-byte session_id + at least 36 bytes for a serialized SphinxPacket.
const MIN_PACKET_SIZE: usize = 8 + 36;

/// A dedicated UDP listener for multi-hop relay traffic.
///
/// Relay packets use a simple framing: `[8-byte session_id][SphinxPacket bytes]`.
/// Each node listens on a relay port (default 51821, one above the WireGuard port).
///
/// When a packet arrives the listener:
/// 1. Parses the 8-byte session_id.
/// 2. Deserializes the SphinxPacket from the remaining bytes.
/// 3. Peels one onion layer via `RelayService::forward_packet()`.
/// 4. If the resulting next_hop is all zeros this is the exit node — the
///    payload is written to the TUN device.
/// 5. Otherwise the re-wrapped packet is forwarded to the next hop's relay
///    port with the new session_id.
pub struct RelayListener {
    socket: UdpSocket,
    relay_service: Arc<Mutex<RelayService>>,
    tun: Option<Arc<TunDevice>>,
    /// Kept for future direct bandwidth bookkeeping (e.g. per-relay-hop stats).
    #[allow(dead_code)]
    bandwidth: Arc<Mutex<BandwidthTracker>>,
}

impl RelayListener {
    /// Bind the relay listener to `0.0.0.0:<port>`.
    pub async fn bind(
        port: u16,
        relay_service: Arc<Mutex<RelayService>>,
        tun: Option<Arc<TunDevice>>,
        bandwidth: Arc<Mutex<BandwidthTracker>>,
    ) -> Result<Self> {
        let addr: SocketAddr = format!("0.0.0.0:{port}").parse()?;
        let socket = UdpSocket::bind(addr)
            .await
            .with_context(|| format!("binding relay listener on {addr}"))?;
        info!(%addr, "relay UDP listener bound");

        Ok(Self {
            socket,
            relay_service,
            tun,
            bandwidth,
        })
    }

    /// Main receive loop — runs until the task is cancelled.
    pub async fn run(&self) -> Result<()> {
        let mut buf = vec![0u8; 65536];

        info!(has_tun = self.tun.is_some(), "relay listener running");

        loop {
            let (n, peer_addr) = self.socket.recv_from(&mut buf).await?;

            if n < MIN_PACKET_SIZE {
                debug!(
                    peer = %peer_addr,
                    bytes = n,
                    "relay packet too short, dropping"
                );
                continue;
            }

            let packet = &buf[..n];

            // Parse framing: [8-byte session_id][sphinx_packet_bytes]
            let session_id =
                u64::from_be_bytes(packet[..8].try_into().expect("slice is exactly 8 bytes"));
            let sphinx_bytes = &packet[8..];

            let sphinx_packet = match SphinxPacket::from_bytes(sphinx_bytes) {
                Ok(pkt) => pkt,
                Err(e) => {
                    warn!(
                        peer = %peer_addr,
                        session_id,
                        error = %e,
                        "failed to deserialize SphinxPacket"
                    );
                    continue;
                }
            };

            debug!(
                peer = %peer_addr,
                session_id,
                payload_len = sphinx_packet.payload.len(),
                "received relay packet"
            );

            // Peel one layer
            let (next_hop, inner_packet) = {
                let svc = self.relay_service.lock().await;
                match svc.forward_packet(session_id, &sphinx_packet).await {
                    Ok(result) => result,
                    Err(e) => {
                        warn!(
                            session_id,
                            error = %e,
                            "forward_packet failed"
                        );
                        continue;
                    }
                }
            };

            // Check if this is the exit (next_hop == all zeros)
            if next_hop == [0u8; 32] {
                // Exit node: write decrypted payload to TUN
                if let Some(ref tun) = self.tun {
                    if let Err(e) = tun.write_packet(&inner_packet.payload).await {
                        warn!(
                            session_id,
                            error = %e,
                            "failed to write relay payload to TUN"
                        );
                    } else {
                        debug!(
                            session_id,
                            payload_len = inner_packet.payload.len(),
                            "exit: wrote relay payload to TUN"
                        );
                    }
                } else {
                    warn!(
                        session_id,
                        "exit relay packet arrived but no TUN device available"
                    );
                }
            } else {
                // Forward to next hop
                if let Err(e) = self
                    .forward_to_next_hop(&next_hop, session_id, &inner_packet)
                    .await
                {
                    warn!(
                        session_id,
                        error = %e,
                        "failed to forward to next hop"
                    );
                }
            }
        }
    }

    /// Serialize and send the inner packet to the next relay hop.
    ///
    /// The next_hop is interpreted as a 32-byte identifier.  The first 4
    /// bytes are treated as an IPv4 address and the next 2 bytes as the
    /// relay port (big-endian).  If the port bytes are zero the default
    /// relay port (51821) is used.
    async fn forward_to_next_hop(
        &self,
        next_hop: &[u8; 32],
        session_id: u64,
        inner_packet: &SphinxPacket,
    ) -> Result<()> {
        let ip = std::net::Ipv4Addr::new(next_hop[0], next_hop[1], next_hop[2], next_hop[3]);

        // Reject reserved/unroutable addresses.
        if ip.is_unspecified() || ip.is_loopback() || ip.is_broadcast() || ip.is_multicast() {
            anyhow::bail!("next-hop IP {ip} is a reserved address");
        }

        let port = {
            let p = u16::from_be_bytes([next_hop[4], next_hop[5]]);
            if p == 0 { 51821 } else { p }
        };

        let dest = SocketAddr::from((ip, port));

        // Frame: [8-byte session_id][sphinx bytes]
        let sphinx_bytes = inner_packet.to_bytes();
        let mut frame = Vec::with_capacity(8 + sphinx_bytes.len());
        frame.extend_from_slice(&session_id.to_be_bytes());
        frame.extend_from_slice(&sphinx_bytes);

        self.socket
            .send_to(&frame, dest)
            .await
            .with_context(|| format!("sending relay packet to {dest}"))?;

        debug!(
            session_id,
            dest = %dest,
            frame_len = frame.len(),
            "forwarded relay packet to next hop"
        );

        Ok(())
    }
}
