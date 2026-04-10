//! TUN virtual network interface for capturing and injecting OS traffic.
//!
//! Creates a platform-specific TUN device that routes traffic through the
//! ShieldNode VPN tunnel. Outgoing packets are captured from the TUN,
//! encrypted via WireGuard + Sphinx, and sent to the entry node. Incoming
//! decrypted packets are injected back into the TUN.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tracing::{debug, info, warn};

/// Default TUN device IP configuration.
const TUN_ADDRESS: &str = "10.13.37.2";
const TUN_NETMASK: u8 = 24;
const TUN_NAME: &str = "shieldnode0";

/// Manages the client-side TUN device.
pub struct ClientTun {
    device: tun_rs::AsyncDevice,
    active: Arc<AtomicBool>,
}

impl ClientTun {
    /// Create and configure the TUN device.
    pub async fn create() -> Result<Self, String> {
        let ip: std::net::Ipv4Addr = TUN_ADDRESS.parse()
            .map_err(|e| format!("invalid TUN IP: {e}"))?;

        let device = tun_rs::DeviceBuilder::new()
            .name(TUN_NAME)
            .ipv4(ip, TUN_NETMASK, None)
            .enable(true)
            .build_async()
            .map_err(|e| format!("failed to create TUN device: {e}"))?;

        info!(name = TUN_NAME, address = TUN_ADDRESS, "TUN device created");

        Ok(Self {
            device,
            active: Arc::new(AtomicBool::new(true)),
        })
    }

    /// Read one packet from the TUN device (OS outgoing traffic).
    pub async fn read_packet(&self, buf: &mut [u8]) -> Result<usize, String> {
        let n = self.device.recv(buf).await
            .map_err(|e| format!("TUN read error: {e}"))?;
        debug!(bytes = n, "read packet from TUN");
        Ok(n)
    }

    /// Write one packet to the TUN device (inject into OS network stack).
    pub async fn write_packet(&self, packet: &[u8]) -> Result<(), String> {
        if packet.is_empty() {
            return Ok(());
        }
        self.device.send(packet).await
            .map_err(|e| format!("TUN write error: {e}"))?;
        debug!(bytes = packet.len(), "wrote packet to TUN");
        Ok(())
    }

    /// Check if the TUN device is still active.
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    /// Mark the TUN device as inactive (stops the forwarding loop).
    pub fn deactivate(&self) {
        self.active.store(false, Ordering::Relaxed);
        info!("TUN device deactivated");
    }
}
