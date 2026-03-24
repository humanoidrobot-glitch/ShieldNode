use std::sync::Arc;

use thiserror::Error;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::metrics::bandwidth::BandwidthTracker;

#[derive(Debug, Error)]
pub enum TunError {
    #[error("TUN device creation failed: {0}")]
    CreateFailed(String),
    #[error("TUN read error: {0}")]
    ReadFailed(String),
    #[error("TUN write error: {0}")]
    WriteFailed(String),
}

/// TUN device IP address configuration.
pub struct TunConfig {
    /// IP address for the TUN interface (e.g., "10.0.0.1").
    pub address: String,
    /// Subnet prefix length (e.g., 24 for /24).
    pub netmask: u8,
    /// Name for the TUN interface.
    pub name: String,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            address: "10.13.37.1".to_string(),
            netmask: 24,
            name: "shieldnode".to_string(),
        }
    }
}

/// Manages a TUN virtual network interface for forwarding IP packets.
///
/// In exit mode, decapsulated WireGuard packets are written to the TUN
/// device, which injects them into the OS network stack. Responses from
/// the OS are read back and encapsulated for return to the client.
pub struct TunDevice {
    device: tun_rs::AsyncDevice,
    bandwidth: Arc<Mutex<BandwidthTracker>>,
}

impl TunDevice {
    /// Create and bring up the TUN interface.
    pub async fn create(
        config: &TunConfig,
        bandwidth: Arc<Mutex<BandwidthTracker>>,
    ) -> Result<Self, TunError> {
        let ip: std::net::Ipv4Addr = config.address.parse()
            .map_err(|e| TunError::CreateFailed(format!("invalid TUN IP: {e}")))?;

        let device = tun_rs::DeviceBuilder::new()
            .name(&config.name)
            .ipv4(ip, config.netmask, None)
            .enable(true)
            .build_async()
            .map_err(|e| TunError::CreateFailed(format!("{e}")))?;

        info!(
            name = config.name,
            address = %config.address,
            netmask = config.netmask,
            "TUN device created and up"
        );

        Ok(Self { device, bandwidth })
    }

    /// Write an IP packet to the TUN device (inject into OS network stack).
    /// Called when a WireGuard packet is decapsulated in exit mode.
    pub async fn write_packet(&self, packet: &[u8]) -> Result<(), TunError> {
        if packet.is_empty() {
            return Ok(());
        }

        let version = packet[0] >> 4;
        debug!(len = packet.len(), ip_version = version, "writing to TUN");

        self.device.send(packet).await
            .map_err(|e| TunError::WriteFailed(e.to_string()))?;

        Ok(())
    }

    /// Read an IP packet from the TUN device (response from OS).
    /// Returns the number of bytes read into `buf`.
    pub async fn read_packet(&self, buf: &mut [u8]) -> Result<usize, TunError> {
        let n = self.device.recv(buf).await
            .map_err(|e| TunError::ReadFailed(e.to_string()))?;

        if n > 0 {
            debug!(len = n, "read from TUN");
        }

        Ok(n)
    }

    /// Run the TUN -> WireGuard return path. Reads packets from the TUN
    /// device and sends them back through the WireGuard UDP socket to the
    /// appropriate peer.
    ///
    /// `send_to_peer` is a callback that encapsulates and sends the packet
    /// back to the correct WireGuard peer.
    pub async fn run_return_path<F>(&self, mut send_to_peer: F)
    where
        F: FnMut(&[u8]) -> futures::future::BoxFuture<'_, ()>,
    {
        let mut buf = vec![0u8; 65536];
        loop {
            match self.read_packet(&mut buf).await {
                Ok(0) => continue,
                Ok(n) => {
                    let packet = &buf[..n];
                    send_to_peer(packet).await;
                }
                Err(e) => {
                    warn!(error = %e, "TUN read error");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }
}
