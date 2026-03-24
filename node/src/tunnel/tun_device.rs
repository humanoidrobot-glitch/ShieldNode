use thiserror::Error;
use tracing::{debug, info};

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
    pub address: String,
    pub netmask: u8,
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
/// device, which injects them into the OS network stack. The return path
/// (TUN -> WireGuard encapsulation) will be implemented in Phase 2 when
/// multi-peer routing is needed.
pub struct TunDevice {
    device: tun_rs::AsyncDevice,
}

impl TunDevice {
    pub async fn create(config: &TunConfig) -> Result<Self, TunError> {
        let ip: std::net::Ipv4Addr = config
            .address
            .parse()
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

        Ok(Self { device })
    }

    /// Write an IP packet to the TUN device (inject into OS network stack).
    pub async fn write_packet(&self, packet: &[u8]) -> Result<(), TunError> {
        if packet.is_empty() {
            return Ok(());
        }

        debug!(
            len = packet.len(),
            ip_version = packet[0] >> 4,
            "writing to TUN"
        );

        self.device
            .send(packet)
            .await
            .map_err(|e| TunError::WriteFailed(e.to_string()))?;

        Ok(())
    }

    /// Read an IP packet from the TUN device (response from OS).
    pub async fn read_packet(&self, buf: &mut [u8]) -> Result<usize, TunError> {
        let n = self
            .device
            .recv(buf)
            .await
            .map_err(|e| TunError::ReadFailed(e.to_string()))?;
        Ok(n)
    }
}
