//! UPnP/IGD port mapping for NAT traversal.
//!
//! Attempts to map relay, WireGuard, and libp2p ports via UPnP on startup.
//! Falls back gracefully if no gateway is found or mapping fails.

use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};

use igd_next::PortMappingProtocol;
use tracing::{info, warn};

/// Lease duration for UPnP port mappings.
/// NOTE: No automatic renewal — mappings expire after 1 hour. For long-running
/// nodes, manual port forwarding is more reliable. Future: spawn a renewal task.
const LEASE_SECS: u32 = 3600;

/// Attempt to map the given ports via UPnP/IGD.
///
/// Runs synchronous IGD operations on a blocking thread.
/// Logs success/failure per port. Returns the gateway's external IP on success.
pub async fn attempt_upnp_mappings(
    ports: &[(u16, PortMappingProtocol, &str)],
) -> Result<IpAddr, String> {
    let ports: Vec<(u16, PortMappingProtocol, String)> = ports
        .iter()
        .map(|&(p, proto, desc)| (p, proto, desc.to_string()))
        .collect();

    tokio::task::spawn_blocking(move || {
        let gateway = igd_next::search_gateway(Default::default())
            .map_err(|e| format!("UPnP gateway discovery failed: {e}"))?;

        let external_ip = gateway
            .get_external_ip()
            .map_err(|e| format!("failed to get external IP: {e}"))?;

        info!(external_ip = %external_ip, "UPnP gateway found");

        // Use 0.0.0.0 — the router resolves the requester's actual LAN IP.
        // gateway.addr is the router's control URL, not the local machine.
        let local_ip = Ipv4Addr::UNSPECIFIED;

        for (port, protocol, description) in &ports {
            let local = std::net::SocketAddr::V4(SocketAddrV4::new(local_ip, *port));
            match gateway.add_port(*protocol, *port, local, LEASE_SECS, description) {
                Ok(()) => {
                    info!(port, protocol = ?protocol, description = description.as_str(), "UPnP port mapped");
                }
                Err(e) => {
                    warn!(port, protocol = ?protocol, error = %e, "UPnP port mapping failed");
                }
            }
        }

        Ok(external_ip)
    })
    .await
    .map_err(|e| format!("UPnP task panicked: {e}"))?
}

/// Build the standard port mapping list for a ShieldNode relay.
pub fn relay_port_mappings(
    wg_port: u16,
    relay_port: u16,
    libp2p_port: u16,
) -> Vec<(u16, PortMappingProtocol, &'static str)> {
    vec![
        (wg_port, PortMappingProtocol::UDP, "ShieldNode WireGuard"),
        (relay_port, PortMappingProtocol::UDP, "ShieldNode Relay"),
        (libp2p_port, PortMappingProtocol::TCP, "ShieldNode libp2p"),
    ]
}
