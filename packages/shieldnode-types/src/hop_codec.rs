//! Next-hop address encoding for Sphinx relay routing.

use std::net::Ipv4Addr;

/// Encode an IPv4 address and port into a 32-byte next-hop identifier.
///
/// Layout: `[4-byte IPv4][2-byte port BE][26 zero bytes]`
pub fn encode_next_hop(ip: Ipv4Addr, port: u16) -> [u8; 32] {
    let mut buf = [0u8; 32];
    let octets = ip.octets();
    buf[0] = octets[0];
    buf[1] = octets[1];
    buf[2] = octets[2];
    buf[3] = octets[3];
    let port_bytes = port.to_be_bytes();
    buf[4] = port_bytes[0];
    buf[5] = port_bytes[1];
    buf
}

/// Returns `true` when the 32-byte next-hop is the exit sentinel (all zeros).
pub fn is_exit_hop(next_hop: &[u8; 32]) -> bool {
    *next_hop == [0u8; 32]
}

/// Parse an endpoint string like `"203.0.113.10:51820"` and produce a
/// next-hop encoding using `relay_port` as the port value.
pub fn endpoint_to_next_hop(endpoint: &str, relay_port: u16) -> Result<[u8; 32], String> {
    let addr: std::net::SocketAddr = endpoint
        .parse()
        .map_err(|e| format!("invalid endpoint '{endpoint}': {e}"))?;

    match addr.ip() {
        std::net::IpAddr::V4(ipv4) => Ok(encode_next_hop(ipv4, relay_port)),
        std::net::IpAddr::V6(_) => Err("IPv6 endpoints are not supported".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_roundtrip() {
        let ip = Ipv4Addr::new(203, 0, 113, 10);
        let port = 51821u16;
        let nh = encode_next_hop(ip, port);
        assert_eq!(nh[0], 203);
        assert_eq!(u16::from_be_bytes([nh[4], nh[5]]), 51821);
        assert_eq!(&nh[6..], &[0u8; 26]);
    }

    #[test]
    fn exit_hop_is_all_zeros() {
        assert!(is_exit_hop(&[0u8; 32]));
        let mut nh = [0u8; 32];
        nh[0] = 1;
        assert!(!is_exit_hop(&nh));
    }

    #[test]
    fn endpoint_to_next_hop_ok() {
        let nh = endpoint_to_next_hop("203.0.113.10:51820", 51821).unwrap();
        assert_eq!(nh[0], 203);
        assert_eq!(u16::from_be_bytes([nh[4], nh[5]]), 51821);
    }
}
