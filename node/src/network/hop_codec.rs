//! Re-export shared hop codec + node-only decode function.

pub use shieldnode_types::hop_codec::*;

use std::net::Ipv4Addr;

/// Decode a 32-byte next-hop into an IPv4 address and port.
///
/// Returns an error for unspecified, loopback, broadcast, or multicast IPs.
pub fn decode_next_hop(next_hop: &[u8; 32], default_port: u16) -> Result<(Ipv4Addr, u16), String> {
    let ip = Ipv4Addr::new(next_hop[0], next_hop[1], next_hop[2], next_hop[3]);

    if ip.is_unspecified() {
        return Err(format!("next-hop IP {ip} is unspecified"));
    }
    if ip.is_loopback() {
        return Err(format!("next-hop IP {ip} is a loopback address"));
    }
    if ip.is_broadcast() {
        return Err(format!("next-hop IP {ip} is a broadcast address"));
    }
    if ip.is_multicast() {
        return Err(format!("next-hop IP {ip} is a multicast address"));
    }

    let port = u16::from_be_bytes([next_hop[4], next_hop[5]]);
    let port = if port == 0 { default_port } else { port };

    Ok((ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_roundtrip() {
        let ip = Ipv4Addr::new(203, 0, 113, 10);
        let nh = encode_next_hop(ip, 51821);
        let (decoded_ip, decoded_port) = decode_next_hop(&nh, 0).unwrap();
        assert_eq!(decoded_ip, ip);
        assert_eq!(decoded_port, 51821);
    }

    #[test]
    fn exit_hop_is_all_zeros() {
        assert!(is_exit_hop(&[0u8; 32]));
    }

    #[test]
    fn decode_rejects_loopback() {
        let nh = encode_next_hop(Ipv4Addr::new(127, 0, 0, 1), 51821);
        assert!(decode_next_hop(&nh, 0).is_err());
    }
}
