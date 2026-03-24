//! Encoding and decoding of 32-byte next-hop identifiers.
//!
//! The relay layer uses a fixed 32-byte blob to represent the next hop in a
//! Sphinx route.  The format is intentionally simple:
//!
//! ```text
//! [0.. 4)  IPv4 address (4 bytes, network byte order)
//! [4.. 6)  port         (2 bytes, big-endian)
//! [6..32)  reserved     (26 zero bytes)
//! ```
//!
//! An all-zero blob is the **exit sentinel** — it signals that the current
//! node is the final hop and the decrypted payload should be delivered
//! locally (e.g. written to the TUN device).

use std::net::Ipv4Addr;

/// Encode an IPv4 address and port into a 32-byte next-hop identifier.
///
/// Format: `[4-byte IPv4][2-byte port BE][26 zero bytes]`
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

/// Decode a 32-byte next-hop identifier into an `(IPv4, port)` pair.
///
/// If the encoded port is 0, `default_port` is used instead.
///
/// Returns an error when the decoded IP is unspecified (`0.0.0.0`),
/// loopback (`127.x.x.x`), broadcast (`255.255.255.255`), or multicast
/// (`224.0.0.0/4`).
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

/// Returns `true` when every byte in the next-hop identifier is zero,
/// indicating that the current node is the exit (final) hop.
pub fn is_exit_hop(next_hop: &[u8; 32]) -> bool {
    next_hop == &[0u8; 32]
}

// ── tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let ip = Ipv4Addr::new(10, 0, 1, 42);
        let port = 51821u16;
        let encoded = encode_next_hop(ip, port);
        let (dec_ip, dec_port) = decode_next_hop(&encoded, 9999).unwrap();
        assert_eq!(dec_ip, ip);
        assert_eq!(dec_port, port);
    }

    #[test]
    fn zero_port_uses_default() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let encoded = encode_next_hop(ip, 0);
        let (_, dec_port) = decode_next_hop(&encoded, 51821).unwrap();
        assert_eq!(dec_port, 51821);
    }

    #[test]
    fn exit_sentinel() {
        assert!(is_exit_hop(&[0u8; 32]));
        assert!(!is_exit_hop(&encode_next_hop(
            Ipv4Addr::new(1, 2, 3, 4),
            80,
        )));
    }

    #[test]
    fn reject_unspecified() {
        // All-zero IP but non-zero port — should still fail validation.
        let mut hop = [0u8; 32];
        hop[4] = 0xCA;
        hop[5] = 0x51;
        assert!(decode_next_hop(&hop, 51821).is_err());
    }

    #[test]
    fn reject_loopback() {
        let encoded = encode_next_hop(Ipv4Addr::new(127, 0, 0, 1), 8080);
        assert!(decode_next_hop(&encoded, 51821).is_err());
    }

    #[test]
    fn reject_broadcast() {
        let encoded = encode_next_hop(Ipv4Addr::new(255, 255, 255, 255), 1234);
        assert!(decode_next_hop(&encoded, 51821).is_err());
    }

    #[test]
    fn reject_multicast() {
        let encoded = encode_next_hop(Ipv4Addr::new(224, 0, 0, 1), 5000);
        assert!(decode_next_hop(&encoded, 51821).is_err());
    }
}
