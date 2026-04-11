//! NAT flow table for routing TUN responses back to the correct session.
//!
//! When the exit node writes an outbound packet to TUN, it records a mapping
//! from the packet's flow (dst_ip, dst_port, protocol) to the session_id.
//! When the TUN response arrives, the flow is reversed (src becomes remote)
//! and the session_id is looked up.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// Maximum age of a NAT entry before eviction.
const NAT_ENTRY_TTL: Duration = Duration::from_secs(300); // 5 minutes

/// Maximum number of NAT entries before forced eviction of oldest.
const MAX_NAT_ENTRIES: usize = 65536;

/// A flow identifier for NAT tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub remote_ip: Ipv4Addr,
    pub remote_port: u16,
    pub local_port: u16,
    pub protocol: u8,
}

struct NatEntry {
    session_id: u64,
    last_seen: Instant,
}

/// Maps outbound IP flows to relay session IDs.
pub struct NatTable {
    entries: HashMap<FlowKey, NatEntry>,
}

impl NatTable {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Record a NAT mapping for an outbound packet.
    pub fn insert(&mut self, key: FlowKey, session_id: u64) {
        if self.entries.len() >= MAX_NAT_ENTRIES {
            self.evict_stale();
        }
        self.entries.insert(key, NatEntry {
            session_id,
            last_seen: Instant::now(),
        });
    }

    /// Look up the session_id for an inbound response packet.
    pub fn lookup(&self, key: &FlowKey) -> Option<u64> {
        self.entries.get(key).and_then(|e| {
            if e.last_seen.elapsed() < NAT_ENTRY_TTL {
                Some(e.session_id)
            } else {
                None
            }
        })
    }

    /// Remove expired entries.
    fn evict_stale(&mut self) {
        self.entries.retain(|_, e| e.last_seen.elapsed() < NAT_ENTRY_TTL);
    }
}

impl Default for NatTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract a flow key from an IP packet (for outbound: use dst as remote).
/// Returns None for non-IPv4 or non-TCP/UDP packets.
pub fn extract_outbound_flow(packet: &[u8]) -> Option<FlowKey> {
    if packet.len() < 20 {
        return None;
    }
    let version = packet[0] >> 4;
    if version != 4 {
        return None; // IPv6 not supported yet
    }
    let ihl = (packet[0] & 0x0F) as usize * 4;
    let protocol = packet[9];
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

    // TCP (6) or UDP (17) — extract ports from transport header.
    if (protocol == 6 || protocol == 17) && packet.len() >= ihl + 4 {
        let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
        let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
        Some(FlowKey {
            remote_ip: dst_ip,
            remote_port: dst_port,
            local_port: src_port,
            protocol,
        })
    } else {
        // ICMP or other — use port 0.
        Some(FlowKey {
            remote_ip: dst_ip,
            remote_port: 0,
            local_port: 0,
            protocol,
        })
    }
}

/// Extract a flow key from a TUN response packet (for inbound: use src as remote).
pub fn extract_inbound_flow(packet: &[u8]) -> Option<FlowKey> {
    if packet.len() < 20 {
        return None;
    }
    let version = packet[0] >> 4;
    if version != 4 {
        return None;
    }
    let ihl = (packet[0] & 0x0F) as usize * 4;
    let protocol = packet[9];
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);

    if (protocol == 6 || protocol == 17) && packet.len() >= ihl + 4 {
        let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
        let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
        Some(FlowKey {
            remote_ip: src_ip,
            remote_port: src_port,
            local_port: dst_port,
            protocol,
        })
    } else {
        Some(FlowKey {
            remote_ip: src_ip,
            remote_port: 0,
            local_port: 0,
            protocol,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_lookup() {
        let mut table = NatTable::new();
        let key = FlowKey {
            remote_ip: Ipv4Addr::new(93, 184, 216, 34),
            remote_port: 443,
            local_port: 12345,
            protocol: 6,
        };
        table.insert(key, 42);
        assert_eq!(table.lookup(&key), Some(42));
    }

    #[test]
    fn unknown_flow_returns_none() {
        let table = NatTable::new();
        let key = FlowKey {
            remote_ip: Ipv4Addr::new(1, 1, 1, 1),
            remote_port: 53,
            local_port: 9999,
            protocol: 17,
        };
        assert_eq!(table.lookup(&key), None);
    }
}
