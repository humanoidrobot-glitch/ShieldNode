//! Shared control message type registry.
//!
//! Defines all control message discriminants used across the relay protocol
//! and Sphinx-layer control channels. Having a single registry prevents
//! accidental collisions if messages ever share a transport.

/// Relay-level control messages (sent on session_id 0).
///
/// These are 1-byte discriminants at the start of a control message payload.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayControlType {
    /// Register a new relay session (session key + hop index).
    SessionSetup = 0x01,
    /// Tear down an existing relay session.
    SessionTeardown = 0x02,
    /// Request a co-signature on a bandwidth receipt.
    ReceiptSign = 0x03,
}

impl RelayControlType {
    /// Try to parse a byte into a relay control type.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::SessionSetup),
            0x02 => Some(Self::SessionTeardown),
            0x03 => Some(Self::ReceiptSign),
            _ => None,
        }
    }
}

/// Sphinx-layer control message magic bytes (4-byte prefix).
///
/// These identify control messages embedded within Sphinx payloads,
/// distinguished from data packets by their magic prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SphinxControlMagic {
    /// Ratchet epoch advancement ("RATC").
    RatchetStep,
    /// Inter-node link padding ("PADD").
    LinkPadding,
}

impl SphinxControlMagic {
    pub const RATCHET_BYTES: [u8; 4] = [0x52, 0x41, 0x54, 0x43]; // "RATC"
    pub const PADDING_BYTES: [u8; 4] = [0x50, 0x41, 0x44, 0x44]; // "PADD"

    /// Try to identify a Sphinx control message from its first 4 bytes.
    pub fn from_bytes(header: &[u8]) -> Option<Self> {
        if header.len() < 4 {
            return None;
        }
        match &header[..4] {
            b if b == Self::RATCHET_BYTES => Some(Self::RatchetStep),
            b if b == Self::PADDING_BYTES => Some(Self::LinkPadding),
            _ => None,
        }
    }

    /// Get the 4-byte magic for this control type.
    pub fn as_bytes(self) -> [u8; 4] {
        match self {
            Self::RatchetStep => Self::RATCHET_BYTES,
            Self::LinkPadding => Self::PADDING_BYTES,
        }
    }
}

/// ACK response bytes for relay control messages.
pub const ACK_SUCCESS: u8 = 0x01;
pub const ACK_FAILURE: u8 = 0x00;

/// Expected payload lengths for relay control messages (after the type byte).
pub mod payload_len {
    /// SESSION_SETUP: 8 (session_id) + 32 (session_key) + 8 (hop_index) = 48
    pub const SESSION_SETUP: usize = 8 + 32 + 8;
    /// SESSION_TEARDOWN: 8 (session_id)
    pub const SESSION_TEARDOWN: usize = 8;
    /// RECEIPT_SIGN: 8 (session_id) + 8 (cumulative_bytes) + 8 (timestamp) + 65 (client_sig) = 89
    pub const RECEIPT_SIGN: usize = 8 + 8 + 8 + 65;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_control_roundtrip() {
        assert_eq!(RelayControlType::from_byte(0x01), Some(RelayControlType::SessionSetup));
        assert_eq!(RelayControlType::from_byte(0x02), Some(RelayControlType::SessionTeardown));
        assert_eq!(RelayControlType::from_byte(0x03), Some(RelayControlType::ReceiptSign));
        assert_eq!(RelayControlType::from_byte(0x00), None);
        assert_eq!(RelayControlType::from_byte(0xFF), None);
    }

    #[test]
    fn sphinx_magic_roundtrip() {
        assert_eq!(SphinxControlMagic::from_bytes(&[0x52, 0x41, 0x54, 0x43]), Some(SphinxControlMagic::RatchetStep));
        assert_eq!(SphinxControlMagic::from_bytes(&[0x50, 0x41, 0x44, 0x44]), Some(SphinxControlMagic::LinkPadding));
        assert_eq!(SphinxControlMagic::from_bytes(&[0x00, 0x00, 0x00, 0x00]), None);
        assert_eq!(SphinxControlMagic::from_bytes(&[0x52, 0x41]), None); // too short
    }

    #[test]
    fn sphinx_magic_as_bytes() {
        assert_eq!(SphinxControlMagic::RatchetStep.as_bytes(), [0x52, 0x41, 0x54, 0x43]);
        assert_eq!(SphinxControlMagic::LinkPadding.as_bytes(), [0x50, 0x41, 0x44, 0x44]);
    }

    #[test]
    fn no_discriminant_collisions() {
        // Relay discriminants must not overlap with the first byte of any magic.
        let relay_bytes: Vec<u8> = vec![0x01, 0x02, 0x03];
        let magic_first_bytes: Vec<u8> = vec![
            SphinxControlMagic::RATCHET_BYTES[0], // 0x52
            SphinxControlMagic::PADDING_BYTES[0],  // 0x50
        ];

        for r in &relay_bytes {
            assert!(!magic_first_bytes.contains(r), "collision between relay 0x{r:02x} and magic first byte");
        }
    }
}
