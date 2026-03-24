use crate::aead;

/// A Sphinx-like onion packet (client-side, creation only).
///
/// Wire format: `[32-byte next_hop][4-byte payload_len BE][payload]`
pub struct SphinxPacket {
    pub next_hop: [u8; 32],
    pub payload: Vec<u8>,
}

impl SphinxPacket {
    /// Build an onion packet that traverses `route` carrying `plaintext`.
    ///
    /// `route` is an ordered list of `(next_hop_encoding, session_key)` pairs
    /// from entry hop to exit hop.  Each `session_key` is a 32-byte symmetric
    /// key previously negotiated with that hop.
    ///
    /// The packet is wrapped from the inside out: the exit hop's layer is
    /// encrypted first, then the relay's, then the entry's.
    pub fn create(route: &[([u8; 32], [u8; 32])], plaintext: &[u8]) -> Result<Self, String> {
        if route.is_empty() {
            return Err("route must have at least one hop".to_string());
        }

        let mut current_payload = plaintext.to_vec();
        let mut next_hop = [0u8; 32]; // final hop has no successor

        for (i, (pub_key, session_key)) in route.iter().enumerate().rev() {
            // Prepend the next_hop to the current payload before encrypting.
            let mut layer_plaintext = Vec::with_capacity(32 + current_payload.len());
            layer_plaintext.extend_from_slice(&next_hop);
            layer_plaintext.extend_from_slice(&current_payload);

            current_payload = aead::encrypt(session_key, i as u64, &layer_plaintext)
                .map_err(|e| format!("encryption failed at hop {i}: {e}"))?;

            next_hop = *pub_key;
        }

        Ok(Self {
            next_hop: route[0].0,
            payload: current_payload,
        })
    }

    /// Serialize to bytes: `[32-byte next_hop][4-byte payload_len BE][payload]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let payload_len = self.payload.len() as u32;
        let mut buf = Vec::with_capacity(32 + 4 + self.payload.len());
        buf.extend_from_slice(&self.next_hop);
        buf.extend_from_slice(&payload_len.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }
}
