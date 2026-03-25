use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::aead;

type HmacSha256 = Hmac<Sha256>;

/// A Sphinx-like onion packet (client-side, creation only).
///
/// Wire format: `[32-byte next_hop][32-byte mac][4-byte payload_len BE][payload]`
pub struct SphinxPacket {
    pub next_hop: [u8; 32],
    pub mac: [u8; 32],
    pub payload: Vec<u8>,
}

impl SphinxPacket {
    /// Build an onion packet that traverses `route` carrying `plaintext`.
    pub fn create(route: &[([u8; 32], [u8; 32])], plaintext: &[u8]) -> Result<Self, String> {
        if route.is_empty() {
            return Err("route must have at least one hop".to_string());
        }

        let mut current_payload = plaintext.to_vec();
        let mut next_hop = [0u8; 32];

        for (i, (pub_key, session_key)) in route.iter().enumerate().rev() {
            let mut layer_plaintext = Vec::with_capacity(32 + current_payload.len());
            layer_plaintext.extend_from_slice(&next_hop);
            layer_plaintext.extend_from_slice(&current_payload);

            current_payload = aead::encrypt(session_key, i as u64, &layer_plaintext)
                .map_err(|e| format!("encryption failed at hop {i}: {e}"))?;

            next_hop = *pub_key;
        }

        let mac = compute_mac(&route[0].1, &next_hop, &current_payload);

        Ok(Self {
            next_hop: route[0].0,
            mac,
            payload: current_payload,
        })
    }

    /// Serialize to bytes: `[32-byte next_hop][32-byte mac][4-byte payload_len BE][payload]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let payload_len = self.payload.len() as u32;
        let mut buf = Vec::with_capacity(32 + 32 + 4 + self.payload.len());
        buf.extend_from_slice(&self.next_hop);
        buf.extend_from_slice(&self.mac);
        buf.extend_from_slice(&payload_len.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }
}

fn compute_mac(session_key: &[u8; 32], next_hop: &[u8; 32], payload: &[u8]) -> [u8; 32] {
    let mut hmac = HmacSha256::new_from_slice(session_key)
        .expect("HMAC accepts any key length");
    hmac.update(next_hop);
    hmac.update(payload);
    let result = hmac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}
