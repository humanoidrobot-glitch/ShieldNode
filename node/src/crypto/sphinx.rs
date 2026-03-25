use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;

use super::aead;

type HmacSha256 = Hmac<Sha256>;

// ── errors ─────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum SphinxError {
    #[error("route must have at least one hop")]
    EmptyRoute,
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("malformed header")]
    MalformedHeader,
    #[error("MAC verification failed")]
    MacVerificationFailed,
}

// ── header + packet ────────────────────────────────────────────────────

/// Per-hop header prepended to the onion payload.
#[derive(Clone, Debug)]
pub struct SphinxHeader {
    pub next_hop: [u8; 32],
    pub routing_info: Vec<u8>,
    /// HMAC-SHA256 over (next_hop || payload), keyed by the session key.
    pub mac: [u8; 32],
}

/// A Sphinx-like onion packet.
#[derive(Clone, Debug)]
pub struct SphinxPacket {
    pub header: SphinxHeader,
    pub payload: Vec<u8>,
}

impl SphinxPacket {
    /// Build an onion packet that traverses `route` carrying `plaintext`.
    ///
    /// `route` is an ordered list of (public_key, session_key) pairs from
    /// first hop to last.  Each `session_key` is a 32-byte symmetric key
    /// previously negotiated (e.g. via DH) with that hop.
    pub fn create(route: &[([u8; 32], [u8; 32])], plaintext: &[u8]) -> Result<Self, SphinxError> {
        if route.is_empty() {
            return Err(SphinxError::EmptyRoute);
        }

        let mut current_payload = plaintext.to_vec();
        let mut next_hop = [0u8; 32]; // final hop has no successor

        for (i, (pub_key, session_key)) in route.iter().enumerate().rev() {
            let mut layer_plaintext = Vec::with_capacity(32 + current_payload.len());
            layer_plaintext.extend_from_slice(&next_hop);
            layer_plaintext.extend_from_slice(&current_payload);

            current_payload = aead::encrypt(session_key, i as u64, &layer_plaintext)
                .map_err(|e| SphinxError::EncryptionFailed(e.to_string()))?;

            next_hop = *pub_key;
        }

        let mac = compute_mac(&route[0].1, &next_hop, &current_payload);

        Ok(Self {
            header: SphinxHeader {
                next_hop: route[0].0,
                routing_info: Vec::new(),
                mac,
            },
            payload: current_payload,
        })
    }

    /// Peel one onion layer using `session_key` for this hop.
    ///
    /// Verifies the HMAC before decrypting. Returns `(next_hop_public_key,
    /// inner_packet)`. If `next_hop` is all zeros, this node is the final
    /// destination.
    pub fn peel_layer(
        &self,
        session_key: &[u8; 32],
        hop_index: u64,
    ) -> Result<([u8; 32], SphinxPacket), SphinxError> {
        // Verify MAC before decrypting.
        verify_mac(session_key, &self.header.next_hop, &self.payload, &self.header.mac)?;

        let decrypted = aead::decrypt(session_key, hop_index, &self.payload)
            .map_err(|e| SphinxError::DecryptionFailed(e.to_string()))?;

        if decrypted.len() < 32 {
            return Err(SphinxError::MalformedHeader);
        }

        let mut next_hop = [0u8; 32];
        next_hop.copy_from_slice(&decrypted[..32]);
        let inner_payload = decrypted[32..].to_vec();

        // Compute MAC for the inner packet using the same session key.
        // The next hop will verify with its own session key.
        let inner_mac = compute_mac(session_key, &next_hop, &inner_payload);

        let inner_packet = SphinxPacket {
            header: SphinxHeader {
                next_hop,
                routing_info: Vec::new(),
                mac: inner_mac,
            },
            payload: inner_payload,
        };

        Ok((next_hop, inner_packet))
    }

    // ── serialisation ──────────────────────────────────────────────────

    /// Serialize this packet to bytes:
    /// `[32-byte next_hop][32-byte mac][4-byte payload_len (BE)][payload]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let payload_len = self.payload.len() as u32;
        let mut buf = Vec::with_capacity(32 + 32 + 4 + self.payload.len());
        buf.extend_from_slice(&self.header.next_hop);
        buf.extend_from_slice(&self.header.mac);
        buf.extend_from_slice(&payload_len.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Deserialize a packet from bytes produced by [`to_bytes`].
    pub fn from_bytes(data: &[u8]) -> Result<Self, SphinxError> {
        // 32 (next_hop) + 32 (mac) + 4 (len) = 68 minimum
        if data.len() < 68 {
            return Err(SphinxError::MalformedHeader);
        }

        let mut next_hop = [0u8; 32];
        next_hop.copy_from_slice(&data[..32]);

        let mut mac = [0u8; 32];
        mac.copy_from_slice(&data[32..64]);

        let payload_len = u32::from_be_bytes(
            data[64..68].try_into().map_err(|_| SphinxError::MalformedHeader)?
        ) as usize;

        if data.len() < 68 + payload_len {
            return Err(SphinxError::MalformedHeader);
        }

        let payload = data[68..68 + payload_len].to_vec();

        Ok(Self {
            header: SphinxHeader {
                next_hop,
                routing_info: Vec::new(),
                mac,
            },
            payload,
        })
    }
}

/// Compute HMAC-SHA256 over (next_hop || payload) using session_key.
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

/// Verify HMAC-SHA256 over (next_hop || payload).
fn verify_mac(
    session_key: &[u8; 32],
    next_hop: &[u8; 32],
    payload: &[u8],
    expected: &[u8; 32],
) -> Result<(), SphinxError> {
    let computed = compute_mac(session_key, next_hop, payload);
    // Constant-time comparison via HMAC verify.
    let mut hmac = HmacSha256::new_from_slice(session_key)
        .expect("HMAC accepts any key length");
    hmac.update(next_hop);
    hmac.update(payload);
    hmac.verify_slice(expected)
        .map_err(|_| SphinxError::MacVerificationFailed)
}
