use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use thiserror::Error;

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
}

// ── header + packet ────────────────────────────────────────────────────

/// Per-hop header prepended to the onion payload.
#[derive(Clone, Debug)]
pub struct SphinxHeader {
    /// Next hop's 32-byte public key (or all-zero for the final hop).
    pub next_hop: [u8; 32],
    /// Encrypted routing info blob (encrypted under this hop's session key).
    pub routing_info: Vec<u8>,
    /// HMAC / authentication tag for integrity (here we rely on the AEAD
    /// tag inside `routing_info`, so this field carries an extra binding
    /// tag derived from the payload).
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
    pub fn create(
        route: &[([u8; 32], [u8; 32])], // (public_key, session_key)
        plaintext: &[u8],
    ) -> Result<Self, SphinxError> {
        if route.is_empty() {
            return Err(SphinxError::EmptyRoute);
        }

        // Start from the innermost layer (last hop) and work outward.
        let mut current_payload = plaintext.to_vec();
        let mut next_hop = [0u8; 32]; // final hop has no successor

        for (i, (pub_key, session_key)) in route.iter().enumerate().rev() {
            // Prepend the next_hop address to the payload so the current
            // hop knows where to send the inner packet.
            let mut layer_plaintext = Vec::with_capacity(32 + current_payload.len());
            layer_plaintext.extend_from_slice(&next_hop);
            layer_plaintext.extend_from_slice(&current_payload);

            let cipher = ChaCha20Poly1305::new_from_slice(session_key)
                .map_err(|e| SphinxError::EncryptionFailed(e.to_string()))?;

            // Nonce: we use the hop index (little-endian) padded to 12 bytes.
            // A production system would use a counter or random nonce
            // communicated out-of-band.
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let nonce = Nonce::from(nonce_bytes);

            let ciphertext = cipher
                .encrypt(&nonce, layer_plaintext.as_ref())
                .map_err(|e| SphinxError::EncryptionFailed(e.to_string()))?;

            // After encryption, `current_payload` becomes the ciphertext;
            // `next_hop` shifts to *this* hop's public key so the
            // previous hop can direct traffic here.
            current_payload = ciphertext;
            next_hop = *pub_key;
        }

        // The outermost header is addressed to the first hop.
        let mac = {
            let mut m = [0u8; 32];
            // Simple binding: first 32 bytes of payload hash (placeholder).
            // A real Sphinx uses a proper HMAC over the header.
            if current_payload.len() >= 32 {
                m.copy_from_slice(&current_payload[..32]);
            }
            m
        };

        Ok(Self {
            header: SphinxHeader {
                next_hop: route[0].0,
                routing_info: Vec::new(), // all routing info is inside the
                // encrypted layers
                mac,
            },
            payload: current_payload,
        })
    }

    /// Peel one onion layer using `session_key` for this hop.
    ///
    /// Returns `(next_hop_public_key, inner_packet)`.  If `next_hop` is
    /// all zeros, this node is the final destination and `inner_packet`
    /// carries the cleartext payload.
    pub fn peel_layer(
        &self,
        session_key: &[u8; 32],
        hop_index: u64,
    ) -> Result<([u8; 32], SphinxPacket), SphinxError> {
        let cipher = ChaCha20Poly1305::new_from_slice(session_key)
            .map_err(|e| SphinxError::DecryptionFailed(e.to_string()))?;

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&hop_index.to_le_bytes());
        let nonce = Nonce::from(nonce_bytes);

        let decrypted = cipher
            .decrypt(&nonce, self.payload.as_ref())
            .map_err(|e| SphinxError::DecryptionFailed(e.to_string()))?;

        if decrypted.len() < 32 {
            return Err(SphinxError::MalformedHeader);
        }

        let mut next_hop = [0u8; 32];
        next_hop.copy_from_slice(&decrypted[..32]);
        let inner_payload = decrypted[32..].to_vec();

        let inner_mac = {
            let mut m = [0u8; 32];
            if inner_payload.len() >= 32 {
                m.copy_from_slice(&inner_payload[..32]);
            }
            m
        };

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
}
