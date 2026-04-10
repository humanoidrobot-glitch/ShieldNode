use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::aead;
use crate::kex::{HybridKem, HybridPublicKey, KeyExchange};

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

        let mac = compute_mac(&route[0].1, 0, &next_hop, &current_payload);

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

fn compute_mac(session_key: &[u8; 32], hop_index: u8, next_hop: &[u8; 32], payload: &[u8]) -> [u8; 32] {
    let mut hmac = HmacSha256::new_from_slice(session_key)
        .expect("HMAC accepts any key length");
    hmac.update(&[hop_index]); // bind MAC to hop position (prevents replay across hops)
    hmac.update(next_hop);
    hmac.update(payload);
    let result = hmac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// ── PQ Sphinx (client-side, creation only) ────────────────────────────

/// Version byte for PQ Sphinx packets.
pub const PQ_SPHINX_VERSION: u8 = 0xFF;

/// Pre-computed KEM state for one hop.
pub struct PqHopKeys {
    pub next_hop: [u8; 32],
    pub kem_ciphertext: Vec<u8>,
    pub layer_key: [u8; 32],
}

/// Pre-computed KEM state for a full PQ Sphinx circuit.
pub struct PqSessionKeys {
    pub hops: Vec<PqHopKeys>,
}

impl PqSessionKeys {
    /// Compute KEM encapsulations for each hop.
    /// `route` is ordered entry → exit: `(hop_public_key, next_hop_encoding)`.
    pub fn new(route: &[(HybridPublicKey, [u8; 32])]) -> Result<Self, String> {
        let mut hops = Vec::with_capacity(route.len());
        for (hop_pk, next_hop) in route {
            let (shared_secret, ciphertext) = HybridKem::encapsulate(hop_pk)?;
            let layer_key = pq_derive_layer_key(shared_secret.as_ref());
            hops.push(PqHopKeys {
                next_hop: *next_hop,
                kem_ciphertext: ciphertext.as_ref().to_vec(),
                layer_key,
            });
        }
        Ok(Self { hops })
    }
}

/// A PQ Sphinx onion packet (client-side, creation + serialization only).
pub struct PqSphinxPacket {
    pub next_hop: [u8; 32],
    pub kem_ciphertext: Vec<u8>,
    pub mac: [u8; 32],
    pub encrypted_blob: Vec<u8>,
}

impl PqSphinxPacket {
    /// Build a PQ Sphinx onion packet using pre-computed session keys.
    pub fn create(session: &PqSessionKeys, plaintext: &[u8]) -> Result<Self, String> {
        if session.hops.is_empty() {
            return Err("route must have at least one hop".to_string());
        }

        let mut current_blob = plaintext.to_vec();

        for (i, hop) in session.hops.iter().enumerate().rev() {
            let layer_plaintext = if i < session.hops.len() - 1 {
                let inner = &session.hops[i + 1];
                pq_serialize(
                    &inner.next_hop,
                    &inner.kem_ciphertext,
                    &pq_compute_mac(&inner.layer_key, (i + 1) as u8, &inner.next_hop, &inner.kem_ciphertext, &current_blob),
                    &current_blob,
                )
            } else {
                current_blob
            };

            current_blob = aead::encrypt_with_nonce(&hop.layer_key, &pq_nonce(i), &layer_plaintext)
                .map_err(|e| format!("PQ encrypt failed at hop {i}: {e}"))?;
        }

        let hop0 = &session.hops[0];
        let mac = pq_compute_mac(&hop0.layer_key, 0, &hop0.next_hop, &hop0.kem_ciphertext, &current_blob);

        Ok(Self {
            next_hop: hop0.next_hop,
            kem_ciphertext: hop0.kem_ciphertext.clone(),
            mac,
            encrypted_blob: current_blob,
        })
    }

    /// Serialize with PQ version prefix.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 32 + self.kem_ciphertext.len() + 32 + 4 + self.encrypted_blob.len());
        buf.push(PQ_SPHINX_VERSION);
        buf.extend_from_slice(&self.next_hop);
        buf.extend_from_slice(&self.kem_ciphertext);
        buf.extend_from_slice(&self.mac);
        buf.extend_from_slice(&(self.encrypted_blob.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.encrypted_blob);
        buf
    }
}

fn pq_derive_layer_key(shared_secret: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"shieldnode-pq-sphinx-v1"), shared_secret);
    let mut key = [0u8; 32];
    hk.expand(b"layer-key", &mut key)
        .expect("32 bytes is valid HKDF output");
    key
}

fn pq_nonce(hop_index: usize) -> [u8; 12] {
    aead::nonce_from_index(hop_index as u64)
}

fn pq_compute_mac(
    layer_key: &[u8; 32],
    hop_index: u8,
    next_hop: &[u8; 32],
    kem_ciphertext: &[u8],
    encrypted_blob: &[u8],
) -> [u8; 32] {
    let mut hmac = HmacSha256::new_from_slice(layer_key)
        .expect("HMAC accepts any key length");
    hmac.update(&[hop_index]);
    hmac.update(next_hop);
    hmac.update(kem_ciphertext);
    hmac.update(encrypted_blob);
    let result = hmac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn pq_serialize(
    next_hop: &[u8; 32],
    kem_ciphertext: &[u8],
    mac: &[u8; 32],
    encrypted_blob: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + kem_ciphertext.len() + 32 + 4 + encrypted_blob.len());
    buf.extend_from_slice(next_hop);
    buf.extend_from_slice(kem_ciphertext);
    buf.extend_from_slice(mac);
    buf.extend_from_slice(&(encrypted_blob.len() as u32).to_be_bytes());
    buf.extend_from_slice(encrypted_blob);
    buf
}
