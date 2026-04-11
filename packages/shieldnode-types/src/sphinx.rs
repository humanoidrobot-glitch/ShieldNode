//! Sphinx packet MAC computation and PQ layer key derivation.
//!
//! Shared between node (which peels layers) and client (which creates packets).
//! Full packet types stay in their respective crates due to asymmetric APIs
//! (node: peel_layer, client: create).

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::aead;
use crate::kdf::hkdf_sha256;

type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256 MAC over `[hop_index || next_hop || payload]`.
///
/// Binds the MAC to the hop position to prevent replay across hops.
pub fn compute_mac(
    session_key: &[u8; 32],
    hop_index: u8,
    next_hop: &[u8; 32],
    payload: &[u8],
) -> [u8; 32] {
    let mut hmac = HmacSha256::new_from_slice(session_key)
        .expect("HMAC accepts any key length");
    hmac.update(&[hop_index]);
    hmac.update(next_hop);
    hmac.update(payload);
    let result = hmac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Derive a layer encryption key from a shared secret (PQ Sphinx).
pub fn pq_derive_layer_key(shared_secret: &[u8]) -> [u8; 32] {
    hkdf_sha256::<32>(
        Some(b"shieldnode-pq-sphinx-v1"),
        shared_secret,
        b"layer-key",
    )
}

/// Build a 12-byte nonce for a PQ Sphinx hop.
pub fn pq_nonce(hop_index: usize) -> [u8; 12] {
    aead::nonce_from_index(hop_index as u64)
}

/// Compute HMAC-SHA256 MAC for PQ Sphinx packets.
///
/// Covers `[hop_index || next_hop || kem_ciphertext || encrypted_blob]`.
pub fn pq_compute_mac(
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

/// PQ Sphinx version byte for wire-level dispatch.
pub const PQ_SPHINX_VERSION: u8 = 0xFF;
