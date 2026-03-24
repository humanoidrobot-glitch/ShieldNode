use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;

use super::aead;
use super::traits::KeyExchange;
use super::x25519_kem::{X25519Kem, X25519PublicKey, X25519SecretKey};

// ── errors ─────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum NoiseError {
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),
    #[error("encryption error: {0}")]
    Encryption(String),
    #[error("decryption error: {0}")]
    Decryption(String),
    #[error("invalid message length")]
    InvalidLength,
}

// ── handshake state ────────────────────────────────────────────────────

/// Simplified NK-pattern Noise handshake state machine.
///
/// NK pattern (known responder static key):
///   -> e                         (initiator sends ephemeral public)
///   <- e, ee, se                 (responder sends ephemeral, DH results)
///
/// After the handshake both sides share a symmetric session key derived
/// from the DH outputs.
///
/// Uses `KeyExchange` trait types for key storage and generation. The DH
/// operations use KEM encapsulate/decapsulate internally (for X25519, the
/// "ciphertext" is the ephemeral public key). When hybrid PQ is added,
/// it will layer ML-KEM alongside this X25519 Noise handshake.
pub struct NoiseHandshake {
    local_static_sk: X25519SecretKey,
    ephemeral_sk: Option<X25519SecretKey>,
    peer_static_pk: Option<X25519PublicKey>,
    session_key: Option<[u8; 32]>,
}

impl NoiseHandshake {
    pub fn new(local_static: X25519SecretKey) -> Self {
        Self {
            local_static_sk: local_static,
            ephemeral_sk: None,
            peer_static_pk: None,
            session_key: None,
        }
    }

    // ── initiator side ─────────────────────────────────────────────

    /// Initiator step 1: generate an ephemeral keypair and produce the
    /// first message `-> e`.
    ///
    /// `peer_static` is the responder's known static public key.
    /// Returns the 32-byte ephemeral public key to send.
    pub fn initiator_handshake_msg1(&mut self, peer_static: X25519PublicKey) -> [u8; 32] {
        let (eph_pk, eph_sk) = X25519Kem::generate_keypair();
        self.ephemeral_sk = Some(eph_sk);
        self.peer_static_pk = Some(peer_static);
        eph_pk.to_bytes()
    }

    /// Initiator step 2: process the responder's message `<- e, ee, se`
    /// and derive the session key.
    ///
    /// Must be called after `initiator_handshake_msg1`.
    pub fn initiator_handshake_msg2(&mut self, msg: &[u8; 32]) -> Result<[u8; 32], NoiseError> {
        let responder_eph_ct = X25519Kem::ciphertext_from_bytes(msg)
            .map_err(|e| NoiseError::HandshakeFailed(e.to_string()))?;

        let eph_sk = self
            .ephemeral_sk
            .as_ref()
            .ok_or_else(|| NoiseError::HandshakeFailed("no ephemeral key".into()))?;

        // ee = DH(initiator_eph, responder_eph)
        let ee = X25519Kem::decapsulate(&responder_eph_ct, eph_sk)
            .map_err(|e| NoiseError::HandshakeFailed(e.to_string()))?;

        // se = DH(initiator_static, responder_eph)
        let se = X25519Kem::decapsulate(&responder_eph_ct, &self.local_static_sk)
            .map_err(|e| NoiseError::HandshakeFailed(e.to_string()))?;

        let session_key = derive_session_key(&ee.to_bytes(), &se.to_bytes());
        self.session_key = Some(session_key);
        Ok(session_key)
    }

    // ── responder side ─────────────────────────────────────────────

    /// Responder: receive the initiator's `-> e` and produce `<- e, ee, se`.
    ///
    /// Returns `(reply_ephemeral_pub, session_key)`.
    pub fn responder_handshake(
        &mut self,
        initiator_eph_bytes: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 32]), NoiseError> {
        let initiator_eph_ct = X25519Kem::ciphertext_from_bytes(initiator_eph_bytes)
            .map_err(|e| NoiseError::HandshakeFailed(e.to_string()))?;

        let (eph_pk, eph_sk) = X25519Kem::generate_keypair();

        // ee = DH(responder_eph, initiator_eph)
        let ee = X25519Kem::decapsulate(&initiator_eph_ct, &eph_sk)
            .map_err(|e| NoiseError::HandshakeFailed(e.to_string()))?;

        // se = DH(responder_static, initiator_eph) — mirrors the
        // initiator's DH(initiator_static, responder_eph) by commutativity.
        let se = X25519Kem::decapsulate(&initiator_eph_ct, &self.local_static_sk)
            .map_err(|e| NoiseError::HandshakeFailed(e.to_string()))?;

        let session_key = derive_session_key(&ee.to_bytes(), &se.to_bytes());
        self.ephemeral_sk = Some(eph_sk);
        self.session_key = Some(session_key);

        Ok((eph_pk.to_bytes(), session_key))
    }

    pub fn session_key(&self) -> Option<[u8; 32]> {
        self.session_key
    }
}

// ── helpers ────────────────────────────────────────────────────────────

/// Derive a 32-byte session key from two DH outputs using HKDF-SHA256.
fn derive_session_key(ee: &[u8; 32], se: &[u8; 32]) -> [u8; 32] {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(ee);
    ikm[32..].copy_from_slice(se);

    let hk = Hkdf::<Sha256>::new(Some(b"ShieldNode-NK-v1"), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(b"session-key", &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

/// Encrypt `plaintext` with the given ChaCha20-Poly1305 key and nonce.
pub fn encrypt(key: &[u8; 32], nonce_val: u64, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
    aead::encrypt(key, nonce_val, plaintext).map_err(|e| NoiseError::Encryption(e.to_string()))
}

/// Decrypt `ciphertext` with the given ChaCha20-Poly1305 key and nonce.
pub fn decrypt(key: &[u8; 32], nonce_val: u64, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
    aead::decrypt(key, nonce_val, ciphertext).map_err(|e| NoiseError::Decryption(e.to_string()))
}
