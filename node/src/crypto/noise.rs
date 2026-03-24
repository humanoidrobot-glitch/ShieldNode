use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

use super::aead;

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
pub struct NoiseHandshake {
    local_static: StaticSecret,
    ephemeral_secret: Option<StaticSecret>,
    peer_static_public: Option<PublicKey>,
    session_key: Option<[u8; 32]>,
}

impl NoiseHandshake {
    pub fn new(local_static: StaticSecret) -> Self {
        Self {
            local_static,
            ephemeral_secret: None,
            peer_static_public: None,
            session_key: None,
        }
    }

    // ── initiator side ─────────────────────────────────────────────

    /// Initiator step 1: generate an ephemeral keypair and produce the
    /// first message `-> e`.
    ///
    /// `peer_static` is the responder's known static public key.
    /// Returns the 32-byte ephemeral public key to send.
    pub fn initiator_handshake_msg1(
        &mut self,
        peer_static: PublicKey,
    ) -> [u8; 32] {
        let eph = StaticSecret::random_from_rng(OsRng);
        let eph_pub = PublicKey::from(&eph);
        self.ephemeral_secret = Some(eph);
        self.peer_static_public = Some(peer_static);
        eph_pub.to_bytes()
    }

    /// Initiator step 2: process the responder's message `<- e, ee, se`
    /// and derive the session key.
    ///
    /// Must be called after `initiator_handshake_msg1`.
    pub fn initiator_handshake_msg2(
        &mut self,
        msg: &[u8; 32],
    ) -> Result<[u8; 32], NoiseError> {
        let responder_eph = PublicKey::from(*msg);

        let eph_secret = self
            .ephemeral_secret
            .as_ref()
            .ok_or_else(|| NoiseError::HandshakeFailed("no ephemeral key".into()))?;

        let ee = eph_secret.diffie_hellman(&responder_eph).to_bytes();
        let se = self
            .local_static
            .diffie_hellman(&responder_eph)
            .to_bytes();

        let session_key = derive_session_key(&ee, &se);
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
        let initiator_eph = PublicKey::from(*initiator_eph_bytes);

        let eph = StaticSecret::random_from_rng(OsRng);
        let eph_pub = PublicKey::from(&eph);

        let ee = eph.diffie_hellman(&initiator_eph).to_bytes();
        // se = DH(responder_static, initiator_eph) — mirrors the
        // initiator's DH(initiator_static, responder_eph) by commutativity.
        let se = self
            .local_static
            .diffie_hellman(&initiator_eph)
            .to_bytes();

        let session_key = derive_session_key(&ee, &se);
        self.ephemeral_secret = Some(eph);
        self.session_key = Some(session_key);

        Ok((eph_pub.to_bytes(), session_key))
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
pub fn encrypt(
    key: &[u8; 32],
    nonce_val: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, NoiseError> {
    aead::encrypt(key, nonce_val, plaintext)
        .map_err(|e| NoiseError::Encryption(e.to_string()))
}

/// Decrypt `ciphertext` with the given ChaCha20-Poly1305 key and nonce.
pub fn decrypt(
    key: &[u8; 32],
    nonce_val: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>, NoiseError> {
    aead::decrypt(key, nonce_val, ciphertext)
        .map_err(|e| NoiseError::Decryption(e.to_string()))
}
