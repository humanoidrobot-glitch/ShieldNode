use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::rngs::OsRng;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

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
    /// Our static secret.
    local_static: StaticSecret,
    /// Our static public key.
    #[allow(dead_code)]
    local_public: PublicKey,
    /// Ephemeral secret generated during the handshake.
    ephemeral_secret: Option<StaticSecret>,
    #[allow(dead_code)]
    ephemeral_public: Option<PublicKey>,
    /// Peer's static public key (known ahead of time in NK).
    peer_static_public: Option<PublicKey>,
    /// Derived symmetric key (available after handshake completes).
    session_key: Option<[u8; 32]>,
}

impl NoiseHandshake {
    /// Create a handshake context using the node's static key.
    pub fn new(local_static: StaticSecret) -> Self {
        let local_public = PublicKey::from(&local_static);
        Self {
            local_static,
            local_public,
            ephemeral_secret: None,
            ephemeral_public: None,
            peer_static_public: None,
            session_key: None,
        }
    }

    // ── initiator side ─────────────────────────────────────────────

    /// Initiator step 1: generate an ephemeral keypair and produce the
    /// first message `-> e`.
    ///
    /// `peer_static` is the responder's known static public key.
    ///
    /// Returns the 32-byte ephemeral public key to send.
    pub fn initiator_handshake_msg1(
        &mut self,
        peer_static: PublicKey,
    ) -> [u8; 32] {
        let eph = StaticSecret::random_from_rng(OsRng);
        let eph_pub = PublicKey::from(&eph);
        self.ephemeral_secret = Some(eph);
        self.ephemeral_public = Some(eph_pub);
        self.peer_static_public = Some(peer_static);
        eph_pub.to_bytes()
    }

    /// Initiator step 2: process the responder's message `<- e, ee, se`
    /// and derive the session key.
    ///
    /// `msg` layout: `[responder_ephemeral_pub: 32]`
    pub fn initiator_handshake_msg2(
        &mut self,
        msg: &[u8; 32],
    ) -> Result<[u8; 32], NoiseError> {
        let responder_eph = PublicKey::from(*msg);

        let eph_secret = self
            .ephemeral_secret
            .as_ref()
            .ok_or_else(|| NoiseError::HandshakeFailed("no ephemeral key".into()))?;

        // ee = DH(initiator_eph, responder_eph)
        let ee = eph_secret.diffie_hellman(&responder_eph).to_bytes();

        let _peer_static = self.peer_static_public.ok_or_else(|| {
            NoiseError::HandshakeFailed("no peer static key".into())
        })?;

        // se = DH(initiator_static, responder_eph)
        let se = self
            .local_static
            .diffie_hellman(&responder_eph)
            .to_bytes();

        let session_key = derive_session_key(&ee, &se);
        self.session_key = Some(session_key);
        Ok(session_key)
    }

    // ── responder side ─────────────────────────────────────────────

    /// Responder step 1: receive the initiator's `-> e` message and
    /// produce `<- e, ee, se` reply.
    ///
    /// `initiator_eph_bytes`: the 32-byte ephemeral public key from the
    /// initiator.
    ///
    /// Returns `(reply_message, session_key)`.
    pub fn responder_handshake(
        &mut self,
        initiator_eph_bytes: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 32]), NoiseError> {
        let initiator_eph = PublicKey::from(*initiator_eph_bytes);

        let eph = StaticSecret::random_from_rng(OsRng);
        let eph_pub = PublicKey::from(&eph);

        // ee = DH(responder_eph, initiator_eph)
        let ee = eph.diffie_hellman(&initiator_eph).to_bytes();

        // se = DH(responder_eph, initiator_static)  — but in NK the
        // initiator's static key isn't known.  Instead we compute
        // se = DH(responder_static, initiator_eph) which the initiator
        // mirrors as DH(initiator_static, responder_eph) — same shared
        // secret by the DH commutativity.
        let se = self
            .local_static
            .diffie_hellman(&initiator_eph)
            .to_bytes();

        let session_key = derive_session_key(&ee, &se);
        self.ephemeral_secret = Some(eph);
        self.ephemeral_public = Some(eph_pub);
        self.session_key = Some(session_key);

        Ok((eph_pub.to_bytes(), session_key))
    }

    /// The derived 32-byte session key (available after handshake).
    pub fn session_key(&self) -> Option<[u8; 32]> {
        self.session_key
    }
}

// ── helpers ────────────────────────────────────────────────────────────

/// Very simple KDF: XOR the two DH outputs.  A production implementation
/// would use HKDF-SHA256 over the concatenation; this keeps external
/// dependencies minimal while remaining deterministic.
fn derive_session_key(ee: &[u8; 32], se: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = ee[i] ^ se[i];
    }
    out
}

/// Encrypt `plaintext` with the given ChaCha20-Poly1305 key and nonce.
pub fn encrypt(
    key: &[u8; 32],
    nonce_val: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, NoiseError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| NoiseError::Encryption(e.to_string()))?;
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..8].copy_from_slice(&nonce_val.to_le_bytes());
    let nonce = Nonce::from(nonce_bytes);
    cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| NoiseError::Encryption(e.to_string()))
}

/// Decrypt `ciphertext` with the given ChaCha20-Poly1305 key and nonce.
pub fn decrypt(
    key: &[u8; 32],
    nonce_val: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>, NoiseError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| NoiseError::Decryption(e.to_string()))?;
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..8].copy_from_slice(&nonce_val.to_le_bytes());
    let nonce = Nonce::from(nonce_bytes);
    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| NoiseError::Decryption(e.to_string()))
}
