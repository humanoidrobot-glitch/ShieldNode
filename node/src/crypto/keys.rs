use std::path::Path;

use thiserror::Error;
use x25519_dalek::PublicKey;

use super::traits::KeyExchange;
use super::x25519_kem::{X25519Kem, X25519PublicKey, X25519SecretKey};

// ── errors ─────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("invalid key length: expected 32, got {0}")]
    InvalidLength(usize),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

// ── persistent node keypair ────────────────────────────────────────────

/// A long-lived X25519 keypair stored on disk.
///
/// Uses `KeyExchange` trait types so the hybrid PQ handshake can
/// access the same key material.
pub struct NodeKeyPair {
    secret: X25519SecretKey,
    public: X25519PublicKey,
}

impl NodeKeyPair {
    /// Generate a brand-new random keypair.
    pub fn generate() -> Self {
        let (public, secret) = X25519Kem::generate_keypair();
        Self { secret, public }
    }

    /// Reconstruct from raw 32-byte secret key material.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        if bytes.len() != 32 {
            return Err(KeyError::InvalidLength(bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        let secret = x25519_dalek::StaticSecret::from(arr);
        let public = PublicKey::from(&secret);
        Ok(Self {
            public: X25519PublicKey(public),
            secret: X25519SecretKey(secret),
        })
    }

    /// The public half of this keypair (as the raw dalek type for
    /// backward compatibility).
    pub fn public_key(&self) -> PublicKey {
        *self.public.as_dalek()
    }

    /// The public half as the trait-based type.
    pub fn public_key_kem(&self) -> &X25519PublicKey {
        &self.public
    }

    /// The 32-byte public key bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Borrow the static secret (as the raw dalek type for backward
    /// compatibility).
    pub fn secret(&self) -> &x25519_dalek::StaticSecret {
        self.secret.as_dalek()
    }

    /// Borrow the static secret as the trait-based type.
    pub fn secret_kem(&self) -> &X25519SecretKey {
        &self.secret
    }

    /// Persist the 32-byte secret to `path`.
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), KeyError> {
        let bytes = self.secret.to_bytes();
        std::fs::write(path, bytes)?;
        Ok(())
    }

    /// Load a keypair from a file previously written by [`save_to_file`].
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, KeyError> {
        let bytes = std::fs::read(path)?;
        Self::from_bytes(&bytes)
    }

    /// Load an existing keypair from `path`, or generate a new one and
    /// save it if the file doesn't exist. Creates parent directories as
    /// needed.
    pub fn load_or_generate<P: AsRef<Path>>(path: P) -> Result<(Self, bool), KeyError> {
        let path = path.as_ref();
        if path.exists() {
            let kp = Self::load_from_file(path)?;
            Ok((kp, false))
        } else {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let kp = Self::generate();
            kp.save_to_file(path)?;
            Ok((kp, true))
        }
    }
}

// ── ephemeral per-circuit session ──────────────────────────────────────

/// An ephemeral X25519 session used for a single circuit.
///
/// Uses `KeyExchange` trait for key generation and KEM-style
/// encapsulate/decapsulate for DH.
pub struct EphemeralSession {
    secret: X25519SecretKey,
    public: X25519PublicKey,
}

impl EphemeralSession {
    /// Generate a fresh ephemeral keypair.
    pub fn new() -> Self {
        let (public, secret) = X25519Kem::generate_keypair();
        Self { secret, public }
    }

    pub fn public_key(&self) -> PublicKey {
        *self.public.as_dalek()
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Perform key exchange with the peer's public key and return the
    /// 32-byte shared secret. Uses KEM decapsulate (X25519 DH internally).
    pub fn diffie_hellman(&self, peer_public: &PublicKey) -> [u8; 32] {
        let ct = X25519Kem::ciphertext_from_bytes(peer_public.as_bytes())
            .expect("PublicKey is always 32 bytes");
        X25519Kem::decapsulate(&ct, &self.secret)
            .expect("X25519 decapsulate cannot fail")
            .to_bytes()
    }
}

impl Default for EphemeralSession {
    fn default() -> Self {
        Self::new()
    }
}
