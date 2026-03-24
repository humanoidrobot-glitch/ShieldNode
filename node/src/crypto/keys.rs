use std::path::Path;

use rand::rngs::OsRng;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

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
pub struct NodeKeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl NodeKeyPair {
    /// Generate a brand-new random keypair.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Reconstruct from raw 32-byte secret key material.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        if bytes.len() != 32 {
            return Err(KeyError::InvalidLength(bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        let secret = StaticSecret::from(arr);
        let public = PublicKey::from(&secret);
        Ok(Self { secret, public })
    }

    /// The public half of this keypair.
    pub fn public_key(&self) -> PublicKey {
        self.public
    }

    /// Borrow the static secret (needed for DH and handshake operations).
    pub fn secret(&self) -> &StaticSecret {
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
pub struct EphemeralSession {
    secret: StaticSecret,
    public: PublicKey,
}

impl EphemeralSession {
    /// Generate a fresh ephemeral keypair.
    pub fn new() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_key(&self) -> PublicKey {
        self.public
    }

    /// Perform X25519 Diffie-Hellman with the peer's public key and
    /// return the 32-byte shared secret.
    pub fn diffie_hellman(&self, peer_public: &PublicKey) -> [u8; 32] {
        self.secret.diffie_hellman(peer_public).to_bytes()
    }
}

impl Default for EphemeralSession {
    fn default() -> Self {
        Self::new()
    }
}
