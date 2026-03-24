use thiserror::Error;

// ── errors ─────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("key generation failed: {0}")]
    KeyGeneration(String),
    #[error("encapsulation failed: {0}")]
    Encapsulation(String),
    #[error("decapsulation failed: {0}")]
    Decapsulation(String),
    #[error("signing failed: {0}")]
    Signing(String),
    #[error("verification failed: {0}")]
    Verification(String),
    #[error("encryption failed: {0}")]
    Encryption(String),
    #[error("decryption failed: {0}")]
    Decryption(String),
    #[error("invalid key material: {0}")]
    InvalidKeyMaterial(String),
}

// ── key exchange (KEM semantics) ──────────────────────────────────────
//
// KEM (Key Encapsulation Mechanism) semantics unify DH-based (X25519)
// and lattice-based (ML-KEM) key exchange under one interface:
//
//   encapsulate(remote_pk) → (shared_secret, ciphertext)
//   decapsulate(ciphertext, local_sk) → shared_secret
//
// For X25519 the "ciphertext" is the ephemeral public key.
// For ML-KEM it's the actual KEM ciphertext.

pub trait KeyExchange: Send + Sync {
    type PublicKey: AsRef<[u8]> + Clone + Send + Sync;
    type SecretKey: Send + Sync;
    type SharedSecret: AsRef<[u8]> + Send + Sync;
    type Ciphertext: AsRef<[u8]> + Clone + Send + Sync;

    fn generate_keypair() -> (Self::PublicKey, Self::SecretKey);

    fn encapsulate(
        remote_pk: &Self::PublicKey,
    ) -> Result<(Self::SharedSecret, Self::Ciphertext), CryptoError>;

    fn decapsulate(
        ciphertext: &Self::Ciphertext,
        local_sk: &Self::SecretKey,
    ) -> Result<Self::SharedSecret, CryptoError>;

    fn public_key_len() -> usize;

    fn ciphertext_len() -> usize;

    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, CryptoError>;

    fn ciphertext_from_bytes(bytes: &[u8]) -> Result<Self::Ciphertext, CryptoError>;
}

// ── digital signatures ────────────────────────────────────────────────
//
// Supports both deterministic (ECDSA) and randomized (ML-DSA) signing.
// ML-DSA uses OsRng internally during sign() — the trait interface
// does not require the caller to provide randomness.

pub trait Signer: Send + Sync {
    type PublicKey: AsRef<[u8]> + Clone + Send + Sync;
    type SecretKey: Send + Sync;
    type Signature: AsRef<[u8]> + Clone + Send + Sync;

    fn generate_keypair() -> (Self::PublicKey, Self::SecretKey);

    /// Randomized schemes (ML-DSA) source entropy internally via OsRng.
    fn sign(message: &[u8], secret_key: &Self::SecretKey) -> Result<Self::Signature, CryptoError>;

    fn verify(
        message: &[u8],
        signature: &Self::Signature,
        public_key: &Self::PublicKey,
    ) -> Result<bool, CryptoError>;

    fn signature_len() -> usize;

    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, CryptoError>;

    fn signature_from_bytes(bytes: &[u8]) -> Result<Self::Signature, CryptoError>;
}

// ── symmetric encryption ──────────────────────────────────────────────

pub trait SymmetricCipher: Send + Sync {
    fn encrypt(key: &[u8; 32], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;

    fn decrypt(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;

    fn nonce_len() -> usize;

    /// Authentication tag overhead in bytes.
    fn tag_len() -> usize;
}
