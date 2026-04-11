use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};

/// Build a 12-byte nonce from a u64 counter (LE-encoded, zero-padded).
pub fn nonce_from_index(index: u64) -> [u8; 12] {
    let mut bytes = [0u8; 12];
    bytes[..8].copy_from_slice(&index.to_le_bytes());
    bytes
}

/// Encrypt `plaintext` with ChaCha20-Poly1305 using a 32-byte key and
/// u64 nonce counter.
pub fn encrypt(
    key: &[u8; 32],
    nonce_val: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from(nonce_from_index(nonce_val));
    cipher.encrypt(&nonce, plaintext)
}

/// Decrypt `ciphertext` with ChaCha20-Poly1305 using a 32-byte key and
/// u64 nonce counter.
pub fn decrypt(
    key: &[u8; 32],
    nonce_val: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from(nonce_from_index(nonce_val));
    cipher.decrypt(&nonce, ciphertext)
}

/// Encrypt using a raw 12-byte nonce.
pub fn encrypt_with_nonce(
    key: &[u8; 32],
    nonce_bytes: &[u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.encrypt(nonce, plaintext)
}
