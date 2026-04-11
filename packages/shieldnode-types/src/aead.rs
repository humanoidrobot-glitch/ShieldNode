//! ChaCha20-Poly1305 AEAD encryption/decryption helpers.

/// Nonce offset for return-path encryption. Added to hop_index to create
/// a distinct nonce domain, preventing AEAD nonce reuse with the same
/// session key used for forward-path traffic.
pub const RETURN_NONCE_OFFSET: u64 = 0x8000_0000_0000_0000;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"hello shieldnode";
        let ct = encrypt(&key, 0, plaintext).unwrap();
        let pt = decrypt(&key, 0, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn wrong_key_fails_decrypt() {
        let key = [0x42u8; 32];
        let wrong = [0x99u8; 32];
        let ct = encrypt(&key, 0, b"secret").unwrap();
        assert!(decrypt(&wrong, 0, &ct).is_err());
    }

    #[test]
    fn nonce_from_index_layout() {
        let n = nonce_from_index(42);
        assert_eq!(&n[..8], &42u64.to_le_bytes());
        assert_eq!(&n[8..], &[0u8; 4]);
    }
}

/// Decrypt using a raw 12-byte nonce.
pub fn decrypt_with_nonce(
    key: &[u8; 32],
    nonce_bytes: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext)
}
