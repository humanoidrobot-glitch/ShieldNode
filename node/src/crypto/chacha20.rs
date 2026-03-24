use super::aead;
use super::traits::{CryptoError, SymmetricCipher};

pub struct ChaCha20Poly1305Cipher;

impl SymmetricCipher for ChaCha20Poly1305Cipher {
    fn encrypt(key: &[u8; 32], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce: &[u8; 12] = nonce
            .try_into()
            .map_err(|_| CryptoError::Encryption(format!("nonce must be 12 bytes, got {}", nonce.len())))?;
        aead::encrypt_with_nonce(key, nonce, plaintext)
            .map_err(|e| CryptoError::Encryption(e.to_string()))
    }

    fn decrypt(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce: &[u8; 12] = nonce
            .try_into()
            .map_err(|_| CryptoError::Decryption(format!("nonce must be 12 bytes, got {}", nonce.len())))?;
        aead::decrypt_with_nonce(key, nonce, ciphertext)
            .map_err(|e| CryptoError::Decryption(e.to_string()))
    }

    fn nonce_len() -> usize {
        12
    }

    fn tag_len() -> usize {
        16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"hello shieldnode";

        let ct = ChaCha20Poly1305Cipher::encrypt(&key, &nonce, plaintext).unwrap();
        let pt = ChaCha20Poly1305Cipher::decrypt(&key, &nonce, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key = [42u8; 32];
        let nonce = [0u8; 12];
        let ct = ChaCha20Poly1305Cipher::encrypt(&key, &nonce, b"secret").unwrap();

        let bad_key = [99u8; 32];
        assert!(ChaCha20Poly1305Cipher::decrypt(&bad_key, &nonce, &ct).is_err());
    }

    #[test]
    fn bad_nonce_length_rejected() {
        let key = [42u8; 32];
        assert!(ChaCha20Poly1305Cipher::encrypt(&key, &[0u8; 8], b"test").is_err());
        assert!(ChaCha20Poly1305Cipher::decrypt(&key, &[0u8; 16], b"test").is_err());
    }
}
