use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use super::traits::{CryptoError, KeyExchange};

// ── newtype wrappers ──────────────────────────────────────────────────
//
// We wrap x25519_dalek types so they satisfy the trait's AsRef<[u8]>
// bound while keeping the inner types accessible internally.

#[derive(Clone)]
pub struct X25519PublicKey(pub(crate) PublicKey);

impl AsRef<[u8]> for X25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

pub struct X25519SecretKey(pub(crate) StaticSecret);

/// For X25519-as-KEM, the "ciphertext" is the ephemeral public key.
#[derive(Clone)]
pub struct X25519Ciphertext(pub(crate) [u8; 32]);

impl AsRef<[u8]> for X25519Ciphertext {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub struct X25519SharedSecret(pub(crate) [u8; 32]);

impl AsRef<[u8]> for X25519SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// ── KeyExchange impl ──────────────────────────────────────────────────

pub struct X25519Kem;

impl KeyExchange for X25519Kem {
    type PublicKey = X25519PublicKey;
    type SecretKey = X25519SecretKey;
    type SharedSecret = X25519SharedSecret;
    type Ciphertext = X25519Ciphertext;

    fn generate_keypair() -> (Self::PublicKey, Self::SecretKey) {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        (X25519PublicKey(public), X25519SecretKey(secret))
    }

    fn encapsulate(
        remote_pk: &Self::PublicKey,
    ) -> Result<(Self::SharedSecret, Self::Ciphertext), CryptoError> {
        let eph_secret = StaticSecret::random_from_rng(OsRng);
        let eph_public = PublicKey::from(&eph_secret);
        let shared = eph_secret.diffie_hellman(&remote_pk.0);
        Ok((
            X25519SharedSecret(shared.to_bytes()),
            X25519Ciphertext(eph_public.to_bytes()),
        ))
    }

    fn decapsulate(
        ciphertext: &Self::Ciphertext,
        local_sk: &Self::SecretKey,
    ) -> Result<Self::SharedSecret, CryptoError> {
        let peer_public = PublicKey::from(ciphertext.0);
        let shared = local_sk.0.diffie_hellman(&peer_public);
        Ok(X25519SharedSecret(shared.to_bytes()))
    }

    fn public_key_len() -> usize {
        32
    }

    fn ciphertext_len() -> usize {
        32
    }

    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, CryptoError> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKeyMaterial(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(X25519PublicKey(PublicKey::from(arr)))
    }

    fn ciphertext_from_bytes(bytes: &[u8]) -> Result<Self::Ciphertext, CryptoError> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKeyMaterial(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(X25519Ciphertext(arr))
    }
}

// ── convenience helpers ───────────────────────────────────────────────

impl X25519PublicKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn as_dalek(&self) -> &PublicKey {
        &self.0
    }
}

impl X25519SecretKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn as_dalek(&self) -> &StaticSecret {
        &self.0
    }
}

impl X25519SharedSecret {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encapsulate_decapsulate_roundtrip() {
        let (pk, sk) = X25519Kem::generate_keypair();
        let (shared_enc, ciphertext) = X25519Kem::encapsulate(&pk).unwrap();
        let shared_dec = X25519Kem::decapsulate(&ciphertext, &sk).unwrap();
        assert_eq!(shared_enc.as_ref(), shared_dec.as_ref());
    }

    #[test]
    fn different_keypairs_produce_different_secrets() {
        let (pk1, _) = X25519Kem::generate_keypair();
        let (pk2, _) = X25519Kem::generate_keypair();
        let (s1, _) = X25519Kem::encapsulate(&pk1).unwrap();
        let (s2, _) = X25519Kem::encapsulate(&pk2).unwrap();
        assert_ne!(s1.as_ref(), s2.as_ref());
    }

    #[test]
    fn public_key_roundtrip_bytes() {
        let (pk, _) = X25519Kem::generate_keypair();
        let bytes = pk.to_bytes();
        let pk2 = X25519Kem::public_key_from_bytes(&bytes).unwrap();
        assert_eq!(pk.as_ref(), pk2.as_ref());
    }

    #[test]
    fn wrong_length_rejected() {
        assert!(X25519Kem::public_key_from_bytes(&[0u8; 16]).is_err());
        assert!(X25519Kem::ciphertext_from_bytes(&[0u8; 64]).is_err());
    }
}
