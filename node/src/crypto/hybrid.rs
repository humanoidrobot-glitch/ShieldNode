//! Hybrid X25519 + ML-KEM-768 key exchange.
//!
//! Combines both primitives so that security equals the stronger of the two:
//! if either X25519 or ML-KEM remains secure, the session key is safe.
//!
//! session_key = HKDF-SHA256(
//!     ikm = X25519_shared || ML-KEM_shared,
//!     salt = "shieldnode-hybrid-kex",
//!     info = "session-key"
//! )
//!
//! Overhead per hop: ~2.3 KB (1184 + 1088 + 32 = 2304 bytes for the
//! compound ciphertext). For a 3-hop circuit: ~6.9 KB total, once per session.

use super::kdf::hkdf_sha256;
use super::mlkem::{self, MlKem768Kem};
use super::traits::{CryptoError, KeyExchange};
use super::x25519_kem::{self, X25519Kem};

// ── compound types ────────────────────────────────────────────────────
//
// Public keys and ciphertexts are concatenated: [X25519 || ML-KEM-768].
// This is simple, unambiguous, and easy to split.

const X25519_PK_LEN: usize = 32;
const MLKEM_PK_LEN: usize = mlkem::EK_LEN; // 1184
const HYBRID_PK_LEN: usize = X25519_PK_LEN + MLKEM_PK_LEN; // 1216

const X25519_CT_LEN: usize = 32;
const MLKEM_CT_LEN: usize = mlkem::CT_LEN; // 1088
const HYBRID_CT_LEN: usize = X25519_CT_LEN + MLKEM_CT_LEN; // 1120

#[derive(Clone)]
pub struct HybridPublicKey(Vec<u8>);

impl AsRef<[u8]> for HybridPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub struct HybridSecretKey {
    x25519: x25519_kem::X25519SecretKey,
    mlkem: mlkem::MlKemSecretKey,
}

#[derive(Clone)]
pub struct HybridCiphertext(Vec<u8>);

impl AsRef<[u8]> for HybridCiphertext {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub struct HybridSharedSecret([u8; 32]);

impl AsRef<[u8]> for HybridSharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl HybridSharedSecret {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

// ── HKDF combiner ────────────────────────────────────────────────────

/// Combine two shared secrets into one session key via HKDF-SHA256.
/// Security = stronger of the two inputs.
fn combine_shared_secrets(x25519_ss: &[u8], mlkem_ss: &[u8]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(x25519_ss.len() + mlkem_ss.len());
    ikm.extend_from_slice(x25519_ss);
    ikm.extend_from_slice(mlkem_ss);

    hkdf_sha256::<32>(Some(b"shieldnode-hybrid-kex"), &ikm, b"session-key")
}

// ── KeyExchange impl ──────────────────────────────────────────────────

pub struct HybridKem;

impl KeyExchange for HybridKem {
    type PublicKey = HybridPublicKey;
    type SecretKey = HybridSecretKey;
    type SharedSecret = HybridSharedSecret;
    type Ciphertext = HybridCiphertext;

    fn generate_keypair() -> (Self::PublicKey, Self::SecretKey) {
        let (x_pk, x_sk) = X25519Kem::generate_keypair();
        let (m_pk, m_sk) = MlKem768Kem::generate_keypair();

        let mut pk_bytes = Vec::with_capacity(HYBRID_PK_LEN);
        pk_bytes.extend_from_slice(x_pk.as_ref());
        pk_bytes.extend_from_slice(m_pk.as_ref());

        (
            HybridPublicKey(pk_bytes),
            HybridSecretKey {
                x25519: x_sk,
                mlkem: m_sk,
            },
        )
    }

    fn encapsulate(
        remote_pk: &Self::PublicKey,
    ) -> Result<(Self::SharedSecret, Self::Ciphertext), CryptoError> {
        if remote_pk.0.len() != HYBRID_PK_LEN {
            return Err(CryptoError::Encapsulation(format!(
                "invalid hybrid public key length: expected {}, got {}",
                HYBRID_PK_LEN,
                remote_pk.0.len()
            )));
        }

        let x_pk = X25519Kem::public_key_from_bytes(&remote_pk.0[..X25519_PK_LEN])?;
        let m_pk = MlKem768Kem::public_key_from_bytes(&remote_pk.0[X25519_PK_LEN..])?;

        let (x_ss, x_ct) = X25519Kem::encapsulate(&x_pk)?;
        let (m_ss, m_ct) = MlKem768Kem::encapsulate(&m_pk)?;

        let combined = combine_shared_secrets(x_ss.as_ref(), m_ss.as_ref());

        let mut ct_bytes = Vec::with_capacity(HYBRID_CT_LEN);
        ct_bytes.extend_from_slice(x_ct.as_ref());
        ct_bytes.extend_from_slice(m_ct.as_ref());

        Ok((HybridSharedSecret(combined), HybridCiphertext(ct_bytes)))
    }

    fn decapsulate(
        ciphertext: &Self::Ciphertext,
        local_sk: &Self::SecretKey,
    ) -> Result<Self::SharedSecret, CryptoError> {
        if ciphertext.0.len() != HYBRID_CT_LEN {
            return Err(CryptoError::Decapsulation(format!(
                "invalid hybrid ciphertext length: expected {}, got {}",
                HYBRID_CT_LEN,
                ciphertext.0.len()
            )));
        }

        let x_ct = X25519Kem::ciphertext_from_bytes(&ciphertext.0[..X25519_CT_LEN])?;
        let m_ct = MlKem768Kem::ciphertext_from_bytes(&ciphertext.0[X25519_CT_LEN..])?;

        let x_ss = X25519Kem::decapsulate(&x_ct, &local_sk.x25519)?;
        let m_ss = MlKem768Kem::decapsulate(&m_ct, &local_sk.mlkem)?;

        let combined = combine_shared_secrets(x_ss.as_ref(), m_ss.as_ref());
        Ok(HybridSharedSecret(combined))
    }

    fn public_key_len() -> usize {
        HYBRID_PK_LEN
    }

    fn ciphertext_len() -> usize {
        HYBRID_CT_LEN
    }

    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, CryptoError> {
        if bytes.len() != HYBRID_PK_LEN {
            return Err(CryptoError::InvalidKeyMaterial(format!(
                "expected {} bytes, got {}",
                HYBRID_PK_LEN,
                bytes.len()
            )));
        }
        Ok(HybridPublicKey(bytes.to_vec()))
    }

    fn ciphertext_from_bytes(bytes: &[u8]) -> Result<Self::Ciphertext, CryptoError> {
        if bytes.len() != HYBRID_CT_LEN {
            return Err(CryptoError::InvalidKeyMaterial(format!(
                "expected {} bytes, got {}",
                HYBRID_CT_LEN,
                bytes.len()
            )));
        }
        Ok(HybridCiphertext(bytes.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encapsulate_decapsulate_roundtrip() {
        let (pk, sk) = HybridKem::generate_keypair();
        let (ss_enc, ct) = HybridKem::encapsulate(&pk).unwrap();
        let ss_dec = HybridKem::decapsulate(&ct, &sk).unwrap();
        assert_eq!(ss_enc.as_ref(), ss_dec.as_ref());
    }

    #[test]
    fn public_key_is_x25519_plus_mlkem() {
        let (pk, _) = HybridKem::generate_keypair();
        assert_eq!(pk.as_ref().len(), HYBRID_PK_LEN);
        assert_eq!(HYBRID_PK_LEN, 32 + 1184);
    }

    #[test]
    fn ciphertext_is_x25519_plus_mlkem() {
        let (pk, _) = HybridKem::generate_keypair();
        let (_, ct) = HybridKem::encapsulate(&pk).unwrap();
        assert_eq!(ct.as_ref().len(), HYBRID_CT_LEN);
        assert_eq!(HYBRID_CT_LEN, 32 + 1088);
    }

    #[test]
    fn shared_secret_is_32_bytes() {
        let (pk, _) = HybridKem::generate_keypair();
        let (ss, _) = HybridKem::encapsulate(&pk).unwrap();
        assert_eq!(ss.as_ref().len(), 32);
    }

    #[test]
    fn different_keypairs_produce_different_secrets() {
        let (pk1, _) = HybridKem::generate_keypair();
        let (pk2, _) = HybridKem::generate_keypair();
        let (s1, _) = HybridKem::encapsulate(&pk1).unwrap();
        let (s2, _) = HybridKem::encapsulate(&pk2).unwrap();
        assert_ne!(s1.as_ref(), s2.as_ref());
    }

    #[test]
    fn combiner_uses_both_inputs() {
        // If we change either input, the output changes.
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        let ab = combine_shared_secrets(&a, &b);
        let ac = combine_shared_secrets(&a, &c);
        let cb = combine_shared_secrets(&c, &b);
        assert_ne!(ab, ac); // different ML-KEM input
        assert_ne!(ab, cb); // different X25519 input
    }

    #[test]
    fn wrong_length_rejected() {
        assert!(HybridKem::public_key_from_bytes(&[0u8; 32]).is_err());
        assert!(HybridKem::ciphertext_from_bytes(&[0u8; 32]).is_err());
    }
}
