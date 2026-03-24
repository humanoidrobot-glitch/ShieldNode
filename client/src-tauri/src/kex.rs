//! Key exchange abstractions for the client.
//!
//! Mirrors the node's `crypto::traits::KeyExchange` trait with X25519,
//! ML-KEM-768, and Hybrid implementations. When a shared crate is
//! extracted, this will be replaced by a dependency on that crate.

use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

// ── trait ─────────────────────────────────────────────────────────────

pub trait KeyExchange {
    type PublicKey: AsRef<[u8]>;
    type SharedSecret: AsRef<[u8]>;
    type Ciphertext: AsRef<[u8]>;

    fn encapsulate(
        remote_pk: &Self::PublicKey,
    ) -> Result<(Self::SharedSecret, Self::Ciphertext), String>;

    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, String>;
}

// ── X25519 KEM ────────────────────────────────────────────────────────

pub struct X25519Kem;

pub struct X25519PublicKey(PublicKey);

impl AsRef<[u8]> for X25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

pub struct X25519SharedSecret([u8; 32]);

impl AsRef<[u8]> for X25519SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub struct X25519Ciphertext([u8; 32]);

impl AsRef<[u8]> for X25519Ciphertext {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl KeyExchange for X25519Kem {
    type PublicKey = X25519PublicKey;
    type SharedSecret = X25519SharedSecret;
    type Ciphertext = X25519Ciphertext;

    fn encapsulate(
        remote_pk: &Self::PublicKey,
    ) -> Result<(Self::SharedSecret, Self::Ciphertext), String> {
        let eph_secret = StaticSecret::random_from_rng(OsRng);
        let eph_public = PublicKey::from(&eph_secret);
        let shared = eph_secret.diffie_hellman(&remote_pk.0);
        Ok((
            X25519SharedSecret(shared.to_bytes()),
            X25519Ciphertext(eph_public.to_bytes()),
        ))
    }

    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, String> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| format!("expected 32 bytes, got {}", bytes.len()))?;
        Ok(X25519PublicKey(PublicKey::from(arr)))
    }
}

// ── ML-KEM-768 ────────────────────────────────────────────────────────

use ml_kem::kem::TryDecapsulate;
use ml_kem::{Encapsulate, Kem, KeyExport, MlKem768};

const MLKEM_EK_LEN: usize = 1184;

pub struct MlKem768Kem;

pub struct MlKemPublicKey(Vec<u8>);

impl AsRef<[u8]> for MlKemPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub struct MlKemSharedSecret([u8; 32]);

impl AsRef<[u8]> for MlKemSharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub struct MlKemCiphertext(Vec<u8>);

impl AsRef<[u8]> for MlKemCiphertext {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl KeyExchange for MlKem768Kem {
    type PublicKey = MlKemPublicKey;
    type SharedSecret = MlKemSharedSecret;
    type Ciphertext = MlKemCiphertext;

    fn encapsulate(
        remote_pk: &Self::PublicKey,
    ) -> Result<(Self::SharedSecret, Self::Ciphertext), String> {
        let ek_array: &[u8; MLKEM_EK_LEN] = remote_pk
            .0
            .as_slice()
            .try_into()
            .map_err(|_| format!("invalid ML-KEM-768 key length: {}", remote_pk.0.len()))?;
        let ek = ml_kem::ml_kem_768::EncapsulationKey::new(ek_array.into())
            .map_err(|e| format!("invalid encapsulation key: {e:?}"))?;
        let (ct, ss) = ek.encapsulate();
        let mut ss_bytes = [0u8; 32];
        ss_bytes.copy_from_slice(ss.as_slice());
        Ok((
            MlKemSharedSecret(ss_bytes),
            MlKemCiphertext(ct.as_slice().to_vec()),
        ))
    }

    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, String> {
        if bytes.len() != MLKEM_EK_LEN {
            return Err(format!("expected {} bytes, got {}", MLKEM_EK_LEN, bytes.len()));
        }
        Ok(MlKemPublicKey(bytes.to_vec()))
    }
}

// ── Hybrid X25519 + ML-KEM-768 ───────────────────────────────────────

pub const HYBRID_PK_LEN: usize = 32 + MLKEM_EK_LEN; // 1216
const MLKEM_CT_LEN: usize = 1088;
const HYBRID_CT_LEN: usize = 32 + MLKEM_CT_LEN; // 1120

pub struct HybridKem;

pub struct HybridPublicKey(Vec<u8>);

impl AsRef<[u8]> for HybridPublicKey {
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

pub struct HybridCiphertext(Vec<u8>);

impl AsRef<[u8]> for HybridCiphertext {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

fn combine_shared_secrets(x25519_ss: &[u8], mlkem_ss: &[u8]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(x25519_ss.len() + mlkem_ss.len());
    ikm.extend_from_slice(x25519_ss);
    ikm.extend_from_slice(mlkem_ss);

    let hk = Hkdf::<Sha256>::new(Some(b"shieldnode-hybrid-kex"), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(b"session-key", &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

impl KeyExchange for HybridKem {
    type PublicKey = HybridPublicKey;
    type SharedSecret = HybridSharedSecret;
    type Ciphertext = HybridCiphertext;

    fn encapsulate(
        remote_pk: &Self::PublicKey,
    ) -> Result<(Self::SharedSecret, Self::Ciphertext), String> {
        if remote_pk.0.len() != HYBRID_PK_LEN {
            return Err(format!(
                "invalid hybrid key length: expected {}, got {}",
                HYBRID_PK_LEN,
                remote_pk.0.len()
            ));
        }

        let x_pk = X25519Kem::public_key_from_bytes(&remote_pk.0[..32])?;
        let m_pk = MlKem768Kem::public_key_from_bytes(&remote_pk.0[32..])?;

        let (x_ss, x_ct) = X25519Kem::encapsulate(&x_pk)?;
        let (m_ss, m_ct) = MlKem768Kem::encapsulate(&m_pk)?;

        let combined = combine_shared_secrets(x_ss.as_ref(), m_ss.as_ref());

        let mut ct_bytes = Vec::with_capacity(HYBRID_CT_LEN);
        ct_bytes.extend_from_slice(x_ct.as_ref());
        ct_bytes.extend_from_slice(m_ct.as_ref());

        Ok((HybridSharedSecret(combined), HybridCiphertext(ct_bytes)))
    }

    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, String> {
        if bytes.len() != HYBRID_PK_LEN {
            return Err(format!(
                "expected {} bytes, got {}",
                HYBRID_PK_LEN,
                bytes.len()
            ));
        }
        Ok(HybridPublicKey(bytes.to_vec()))
    }
}
