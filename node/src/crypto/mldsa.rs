//! ML-DSA-65 (FIPS 204) digital signature implementation behind the
//! `Signer` trait. Provides post-quantum signature capability for
//! bandwidth receipts, verified inside the ZK settlement circuit.
//!
//! ML-DSA-65 parameters (NIST Security Level 3):
//! - Public key:  1952 bytes
//! - Signature:   3309 bytes
//! - Secret key:  4032 bytes (seed: 32 bytes)

use ml_dsa::{EncodedSignature, EncodedVerifyingKey, KeyGen, MlDsa65, Signature as MlDsaSig};

use super::traits::{CryptoError, Signer};

type Vk = ml_dsa::VerifyingKey<MlDsa65>;
type Esk = ml_dsa::ExpandedSigningKey<MlDsa65>;

// ── newtype wrappers ──────────────────────────────────────────────────

#[derive(Clone)]
pub struct MlDsaPublicKey {
    key: Vk,
    bytes: Vec<u8>,
}

impl MlDsaPublicKey {
    fn new(key: Vk) -> Self {
        let bytes = key.encode().to_vec();
        Self { key, bytes }
    }
}

impl AsRef<[u8]> for MlDsaPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

pub struct MlDsaSecretKey {
    expanded: Esk,
    seed: [u8; 32],
}

#[derive(Clone)]
pub struct MlDsaSignature {
    bytes: Vec<u8>,
}

impl AsRef<[u8]> for MlDsaSignature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

// ── Signer impl ───────────────────────────────────────────────────────

pub struct MlDsaSigner;

impl Signer for MlDsaSigner {
    type PublicKey = MlDsaPublicKey;
    type SecretKey = MlDsaSecretKey;
    type Signature = MlDsaSignature;

    fn generate_keypair() -> (Self::PublicKey, Self::SecretKey) {
        // Generate a random 32-byte seed, then derive the keypair
        // deterministically. Avoids rand_core version mismatch between
        // rand 0.8 (OsRng) and ml-dsa's rand_core 0.9.
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);

        let seed_arr = ml_dsa::B32::from(seed);
        let signing_key = MlDsa65::from_seed(&seed_arr);
        let expanded = signing_key.signing_key().clone();
        let verifying = expanded.verifying_key();

        (
            MlDsaPublicKey::new(verifying),
            MlDsaSecretKey { expanded, seed },
        )
    }

    /// Sign a message using ML-DSA-65 deterministic mode.
    /// Context string is empty per FIPS 204 default.
    fn sign(message: &[u8], secret_key: &Self::SecretKey) -> Result<Self::Signature, CryptoError> {
        let sig = secret_key
            .expanded
            .sign_deterministic(message, b"")
            .map_err(|e| CryptoError::Signing(format!("ML-DSA sign failed: {e:?}")))?;
        let encoded = sig.encode();
        Ok(MlDsaSignature {
            bytes: encoded.to_vec(),
        })
    }

    fn verify(
        message: &[u8],
        signature: &Self::Signature,
        public_key: &Self::PublicKey,
    ) -> Result<bool, CryptoError> {
        let encoded_sig = EncodedSignature::<MlDsa65>::try_from(signature.bytes.as_slice())
            .map_err(|_| CryptoError::Verification("invalid ML-DSA signature encoding".into()))?;
        let sig = MlDsaSig::<MlDsa65>::decode(&encoded_sig)
            .ok_or_else(|| CryptoError::Verification("ML-DSA signature decode failed".into()))?;
        Ok(public_key.key.verify_with_context(message, b"", &sig))
    }

    fn signature_len() -> usize {
        3309 // ML-DSA-65 encoded signature size
    }

    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, CryptoError> {
        let encoded = EncodedVerifyingKey::<MlDsa65>::try_from(bytes)
            .map_err(|_| CryptoError::InvalidKeyMaterial(format!(
                "invalid ML-DSA-65 public key length: expected 1952, got {}",
                bytes.len()
            )))?;
        let key = Vk::decode(&encoded);
        Ok(MlDsaPublicKey::new(key))
    }

    fn signature_from_bytes(bytes: &[u8]) -> Result<Self::Signature, CryptoError> {
        let encoded = EncodedSignature::<MlDsa65>::try_from(bytes)
            .map_err(|_| CryptoError::InvalidKeyMaterial(format!(
                "invalid ML-DSA-65 signature length: expected 3309, got {}",
                bytes.len()
            )))?;
        MlDsaSig::<MlDsa65>::decode(&encoded)
            .ok_or_else(|| CryptoError::InvalidKeyMaterial("ML-DSA signature decode failed".into()))?;
        Ok(MlDsaSignature {
            bytes: bytes.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let (pk, sk) = MlDsaSigner::generate_keypair();
        let msg = b"bandwidth receipt data";
        let sig = MlDsaSigner::sign(msg, &sk).unwrap();
        assert!(MlDsaSigner::verify(msg, &sig, &pk).unwrap());
    }

    #[test]
    fn wrong_message_fails_verify() {
        let (pk, sk) = MlDsaSigner::generate_keypair();
        let sig = MlDsaSigner::sign(b"original", &sk).unwrap();
        assert!(!MlDsaSigner::verify(b"tampered", &sig, &pk).unwrap());
    }

    #[test]
    fn wrong_key_fails_verify() {
        let (_, sk) = MlDsaSigner::generate_keypair();
        let (pk2, _) = MlDsaSigner::generate_keypair();
        let sig = MlDsaSigner::sign(b"message", &sk).unwrap();
        assert!(!MlDsaSigner::verify(b"message", &sig, &pk2).unwrap());
    }

    #[test]
    fn public_key_roundtrip_bytes() {
        let (pk, _) = MlDsaSigner::generate_keypair();
        let bytes = pk.as_ref().to_vec();
        let pk2 = MlDsaSigner::public_key_from_bytes(&bytes).unwrap();
        assert_eq!(pk.as_ref(), pk2.as_ref());
    }

    #[test]
    fn signature_roundtrip_bytes() {
        let (_, sk) = MlDsaSigner::generate_keypair();
        let sig = MlDsaSigner::sign(b"test", &sk).unwrap();
        let bytes = sig.as_ref().to_vec();
        let sig2 = MlDsaSigner::signature_from_bytes(&bytes).unwrap();
        assert_eq!(sig.as_ref(), sig2.as_ref());
    }

    #[test]
    fn key_and_sig_sizes() {
        let (pk, sk) = MlDsaSigner::generate_keypair();
        let sig = MlDsaSigner::sign(b"size check", &sk).unwrap();
        // ML-DSA-65: vk=1952, sig=3309
        assert_eq!(pk.as_ref().len(), 1952);
        assert_eq!(sig.as_ref().len(), 3309);
        assert_eq!(MlDsaSigner::signature_len(), 3309);
    }
}
