use k256::ecdsa::{
    signature::{Signer as K256Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use rand::rngs::OsRng;

use super::traits::{CryptoError, Signer};

// ── newtype wrappers ──────────────────────────────────────────────────

#[derive(Clone)]
pub struct EcdsaPublicKey {
    key: VerifyingKey,
    /// SEC1 compressed encoding (33 bytes: 0x02/0x03 || X).
    bytes: [u8; 33],
}

impl EcdsaPublicKey {
    fn new(key: VerifyingKey) -> Self {
        let sec1 = key.to_sec1_bytes();
        let mut bytes = [0u8; 33];
        bytes.copy_from_slice(&sec1);
        Self { key, bytes }
    }
}

impl AsRef<[u8]> for EcdsaPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

pub struct EcdsaSecretKey(SigningKey);

#[derive(Clone)]
pub struct EcdsaSignature {
    sig: Signature,
    /// 64-byte r||s encoding.
    bytes: [u8; 64],
}

impl EcdsaSignature {
    fn new(sig: Signature) -> Self {
        let bytes: [u8; 64] = sig.to_bytes().into();
        Self { sig, bytes }
    }
}

impl AsRef<[u8]> for EcdsaSignature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

// ── Signer impl ───────────────────────────────────────────────────────

pub struct EcdsaSigner;

impl Signer for EcdsaSigner {
    type PublicKey = EcdsaPublicKey;
    type SecretKey = EcdsaSecretKey;
    type Signature = EcdsaSignature;

    fn generate_keypair() -> (Self::PublicKey, Self::SecretKey) {
        let signing = SigningKey::random(&mut OsRng);
        let verifying = VerifyingKey::from(&signing);
        (EcdsaPublicKey::new(verifying), EcdsaSecretKey(signing))
    }

    fn sign(message: &[u8], secret_key: &Self::SecretKey) -> Result<Self::Signature, CryptoError> {
        let sig: Signature = secret_key
            .0
            .try_sign(message)
            .map_err(|e: k256::ecdsa::Error| CryptoError::Signing(e.to_string()))?;
        Ok(EcdsaSignature::new(sig))
    }

    fn verify(
        message: &[u8],
        signature: &Self::Signature,
        public_key: &Self::PublicKey,
    ) -> Result<bool, CryptoError> {
        Ok(public_key.key.verify(message, &signature.sig).is_ok())
    }

    fn signature_len() -> usize {
        64
    }

    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, CryptoError> {
        let vk = VerifyingKey::from_sec1_bytes(bytes)
            .map_err(|e: k256::ecdsa::Error| CryptoError::InvalidKeyMaterial(e.to_string()))?;
        Ok(EcdsaPublicKey::new(vk))
    }

    fn signature_from_bytes(bytes: &[u8]) -> Result<Self::Signature, CryptoError> {
        let sig = Signature::from_slice(bytes)
            .map_err(|e: k256::ecdsa::Error| CryptoError::InvalidKeyMaterial(e.to_string()))?;
        Ok(EcdsaSignature::new(sig))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let (pk, sk) = EcdsaSigner::generate_keypair();
        let msg = b"bandwidth receipt data";
        let sig = EcdsaSigner::sign(msg, &sk).unwrap();
        assert!(EcdsaSigner::verify(msg, &sig, &pk).unwrap());
    }

    #[test]
    fn wrong_message_fails_verify() {
        let (pk, sk) = EcdsaSigner::generate_keypair();
        let sig = EcdsaSigner::sign(b"original", &sk).unwrap();
        assert!(!EcdsaSigner::verify(b"tampered", &sig, &pk).unwrap());
    }

    #[test]
    fn wrong_key_fails_verify() {
        let (_, sk) = EcdsaSigner::generate_keypair();
        let (pk2, _) = EcdsaSigner::generate_keypair();
        let sig = EcdsaSigner::sign(b"message", &sk).unwrap();
        assert!(!EcdsaSigner::verify(b"message", &sig, &pk2).unwrap());
    }

    #[test]
    fn public_key_roundtrip_bytes() {
        let (pk, _) = EcdsaSigner::generate_keypair();
        let bytes = pk.as_ref().to_vec();
        let pk2 = EcdsaSigner::public_key_from_bytes(&bytes).unwrap();
        assert_eq!(pk.as_ref(), pk2.as_ref());
    }

    #[test]
    fn signature_roundtrip_bytes() {
        let (_, sk) = EcdsaSigner::generate_keypair();
        let sig = EcdsaSigner::sign(b"test", &sk).unwrap();
        let bytes = sig.as_ref().to_vec();
        let sig2 = EcdsaSigner::signature_from_bytes(&bytes).unwrap();
        assert_eq!(sig.as_ref(), sig2.as_ref());
    }
}
