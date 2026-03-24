use ml_kem::ml_kem_768;
use ml_kem::kem::TryDecapsulate;
use ml_kem::{Encapsulate, Kem, KeyExport, MlKem768};

use super::traits::{CryptoError, KeyExchange};

// ML-KEM-768 key sizes (FIPS 203):
//   Encapsulation key (public): 1,184 bytes
//   Decapsulation key (secret): 2,400 bytes
//   Ciphertext:                 1,088 bytes
//   Shared secret:              32 bytes

pub const EK_LEN: usize = 1184;
pub const CT_LEN: usize = 1088;

#[derive(Clone)]
pub struct MlKemPublicKey(Vec<u8>);

impl AsRef<[u8]> for MlKemPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub struct MlKemSecretKey(ml_kem_768::DecapsulationKey);

#[derive(Clone)]
pub struct MlKemCiphertext(Vec<u8>);

impl AsRef<[u8]> for MlKemCiphertext {
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

impl MlKemSharedSecret {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

fn shared_key_to_bytes(sk: &ml_kem::kem::SharedKey<MlKem768>) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(sk.as_slice());
    out
}

// ── KeyExchange impl ──────────────────────────────────────────────────

pub struct MlKem768Kem;

impl KeyExchange for MlKem768Kem {
    type PublicKey = MlKemPublicKey;
    type SecretKey = MlKemSecretKey;
    type SharedSecret = MlKemSharedSecret;
    type Ciphertext = MlKemCiphertext;

    fn generate_keypair() -> (Self::PublicKey, Self::SecretKey) {
        let (dk, ek) = MlKem768::generate_keypair();
        let ek_bytes = ek.to_bytes().to_vec();
        (MlKemPublicKey(ek_bytes), MlKemSecretKey(dk))
    }

    fn encapsulate(
        remote_pk: &Self::PublicKey,
    ) -> Result<(Self::SharedSecret, Self::Ciphertext), CryptoError> {
        let ek_array: &[u8; EK_LEN] = remote_pk.0.as_slice().try_into().map_err(|_| {
            CryptoError::Encapsulation(format!(
                "invalid ML-KEM-768 public key length: {}",
                remote_pk.0.len()
            ))
        })?;
        let ek = ml_kem_768::EncapsulationKey::new(ek_array.into())
            .map_err(|e| CryptoError::Encapsulation(format!("invalid encapsulation key: {e:?}")))?;
        let (ct, ss) = ek.encapsulate();
        Ok((
            MlKemSharedSecret(shared_key_to_bytes(&ss)),
            MlKemCiphertext(ct.as_slice().to_vec()),
        ))
    }

    fn decapsulate(
        ciphertext: &Self::Ciphertext,
        local_sk: &Self::SecretKey,
    ) -> Result<Self::SharedSecret, CryptoError> {
        let ct_array: &[u8; CT_LEN] = ciphertext.0.as_slice().try_into().map_err(|_| {
            CryptoError::Decapsulation(format!(
                "invalid ML-KEM-768 ciphertext length: {}",
                ciphertext.0.len()
            ))
        })?;
        let ct = ml_kem::Ciphertext::<MlKem768>::from(*ct_array);
        let ss = local_sk.0.try_decapsulate(&ct)
            .map_err(|e| CryptoError::Decapsulation(format!("{e:?}")))?;
        Ok(MlKemSharedSecret(shared_key_to_bytes(&ss)))
    }

    fn public_key_len() -> usize {
        EK_LEN
    }

    fn ciphertext_len() -> usize {
        CT_LEN
    }

    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, CryptoError> {
        if bytes.len() != EK_LEN {
            return Err(CryptoError::InvalidKeyMaterial(format!(
                "expected {} bytes, got {}",
                EK_LEN,
                bytes.len()
            )));
        }
        Ok(MlKemPublicKey(bytes.to_vec()))
    }

    fn ciphertext_from_bytes(bytes: &[u8]) -> Result<Self::Ciphertext, CryptoError> {
        if bytes.len() != CT_LEN {
            return Err(CryptoError::InvalidKeyMaterial(format!(
                "expected {} bytes, got {}",
                CT_LEN,
                bytes.len()
            )));
        }
        Ok(MlKemCiphertext(bytes.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encapsulate_decapsulate_roundtrip() {
        let (pk, sk) = MlKem768Kem::generate_keypair();
        let (ss_enc, ct) = MlKem768Kem::encapsulate(&pk).unwrap();
        let ss_dec = MlKem768Kem::decapsulate(&ct, &sk).unwrap();
        assert_eq!(ss_enc.as_ref(), ss_dec.as_ref());
    }

    #[test]
    fn public_key_has_correct_length() {
        let (pk, _) = MlKem768Kem::generate_keypair();
        assert_eq!(pk.as_ref().len(), EK_LEN);
    }

    #[test]
    fn ciphertext_has_correct_length() {
        let (pk, _) = MlKem768Kem::generate_keypair();
        let (_, ct) = MlKem768Kem::encapsulate(&pk).unwrap();
        assert_eq!(ct.as_ref().len(), CT_LEN);
    }

    #[test]
    fn shared_secret_is_32_bytes() {
        let (pk, _) = MlKem768Kem::generate_keypair();
        let (ss, _) = MlKem768Kem::encapsulate(&pk).unwrap();
        assert_eq!(ss.as_ref().len(), 32);
    }

    #[test]
    fn wrong_length_rejected() {
        assert!(MlKem768Kem::public_key_from_bytes(&[0u8; 32]).is_err());
        assert!(MlKem768Kem::ciphertext_from_bytes(&[0u8; 32]).is_err());
    }
}
