//! Shared HKDF-SHA256 key derivation helper.
//!
//! Used by `ratchet.rs`, `noise.rs`, and `hybrid.rs` to avoid duplicating
//! the HKDF instantiation pattern.

use hkdf::Hkdf;
use sha2::Sha256;

/// Derive key material via HKDF-SHA256.
///
/// Wraps `Hkdf::<Sha256>::new(salt, ikm).expand(info, out)` into a
/// single call with a fixed-size output.
pub fn hkdf_sha256<const N: usize>(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[u8],
) -> [u8; N] {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = [0u8; N];
    hk.expand(info, &mut okm)
        .expect("HKDF-SHA256 expand failed: output length too large");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_output() {
        let a = hkdf_sha256::<32>(Some(b"salt"), b"ikm", b"info");
        let b = hkdf_sha256::<32>(Some(b"salt"), b"ikm", b"info");
        assert_eq!(a, b);
    }

    #[test]
    fn different_info_produces_different_output() {
        let a = hkdf_sha256::<32>(Some(b"salt"), b"ikm", b"info-a");
        let b = hkdf_sha256::<32>(Some(b"salt"), b"ikm", b"info-b");
        assert_ne!(a, b);
    }

    #[test]
    fn supports_64_byte_output() {
        let out = hkdf_sha256::<64>(None, b"ikm", b"info");
        assert_eq!(out.len(), 64);
    }
}
