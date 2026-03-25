//! Micro-ratcheting session keys.
//!
//! Rekeys the symmetric session key every REKEY_INTERVAL or REKEY_BYTES,
//! whichever comes first. Each ratchet step derives a new ChaCha20-Poly1305
//! key via HKDF-SHA256 from the current key material. Previous keys are
//! zeroized immediately.
//!
//! If an attacker captures ciphertext and later obtains one session key,
//! they get at most one ratchet window of traffic. All previous and
//! subsequent windows remain secure (forward secrecy).
//!
//! Follows Signal's Double Ratchet principle adapted for tunnel traffic.

use std::time::{Duration, Instant};

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use super::aead;

/// Rekey interval: 30 seconds.
const REKEY_INTERVAL: Duration = Duration::from_secs(30);

/// Rekey after this many bytes encrypted under a single key.
const REKEY_BYTES: u64 = 10 * 1024 * 1024; // 10 MB

/// HKDF info string for ratchet derivation.
const RATCHET_INFO: &[u8] = b"shieldnode-ratchet-v1";

/// A ratcheting symmetric cipher that automatically rekeys.
///
/// Wraps ChaCha20-Poly1305, replacing the session key on a schedule.
/// Previous keys are zeroized on drop and on ratchet step.
pub struct Ratchet {
    /// Current encryption key (32 bytes).
    current_key: [u8; 32],
    /// Chain key used to derive the next session key.
    chain_key: [u8; 32],
    /// Current epoch number (increments on each ratchet step).
    epoch: u64,
    /// Bytes encrypted under the current key.
    bytes_this_epoch: u64,
    /// When the current epoch started.
    epoch_start: Instant,
    /// Nonce counter within the current epoch.
    nonce_counter: u64,
}

impl Ratchet {
    /// Create a new ratchet from an initial session key.
    ///
    /// The initial key is typically derived from the Noise/hybrid handshake.
    pub fn new(initial_key: [u8; 32]) -> Self {
        // Derive initial chain key and encryption key from the session key.
        let (chain_key, current_key) = derive_keys(&initial_key, 0);

        Self {
            current_key,
            chain_key,
            epoch: 0,
            bytes_this_epoch: 0,
            epoch_start: Instant::now(),
            nonce_counter: 0,
        }
    }

    /// Current epoch number.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Check if a ratchet step is due (time or data threshold).
    pub fn needs_rekey(&self) -> bool {
        self.epoch_start.elapsed() >= REKEY_INTERVAL
            || self.bytes_this_epoch >= REKEY_BYTES
    }

    /// Advance to the next epoch. Zeroizes the old key.
    pub fn ratchet_step(&mut self) {
        let mut old_key = self.current_key;
        let mut old_chain = self.chain_key;

        self.epoch += 1;
        let (new_chain, new_key) = derive_keys(&old_chain, self.epoch);

        self.chain_key = new_chain;
        self.current_key = new_key;
        self.bytes_this_epoch = 0;
        self.epoch_start = Instant::now();
        self.nonce_counter = 0;

        // Zeroize old key material.
        old_key.zeroize();
        old_chain.zeroize();
    }

    /// Encrypt plaintext, automatically rekeying if thresholds are exceeded.
    ///
    /// Returns `(epoch, ciphertext)` so the receiver knows which epoch's
    /// key to use for decryption.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(u64, Vec<u8>), String> {
        if self.needs_rekey() {
            self.ratchet_step();
        }

        let nonce = aead::nonce_from_index(self.nonce_counter);
        self.nonce_counter += 1;

        let ciphertext = aead::encrypt_with_nonce(&self.current_key, &nonce, plaintext)
            .map_err(|e| format!("ratchet encrypt failed: {e}"))?;

        self.bytes_this_epoch += plaintext.len() as u64;

        Ok((self.epoch, ciphertext))
    }

    /// Decrypt ciphertext for a given epoch and nonce.
    ///
    /// The caller must track which epoch the ciphertext belongs to.
    /// For the current epoch, uses the current key. For the previous
    /// epoch (during transition), a one-step-back key would be needed —
    /// this simplified implementation only decrypts with the current key.
    pub fn decrypt(
        &self,
        epoch: u64,
        nonce_index: u64,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, String> {
        if epoch != self.epoch {
            return Err(format!(
                "epoch mismatch: expected {}, got {epoch}",
                self.epoch
            ));
        }

        let nonce = aead::nonce_from_index(nonce_index);
        aead::decrypt_with_nonce(&self.current_key, &nonce, ciphertext)
            .map_err(|e| format!("ratchet decrypt failed: {e}"))
    }

    /// Synchronize to a specific epoch (for resync after desynchronization).
    /// Advances the ratchet from current epoch to the target epoch.
    pub fn advance_to_epoch(&mut self, target_epoch: u64) {
        while self.epoch < target_epoch {
            self.ratchet_step();
        }
    }
}

impl Drop for Ratchet {
    fn drop(&mut self) {
        self.current_key.zeroize();
        self.chain_key.zeroize();
    }
}

// ── key derivation ────────────────────────────────────────────────────

/// Derive a (chain_key, encryption_key) pair from input key material.
///
/// Uses HKDF-SHA256 with the epoch as salt context.
fn derive_keys(ikm: &[u8; 32], epoch: u64) -> ([u8; 32], [u8; 32]) {
    let salt = epoch.to_be_bytes();
    let hk = Hkdf::<Sha256>::new(Some(&salt), ikm);

    let mut chain_key = [0u8; 32];
    hk.expand(RATCHET_INFO, &mut chain_key)
        .expect("32 bytes is valid HKDF output");

    // Derive encryption key from chain key with a different info string.
    let hk2 = Hkdf::<Sha256>::new(Some(&salt), &chain_key);
    let mut enc_key = [0u8; 32];
    hk2.expand(b"shieldnode-ratchet-enc", &mut enc_key)
        .expect("32 bytes is valid HKDF output");

    (chain_key, enc_key)
}

// ── ratchet step control message ──────────────────────────────────────

/// Magic bytes identifying a ratchet-step control message in the Sphinx layer.
pub const RATCHET_STEP_MAGIC: [u8; 4] = [0x52, 0x41, 0x54, 0x43]; // "RATC"

/// Build a ratchet-step control message announcing a new epoch.
///
/// This is sent as a fixed-size Sphinx packet with the control flag.
/// The receiving side advances its ratchet to the announced epoch.
pub fn build_ratchet_step_message(new_epoch: u64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(12);
    msg.extend_from_slice(&RATCHET_STEP_MAGIC);
    msg.extend_from_slice(&new_epoch.to_be_bytes());
    msg
}

/// Parse a ratchet-step control message.
/// Returns the new epoch if the message is valid, None otherwise.
pub fn parse_ratchet_step_message(data: &[u8]) -> Option<u64> {
    if data.len() < 12 {
        return None;
    }
    if data[..4] != RATCHET_STEP_MAGIC {
        return None;
    }
    let epoch = u64::from_be_bytes(data[4..12].try_into().ok()?);
    Some(epoch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let mut ratchet = Ratchet::new(key);

        let plaintext = b"hello shieldnode ratchet";
        let (epoch, ct) = ratchet.encrypt(plaintext).unwrap();

        // Decrypt with nonce_counter - 1 (since encrypt incremented it).
        let pt = ratchet.decrypt(epoch, 0, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn different_epochs_produce_different_ciphertext() {
        let key = [0x42u8; 32];
        let mut r1 = Ratchet::new(key);
        let mut r2 = Ratchet::new(key);

        let plaintext = b"same input";
        let (_, ct1) = r1.encrypt(plaintext).unwrap();

        r2.ratchet_step(); // advance r2 to epoch 1
        let (_, ct2) = r2.encrypt(plaintext).unwrap();

        assert_ne!(ct1, ct2, "different epochs should produce different ciphertext");
    }

    #[test]
    fn ratchet_step_changes_epoch() {
        let mut ratchet = Ratchet::new([0x01; 32]);
        assert_eq!(ratchet.epoch(), 0);

        ratchet.ratchet_step();
        assert_eq!(ratchet.epoch(), 1);

        ratchet.ratchet_step();
        assert_eq!(ratchet.epoch(), 2);
    }

    #[test]
    fn ratchet_step_resets_counters() {
        let mut ratchet = Ratchet::new([0x01; 32]);
        ratchet.bytes_this_epoch = 5_000_000;
        ratchet.nonce_counter = 100;

        ratchet.ratchet_step();

        assert_eq!(ratchet.bytes_this_epoch, 0);
        assert_eq!(ratchet.nonce_counter, 0);
    }

    #[test]
    fn needs_rekey_after_byte_threshold() {
        let mut ratchet = Ratchet::new([0x01; 32]);
        assert!(!ratchet.needs_rekey());

        ratchet.bytes_this_epoch = REKEY_BYTES;
        assert!(ratchet.needs_rekey());
    }

    #[test]
    fn auto_rekey_on_encrypt() {
        let mut ratchet = Ratchet::new([0x01; 32]);
        ratchet.bytes_this_epoch = REKEY_BYTES; // force rekey threshold

        let (epoch, _) = ratchet.encrypt(b"triggers rekey").unwrap();
        assert_eq!(epoch, 1, "should have rekeyed to epoch 1");
    }

    #[test]
    fn advance_to_epoch_catches_up() {
        let mut ratchet = Ratchet::new([0x01; 32]);
        ratchet.advance_to_epoch(5);
        assert_eq!(ratchet.epoch(), 5);
    }

    #[test]
    fn synchronized_ratchets_can_communicate() {
        let key = [0xAB; 32];
        let mut sender = Ratchet::new(key);
        let mut receiver = Ratchet::new(key);

        // Both start at epoch 0.
        let plaintext = b"message in epoch 0";
        let (epoch, ct) = sender.encrypt(plaintext).unwrap();
        let pt = receiver.decrypt(epoch, 0, &ct).unwrap();
        assert_eq!(pt, plaintext);

        // Both ratchet to epoch 1.
        sender.ratchet_step();
        receiver.ratchet_step();

        let plaintext2 = b"message in epoch 1";
        let (epoch2, ct2) = sender.encrypt(plaintext2).unwrap();
        let pt2 = receiver.decrypt(epoch2, 0, &ct2).unwrap();
        assert_eq!(pt2, plaintext2);
    }

    #[test]
    fn epoch_mismatch_fails_decrypt() {
        let mut ratchet = Ratchet::new([0x01; 32]);
        let (_, ct) = ratchet.encrypt(b"data").unwrap();

        ratchet.ratchet_step(); // advance to epoch 1

        // Try to decrypt epoch 0 data with epoch 1 key.
        assert!(ratchet.decrypt(0, 0, &ct).is_err());
    }

    #[test]
    fn control_message_roundtrip() {
        let msg = build_ratchet_step_message(42);
        let epoch = parse_ratchet_step_message(&msg).unwrap();
        assert_eq!(epoch, 42);
    }

    #[test]
    fn control_message_rejects_garbage() {
        assert!(parse_ratchet_step_message(&[0; 4]).is_none());
        assert!(parse_ratchet_step_message(b"XXXX00000000").is_none());
    }
}
