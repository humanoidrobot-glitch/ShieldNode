//! ZK-VM host program: executes the guest inside the zkVM and verifies outputs.
//!
//! Two modes:
//! - Execute only: runs guest, validates journal outputs (fast, no proof)
//! - Prove: generates a Groth16 proof for on-chain verification (requires r0vm)
//!
//! In production, the node runs this after receiving a challenge.
//! The resulting proof is submitted on-chain to the ChallengeManager.

use std::time::Instant;

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use risc0_zkvm::{default_executor, serde::from_slice, ExecutorEnv};
use sha2::{Digest, Sha256};
use shieldnode_zkvm_methods::SHIELDNODE_ZKVM_GUEST_ELF;

fn main() {
    println!("=== ShieldNode ZK-VM Relay Proof ===\n");

    // ── Step 1: Create a test packet ─────────────────────────────
    let session_key = [0x42u8; 32];
    let nonce_bytes = [0u8; 12];
    let mode: u8 = 0; // forwarding only

    let mut plaintext = Vec::new();
    let next_hop = [0xAB; 32];
    let inner_payload = b"hello from the relay zkvm proof";
    plaintext.extend_from_slice(&next_hop);
    plaintext.extend_from_slice(inner_payload);

    let cipher = ChaCha20Poly1305::new((&session_key).into());
    let encrypted = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_slice())
        .expect("encryption failed");

    println!("Encrypted packet: {} bytes", encrypted.len());
    println!("Mode: {} (forwarding only)", mode);

    // ── Step 2: Build the zkVM environment ───────────────────────
    // Guest reads in order: mode, encrypted_payload, session_key, nonce
    let env = ExecutorEnv::builder()
        .write(&mode)
        .unwrap()
        .write(&encrypted)
        .unwrap()
        .write(&session_key)
        .unwrap()
        .write(&nonce_bytes)
        .unwrap()
        .build()
        .unwrap();

    // ── Step 3: Execute guest in the zkVM ────────────────────────
    println!("\nExecuting guest in zkVM...");
    let start = Instant::now();

    let executor = default_executor();
    let session = executor
        .execute(env, SHIELDNODE_ZKVM_GUEST_ELF)
        .expect("guest execution failed");

    println!("Execution completed in {:?}", start.elapsed());

    // ── Step 4: Verify journal outputs ───────────────────────────
    let journal = &session.journal;
    println!("\nJournal size: {} bytes", journal.bytes.len());

    // Guest commits three [u8; 32] values via env::commit (risc0 serde format).
    // Each byte is padded to a u32 word, so 32 bytes → 128 bytes per commit.
    let (committed_next_hop, committed_payload_hash, committed_input_hash): (
        [u8; 32],
        [u8; 32],
        [u8; 32],
    ) = from_slice(&journal.bytes).expect("failed to decode journal");

    // Compute expected values on the host side.
    let expected_payload_hash = {
        let mut h = Sha256::new();
        h.update(inner_payload);
        let r = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&r);
        out
    };

    let expected_input_hash = {
        let mut h = Sha256::new();
        h.update(&encrypted);
        let r = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&r);
        out
    };

    // Verify all outputs match.
    assert_eq!(
        committed_next_hop, next_hop,
        "next_hop mismatch: guest routed to wrong destination"
    );
    assert_eq!(
        committed_payload_hash, expected_payload_hash,
        "payload_hash mismatch: inner payload was corrupted"
    );
    assert_eq!(
        committed_input_hash, expected_input_hash,
        "input_hash mismatch: encrypted input binding is wrong"
    );

    println!("  next_hop:     VERIFIED {:02x?}...", &committed_next_hop[..4]);
    println!(
        "  payload_hash: VERIFIED {:02x?}...",
        &committed_payload_hash[..4]
    );
    println!(
        "  input_hash:   VERIFIED {:02x?}...",
        &committed_input_hash[..4]
    );
    println!(
        "\nExecution: {} segments, {} total cycles",
        session.segments.len(),
        session.cycles()
    );
    println!("\n=== Guest execution verified successfully ===");
}
