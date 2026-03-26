//! ZK-VM host program: executes the guest inside the zkVM and verifies outputs.
//!
//! Usage:
//!   cargo run --release --bin shieldnode-zkvm-host           # execute only (fast)
//!   cargo run --release --bin shieldnode-zkvm-host -- prove  # full proof generation
//!
//! In production, the node runs this after receiving a challenge.
//! The resulting proof is submitted on-chain to the ChallengeManager.

use std::time::Instant;

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use risc0_zkvm::{default_executor, default_prover, serde::from_slice, ExecutorEnv};
use sha2::{Digest, Sha256};
use shieldnode_zkvm_methods::{SHIELDNODE_ZKVM_GUEST_ELF, SHIELDNODE_ZKVM_GUEST_ID};

fn main() {
    let prove_mode = std::env::args().any(|a| a == "prove");

    println!("=== ShieldNode ZK-VM Relay Proof ===");
    println!("Mode: {}\n", if prove_mode { "PROVE" } else { "execute-only" });

    // ── Step 1: Create a test packet ─────────────────────────────
    let session_key = [0x42u8; 32];
    let nonce_bytes = [0u8; 12];
    let guest_mode: u8 = 0; // forwarding only

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

    // ── Step 2: Build the zkVM environment ───────────────────────
    let env = ExecutorEnv::builder()
        .write(&guest_mode)
        .unwrap()
        .write(&encrypted)
        .unwrap()
        .write(&session_key)
        .unwrap()
        .write(&nonce_bytes)
        .unwrap()
        .build()
        .unwrap();

    // ── Step 3: Execute or prove ─────────────────────────────────
    let start = Instant::now();

    let journal = if prove_mode {
        println!("\nGenerating ZK proof (this may take a while)...");

        let prover = default_prover();
        let prove_info = prover
            .prove(env, SHIELDNODE_ZKVM_GUEST_ELF)
            .expect("proof generation failed");

        let elapsed = start.elapsed();
        let receipt = prove_info.receipt;

        println!("Proof generated in {:?}", elapsed);
        println!("Receipt segments: {}", prove_info.stats.segments);
        println!("Total cycles: {}", prove_info.stats.total_cycles);

        // Verify the receipt against the guest image ID.
        println!("\nVerifying receipt...");
        let verify_start = Instant::now();
        receipt
            .verify(SHIELDNODE_ZKVM_GUEST_ID)
            .expect("receipt verification failed");
        println!("Receipt verified in {:?}", verify_start.elapsed());

        receipt.journal
    } else {
        println!("\nExecuting guest in zkVM...");

        let executor = default_executor();
        let session = executor
            .execute(env, SHIELDNODE_ZKVM_GUEST_ELF)
            .expect("guest execution failed");

        println!("Execution completed in {:?}", start.elapsed());
        println!(
            "Segments: {}, cycles: {}",
            session.segments.len(),
            session.cycles()
        );

        session.journal
    };

    // ── Step 4: Verify journal outputs ───────────────────────────
    println!("\nJournal size: {} bytes", journal.bytes.len());

    let (committed_next_hop, committed_payload_hash, committed_input_hash): (
        [u8; 32],
        [u8; 32],
        [u8; 32],
    ) = from_slice(&journal.bytes).expect("failed to decode journal");

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

    assert_eq!(committed_next_hop, next_hop, "next_hop mismatch");
    assert_eq!(committed_payload_hash, expected_payload_hash, "payload_hash mismatch");
    assert_eq!(committed_input_hash, expected_input_hash, "input_hash mismatch");

    println!("  next_hop:     VERIFIED {:02x?}...", &committed_next_hop[..4]);
    println!("  payload_hash: VERIFIED {:02x?}...", &committed_payload_hash[..4]);
    println!("  input_hash:   VERIFIED {:02x?}...", &committed_input_hash[..4]);

    println!("\n=== {} ===", if prove_mode {
        "Proof generated and verified successfully"
    } else {
        "Guest execution verified successfully"
    });
}
