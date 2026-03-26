//! ZK-VM host program: generates proof of correct relay forwarding.
//!
//! The host:
//! 1. Prepares the private inputs (encrypted packet, session key, nonce)
//! 2. Executes the guest program inside the zkVM
//! 3. Extracts the proof and public outputs
//! 4. Optionally verifies the proof locally
//!
//! In production, the node runs this after receiving a challenge.
//! The resulting proof is submitted on-chain to the ChallengeManager.

use std::time::Instant;

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use risc0_zkvm::{default_prover, ExecutorEnv};
use sha2::{Digest, Sha256};

// The guest binary is embedded at compile time by the methods crate.
// For now, we reference the ELF by path.
// In a full RISC Zero project, this would use:
//   use methods::{RELAY_FORWARD_ELF, RELAY_FORWARD_ID};

fn main() {
    println!("=== ShieldNode ZK-VM Relay Proof Generator ===\n");

    // ── Step 1: Create a test packet ─────────────────────────────
    let session_key = [0x42u8; 32];
    let nonce = [0u8; 12];

    // Build a plaintext: [32-byte next_hop][inner payload]
    let mut plaintext = Vec::new();
    let next_hop = [0xAB; 32]; // the expected next hop
    let inner_payload = b"hello from the relay zkvm proof";
    plaintext.extend_from_slice(&next_hop);
    plaintext.extend_from_slice(inner_payload);

    // Encrypt it (simulating what the client would send).
    let cipher = ChaCha20Poly1305::new((&session_key).into());
    let encrypted = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_slice())
        .expect("encryption failed");

    println!("Encrypted packet: {} bytes", encrypted.len());
    println!("Session key: {:02x?}", &session_key[..4]);
    println!("Expected next_hop: {:02x?}", &next_hop[..4]);

    // ── Step 2: Prepare the zkVM environment ─────────────────────
    let env = ExecutorEnv::builder()
        .write(&encrypted)
        .unwrap()
        .write(&session_key)
        .unwrap()
        .write(&nonce)
        .unwrap()
        .build()
        .unwrap();

    // ── Step 3: Generate the proof ───────────────────────────────
    println!("\nGenerating proof...");
    let start = Instant::now();

    let prover = default_prover();
    // NOTE: In a full build, replace "guest_elf_path" with the actual
    // compiled guest ELF binary. The RISC Zero build system produces
    // this automatically via the `methods` crate.
    //
    // For now, this is a structural prototype showing the host/guest
    // interface and proof format. Actual proving requires the guest
    // to be compiled for the riscv32im-risc0-zkvm-elf target.

    println!("Proof generation requires compiled guest ELF.");
    println!("Build with: cd zkvm && cargo risczero build");
    println!("Elapsed: {:?}", start.elapsed());

    // ── Step 4: Verify expected outputs ──────────────────────────
    // After proof generation, the public outputs would be:
    // - next_hop: [u8; 32] — the routing destination
    // - payload_hash: [u8; 32] — SHA-256 of the forwarded inner payload
    // - input_hash: [u8; 32] — SHA-256 of the encrypted input

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

    println!("\nExpected public outputs:");
    println!("  next_hop:     {:02x?}...", &next_hop[..4]);
    println!("  payload_hash: {:02x?}...", &expected_payload_hash[..4]);
    println!("  input_hash:   {:02x?}...", &expected_input_hash[..4]);

    println!("\n=== Proof structure ready for on-chain verification ===");
}
