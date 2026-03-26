//! ZK-VM guest program: proves correct relay packet forwarding.
//!
//! Runs inside RISC Zero's zkVM. Reads private inputs (encrypted packet,
//! session key, nonce), executes ChaCha20-Poly1305 decryption, extracts
//! the next_hop and inner payload, and commits the result as a public output.
//!
//! The proof attests: "given these inputs, the relay function produced
//! this exact output — nothing else happened."

// RISC Zero guest programs use a special no_std environment.
// When building for the zkVM target, std is not available.
#![no_main]
#![no_std]

extern crate alloc;
use alloc::vec::Vec;

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use risc0_zkvm::guest::env;

/// The relay forwarding function — identical to node/src/tunnel/circuit.rs
/// process_relay_packet(), reproduced here for zkVM compilation.
///
/// Pure function: decrypt one Sphinx layer, extract next_hop, return payload.
fn process_relay_packet(
    encrypted_payload: &[u8],
    session_key: &[u8; 32],
    nonce_bytes: &[u8; 12],
) -> Result<([u8; 32], Vec<u8>), &'static str> {
    let cipher = ChaCha20Poly1305::new(session_key.into());
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, encrypted_payload)
        .map_err(|_| "decryption failed")?;

    if plaintext.len() < 32 {
        return Err("payload too short for next_hop");
    }

    let mut next_hop = [0u8; 32];
    next_hop.copy_from_slice(&plaintext[..32]);
    let inner_payload = plaintext[32..].to_vec();

    Ok((next_hop, inner_payload))
}

risc0_zkvm::guest::entry!(main);

fn main() {
    // Read private inputs from the host.
    let encrypted_payload: Vec<u8> = env::read();
    let session_key: [u8; 32] = env::read();
    let nonce_bytes: [u8; 12] = env::read();

    // Execute the relay function.
    let (next_hop, inner_payload) = process_relay_packet(
        &encrypted_payload,
        &session_key,
        &nonce_bytes,
    )
    .expect("relay packet processing failed inside zkVM");

    // Commit public outputs: the next_hop and a hash of the inner payload.
    // The inner payload itself is not committed (it's private to the circuit).
    // The next_hop proves the relay routed correctly.
    // The payload hash proves the content was not modified.
    env::commit(&next_hop);

    // Commit hash of inner payload (not the payload itself — privacy).
    let payload_hash = sha2_hash(&inner_payload);
    env::commit(&payload_hash);

    // Commit hash of the encrypted input (so the challenger can verify
    // the proof was generated for the specific packet they challenged).
    let input_hash = sha2_hash(&encrypted_payload);
    env::commit(&input_hash);
}

/// Simple SHA-256 hash for commitment (the zkVM has native SHA-256 support).
fn sha2_hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}
