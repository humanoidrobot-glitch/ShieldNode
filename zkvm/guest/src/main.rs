//! ZK-VM guest program: proves correct relay packet forwarding AND
//! execution trace integrity (no side-channel outputs).
//!
//! Two proof modes:
//! - Mode 0 (forwarding only): proves correct decryption and routing
//! - Mode 1 (full trace): proves forwarding + no extra outputs occurred
//!
//! The full trace mode commits additional metadata: total I/O bytes,
//! commit count, and a hash binding all inputs to all outputs. The
//! verifier checks that the commit count matches exactly what the
//! honest relay function should produce (4 commits), proving no
//! hidden data was leaked via the journal.

#![no_main]
#![no_std]

extern crate alloc;
use alloc::vec::Vec;

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use risc0_zkvm::guest::env;

mod trace;
use trace::TraceMetadata;

/// Pure relay forwarding function — identical logic to
/// node/src/tunnel/circuit.rs process_relay_packet().
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

fn sha2_hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

risc0_zkvm::guest::entry!(main);

fn main() {
    // Read proof mode: 0 = forwarding only, 1 = full execution trace.
    let mode: u8 = env::read();

    // Read private inputs.
    let encrypted_payload: Vec<u8> = env::read();
    let session_key: [u8; 32] = env::read();
    let nonce_bytes: [u8; 12] = env::read();

    // Initialize trace accounting.
    let mut trace = TraceMetadata::new();
    trace.record_input(1); // mode byte
    trace.record_input(encrypted_payload.len() as u64);
    trace.record_input(32); // session key
    trace.record_input(12); // nonce

    // Execute the relay function.
    let (next_hop, inner_payload) = process_relay_packet(
        &encrypted_payload,
        &session_key,
        &nonce_bytes,
    )
    .expect("relay packet processing failed inside zkVM");

    // Commit public outputs.
    // 1. next_hop — proves correct routing.
    env::commit(&next_hop);
    trace.record_output(32);

    // 2. payload_hash — proves content integrity without revealing payload.
    let payload_hash = sha2_hash(&inner_payload);
    env::commit(&payload_hash);
    trace.record_output(32);

    // 3. input_hash — ties proof to the specific challenged packet.
    let input_hash = sha2_hash(&encrypted_payload);
    env::commit(&input_hash);
    trace.record_output(32);

    // 4. If full trace mode, commit the trace metadata.
    if mode == 1 {
        // Compute I/O hash with a running hasher (no Vec allocation).
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&[mode]);
        hasher.update(&encrypted_payload);
        hasher.update(&session_key);
        hasher.update(&nonce_bytes);
        hasher.update(&next_hop);
        hasher.update(&payload_hash);
        hasher.update(&input_hash);
        let io_result = hasher.finalize();
        trace.io_hash.copy_from_slice(&io_result);

        let trace_bytes = trace.to_bytes();
        trace.record_output(trace_bytes.len() as u64);
        env::commit_slice(&trace_bytes);
    }

    // NOTE: The real security guarantee comes from the image ID — the
    // verifier checks that this specific guest binary (identified by its
    // ELF hash) produced the proof. The commit_count in TraceMetadata is
    // a defense-in-depth check, not the primary invariant. A different
    // guest binary would have a different image ID and be rejected.
}
