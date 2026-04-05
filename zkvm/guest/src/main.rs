//! ZK-VM guest program: three proof modes for ShieldNode relay nodes.
//!
//! - Mode 0 (forwarding only): proves correct decryption and routing
//! - Mode 1 (full trace): proves forwarding + no extra outputs occurred
//! - Mode 2 (no-log compliance): proves runtime state contains no
//!   connection metadata beyond active sessions

#![no_main]
#![no_std]

extern crate alloc;
use alloc::vec::Vec;

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use risc0_zkvm::guest::env;

mod compliance;
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
    // Read proof mode: 0 = forwarding, 1 = execution trace, 2 = no-log compliance.
    let mode: u8 = env::read();

    if mode == 2 {
        run_compliance_proof();
        return;
    }

    // Modes 0 and 1: relay forwarding proof.
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

/// Mode 2: No-log compliance proof.
///
/// Reads a serialized snapshot of the node's runtime state and verifies
/// it contains no connection metadata beyond active sessions.
fn run_compliance_proof() {
    let node_id: [u8; 32] = env::read();
    let timestamp: u64 = env::read();
    let session_count: u32 = env::read();

    let mut session_ids = Vec::with_capacity(session_count as usize);
    let mut session_key_hashes = Vec::with_capacity(session_count as usize);
    for _ in 0..session_count {
        let id: u64 = env::read();
        let key_hash: [u8; 32] = env::read();
        session_ids.push(id);
        session_key_hashes.push(key_hash);
    }

    let bw_count: u32 = env::read();
    let mut bandwidth_session_ids = Vec::with_capacity(bw_count as usize);
    let mut bandwidth_counts = Vec::with_capacity(bw_count as usize);
    for _ in 0..bw_count {
        let id: u64 = env::read();
        let bytes_in: u64 = env::read();
        let bytes_out: u64 = env::read();
        bandwidth_session_ids.push(id);
        bandwidth_counts.push((bytes_in, bytes_out));
    }

    let snapshot = compliance::ComplianceSnapshot {
        node_id,
        timestamp,
        session_ids,
        session_key_hashes,
        bandwidth_session_ids,
        bandwidth_counts,
    };

    let output = compliance::verify_compliance(&snapshot);

    // Commit public outputs.
    env::commit_slice(&output.to_bytes());
}
