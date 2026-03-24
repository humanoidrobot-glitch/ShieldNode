use std::collections::HashMap;
use std::time::Instant;

use thiserror::Error;

use crate::crypto::aead;

// ── errors ─────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum CircuitError {
    #[error("circuit {0} not found")]
    NotFound(u64),
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("no next hop in circuit")]
    NoNextHop,
}

// ── data types ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct HopInfo {
    pub node_id: String,
    pub public_key: [u8; 32],
    pub endpoint: String,
    pub session_key: Option<[u8; 32]>,
}

#[derive(Debug, Clone)]
pub struct Circuit {
    pub circuit_id: u64,
    pub hops: Vec<HopInfo>,
    pub created_at: Instant,
}

/// Manages the set of active circuits on this node.
pub struct CircuitManager {
    circuits: HashMap<u64, Circuit>,
    next_id: u64,
}

impl CircuitManager {
    pub fn new() -> Self {
        Self {
            circuits: HashMap::new(),
            next_id: 1,
        }
    }

    pub fn create_circuit(&mut self, hops: Vec<HopInfo>) -> u64 {
        let id = self.next_id;
        self.next_id += 1;

        let circuit = Circuit {
            circuit_id: id,
            hops,
            created_at: Instant::now(),
        };
        self.circuits.insert(id, circuit);
        id
    }

    /// Remove a circuit, freeing its resources.
    pub fn teardown_circuit(
        &mut self,
        circuit_id: u64,
    ) -> Result<Circuit, CircuitError> {
        self.circuits
            .remove(&circuit_id)
            .ok_or(CircuitError::NotFound(circuit_id))
    }

    pub fn get_circuit(
        &self,
        circuit_id: u64,
    ) -> Result<&Circuit, CircuitError> {
        self.circuits
            .get(&circuit_id)
            .ok_or(CircuitError::NotFound(circuit_id))
    }

    pub fn active_count(&self) -> usize {
        self.circuits.len()
    }
}

impl Default for CircuitManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── pure relay function (ZK-provable path) ─────────────────────────────

/// Decrypt one relay layer and return `(next_hop_id, plaintext_payload)`.
///
/// This function is intentionally **pure** — no I/O, fully deterministic
/// for a given `(encrypted_payload, session_key, nonce)` triple, making
/// it suitable for future ZK proof generation.
pub fn process_relay_packet(
    encrypted_payload: &[u8],
    session_key: &[u8; 32],
    nonce_bytes: &[u8; 12],
) -> Result<([u8; 32], Vec<u8>), CircuitError> {
    let plaintext = aead::decrypt_with_nonce(session_key, nonce_bytes, encrypted_payload)
        .map_err(|e| CircuitError::DecryptionFailed(e.to_string()))?;

    if plaintext.len() < 32 {
        return Err(CircuitError::NoNextHop);
    }

    let mut next_hop = [0u8; 32];
    next_hop.copy_from_slice(&plaintext[..32]);
    let inner_payload = plaintext[32..].to_vec();

    Ok((next_hop, inner_payload))
}
