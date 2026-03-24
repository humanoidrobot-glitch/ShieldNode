use std::collections::HashMap;
use std::time::Instant;

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use thiserror::Error;

// ── errors ─────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum CircuitError {
    #[error("circuit {0} not found")]
    NotFound(u64),
    #[error("circuit {0} is not active")]
    Inactive(u64),
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("no next hop in circuit")]
    NoNextHop,
}

// ── data types ─────────────────────────────────────────────────────────

/// Describes a single hop in a multi-hop circuit.
#[derive(Debug, Clone)]
pub struct HopInfo {
    /// Peer identifier (e.g. libp2p PeerId as base-58 string).
    pub node_id: String,
    /// X25519 public key of this hop (32 bytes).
    pub public_key: [u8; 32],
    /// Network endpoint, e.g. "1.2.3.4:4001".
    pub endpoint: String,
    /// Symmetric session key negotiated with this hop (32 bytes).
    pub session_key: Option<[u8; 32]>,
}

/// A multi-hop circuit through the relay network.
#[derive(Debug, Clone)]
pub struct Circuit {
    pub circuit_id: u64,
    pub hops: Vec<HopInfo>,
    pub created_at: Instant,
    pub is_active: bool,
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

    /// Create a new circuit with the given hop list and return its id.
    pub fn create_circuit(&mut self, hops: Vec<HopInfo>) -> u64 {
        let id = self.next_id;
        self.next_id += 1;

        let circuit = Circuit {
            circuit_id: id,
            hops,
            created_at: Instant::now(),
            is_active: true,
        };
        self.circuits.insert(id, circuit);
        id
    }

    /// Gracefully tear down a circuit by id.
    pub fn teardown_circuit(
        &mut self,
        circuit_id: u64,
    ) -> Result<(), CircuitError> {
        let circuit = self
            .circuits
            .get_mut(&circuit_id)
            .ok_or(CircuitError::NotFound(circuit_id))?;
        circuit.is_active = false;
        Ok(())
    }

    /// Retrieve a reference to an active circuit.
    pub fn get_circuit(
        &self,
        circuit_id: u64,
    ) -> Result<&Circuit, CircuitError> {
        let circuit = self
            .circuits
            .get(&circuit_id)
            .ok_or(CircuitError::NotFound(circuit_id))?;
        if !circuit.is_active {
            return Err(CircuitError::Inactive(circuit_id));
        }
        Ok(circuit)
    }

    /// Return the number of currently active circuits.
    pub fn active_count(&self) -> usize {
        self.circuits.values().filter(|c| c.is_active).count()
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
/// This function is intentionally **pure** — it takes immutable
/// references, performs no I/O, and is fully deterministic for a given
/// `(encrypted_payload, session_key, nonce)` triple.  This makes it
/// suitable for future ZK proof generation.
pub fn process_relay_packet(
    encrypted_payload: &[u8],
    session_key: &[u8; 32],
    nonce_bytes: &[u8; 12],
) -> Result<(String, Vec<u8>), CircuitError> {
    let cipher = ChaCha20Poly1305::new_from_slice(session_key)
        .map_err(|e| CircuitError::DecryptionFailed(e.to_string()))?;

    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, encrypted_payload)
        .map_err(|e| CircuitError::DecryptionFailed(e.to_string()))?;

    // Protocol: first 32 bytes of the plaintext are a UTF-8 next-hop id
    // (right-padded with 0x00), remainder is the inner payload.
    if plaintext.len() < 32 {
        return Err(CircuitError::NoNextHop);
    }

    let next_hop_raw = &plaintext[..32];
    let next_hop = String::from_utf8_lossy(next_hop_raw)
        .trim_end_matches('\0')
        .to_string();
    let inner_payload = plaintext[32..].to_vec();

    Ok((next_hop, inner_payload))
}
