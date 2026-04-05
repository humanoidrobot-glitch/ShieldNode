//! ZK no-log compliance proof: proves the node's runtime state contains
//! no connection metadata beyond what active forwarding requires.
//!
//! The node serializes a snapshot of its session registry and bandwidth
//! tracker. The ZK guest verifies structural invariants:
//!
//! 1. Session registry contains only entries in the declared active set
//! 2. No session has a zero key (indicates improper cleanup)
//! 3. Bandwidth tracker has no orphaned entries (sessions not in registry)
//! 4. Total session count is within the declared bound
//! 5. No raw IP addresses or packet payloads are stored
//!
//! The guest commits: state_hash, active_session_count, timestamp, node_id.
//! The on-chain verifier checks these against the node's registration.
//!
//! Limitation: this proves the *declared state* has no logs. It cannot
//! prove the operator isn't maintaining a separate logging process outside
//! the node binary. That threat requires TEE attestation (Phase 5).

extern crate alloc;
use alloc::vec::Vec;

use sha2::{Digest, Sha256};

/// Maximum sessions a node can declare in a compliance proof.
/// Prevents unbounded proof size. Nodes with more sessions must
/// submit multiple proofs or increase this bound.
pub const MAX_SESSIONS: usize = 1024;

/// All 6 compliance checks passed. Matches NoLogVerifier.sol ALL_CHECKS_PASSED.
pub const ALL_CHECKS_PASSED: u8 = 0x3F;

/// A serialized snapshot of the node's runtime state for compliance proving.
///
/// The node constructs this by reading its `RelayService.sessions` and
/// `BandwidthTracker` state, then passes it as private input to the guest.
#[derive(Clone)]
pub struct ComplianceSnapshot {
    /// Node's on-chain identifier (public key hash or address).
    pub node_id: [u8; 32],
    /// Unix timestamp when the snapshot was taken.
    pub timestamp: u64,
    /// Active session IDs from the session registry.
    pub session_ids: Vec<u64>,
    /// SHA-256 of each session's key material (proves keys exist without
    /// revealing them). One per session, same order as session_ids.
    pub session_key_hashes: Vec<[u8; 32]>,
    /// Bandwidth tracker session IDs (should match session_ids exactly).
    pub bandwidth_session_ids: Vec<u64>,
    /// Per-session byte counts from bandwidth tracker: (bytes_in, bytes_out).
    pub bandwidth_counts: Vec<(u64, u64)>,
}

/// Public outputs committed to the journal after compliance verification.
#[derive(Clone)]
pub struct ComplianceOutput {
    /// SHA-256 of the entire snapshot (binds proof to specific state).
    pub state_hash: [u8; 32],
    /// Node identifier.
    pub node_id: [u8; 32],
    /// Timestamp of the snapshot.
    pub timestamp: u64,
    /// Number of active sessions at proof time.
    pub active_session_count: u32,
    /// Whether all invariants passed.
    pub compliant: bool,
    /// Bitmask of which checks passed (for partial compliance reporting).
    /// Bit 0 (0x01): session count within bounds
    /// Bit 1 (0x02): no zero-key sessions
    /// Bit 2 (0x04): session IDs and key hashes consistent
    /// Bit 3 (0x08): no orphaned bandwidth entries
    /// Bit 4 (0x10): bandwidth entries and counts consistent
    /// Bit 5 (0x20): no duplicate session IDs
    pub check_flags: u8,
}

impl ComplianceOutput {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 32 + 8 + 4 + 1 + 1);
        buf.extend_from_slice(&self.state_hash);
        buf.extend_from_slice(&self.node_id);
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.active_session_count.to_be_bytes());
        buf.push(self.compliant as u8);
        buf.push(self.check_flags);
        buf
    }
}

/// Verify the compliance snapshot and return the public output.
pub fn verify_compliance(snapshot: &ComplianceSnapshot) -> ComplianceOutput {
    let mut check_flags: u8 = 0;

    // Sort session IDs once; reused for both duplicate detection (check 6)
    // and O(n log n) orphan lookup (check 4) instead of O(n²) .contains().
    let mut sorted_ids = snapshot.session_ids.clone();
    sorted_ids.sort_unstable();

    // Check 1: session count within bounds (prevents unbounded proof size).
    if snapshot.session_ids.len() <= MAX_SESSIONS {
        check_flags |= 0x01;
    }

    // Check 2: zero-key hash indicates improper cleanup or uninitialized session.
    if snapshot.session_key_hashes.iter().all(|h| *h != [0u8; 32]) {
        check_flags |= 0x02;
    }

    // Check 3: session registry vectors must be equal length.
    if snapshot.session_ids.len() == snapshot.session_key_hashes.len() {
        check_flags |= 0x04;
    }

    // Check 4: orphaned bandwidth entries (sessions removed but bandwidth
    // data retained) are a logging signal. Binary search on sorted IDs.
    if snapshot
        .bandwidth_session_ids
        .iter()
        .all(|bw_id| sorted_ids.binary_search(bw_id).is_ok())
    {
        check_flags |= 0x08;
    }

    // Check 5: bandwidth tracker vectors must be equal length.
    if snapshot.bandwidth_session_ids.len() == snapshot.bandwidth_counts.len() {
        check_flags |= 0x10;
    }

    // Check 6: duplicates in sorted array detected via adjacent comparison.
    if sorted_ids.len() <= 1 || sorted_ids.windows(2).all(|w| w[0] != w[1]) {
        check_flags |= 0x20;
    }

    let compliant = check_flags == ALL_CHECKS_PASSED;

    // Compute state hash: SHA-256 over the entire snapshot.
    let state_hash = compute_state_hash(snapshot);

    ComplianceOutput {
        state_hash,
        node_id: snapshot.node_id,
        timestamp: snapshot.timestamp,
        active_session_count: snapshot.session_ids.len() as u32,
        compliant,
        check_flags,
    }
}

/// SHA-256 hash of the full snapshot for binding the proof to a specific state.
fn compute_state_hash(snapshot: &ComplianceSnapshot) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&snapshot.node_id);
    hasher.update(&snapshot.timestamp.to_be_bytes());

    // Hash session registry.
    hasher.update(&(snapshot.session_ids.len() as u32).to_be_bytes());
    for (id, key_hash) in snapshot
        .session_ids
        .iter()
        .zip(snapshot.session_key_hashes.iter())
    {
        hasher.update(&id.to_be_bytes());
        hasher.update(key_hash);
    }

    // Hash bandwidth tracker.
    hasher.update(&(snapshot.bandwidth_session_ids.len() as u32).to_be_bytes());
    for (id, (bytes_in, bytes_out)) in snapshot
        .bandwidth_session_ids
        .iter()
        .zip(snapshot.bandwidth_counts.iter())
    {
        hasher.update(&id.to_be_bytes());
        hasher.update(&bytes_in.to_be_bytes());
        hasher.update(&bytes_out.to_be_bytes());
    }

    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}
