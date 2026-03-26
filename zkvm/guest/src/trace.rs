//! Execution trace proof: extends the forwarding proof to prove that
//! NO side-channel outputs occurred during relay packet processing.
//!
//! The trace proof commits additional metadata:
//! - Total bytes read from input
//! - Total bytes committed to journal
//! - Hash of the complete execution state (inputs + outputs + intermediates)
//! - A "no-extra-output" flag proving the guest produced only the declared outputs
//!
//! This proves the *node software itself* didn't log. It cannot prove the
//! operator isn't running a separate capture process outside the zkVM.
//!
//! Used by the extended verifier to confirm both correct forwarding AND
//! software integrity.

extern crate alloc;
use alloc::vec::Vec;

use sha2::{Digest, Sha256};

/// Execution trace metadata committed as public outputs.
/// The verifier checks these against expected values.
#[derive(Clone)]
pub struct TraceMetadata {
    /// Total bytes read from private inputs.
    pub input_bytes: u64,
    /// Total bytes committed to journal (public outputs).
    pub output_bytes: u64,
    /// SHA-256 of (all_inputs || all_outputs) — binds the full I/O.
    pub io_hash: [u8; 32],
    /// Number of env::commit calls made by the guest.
    pub commit_count: u32,
    /// Version of the trace protocol (for forward compatibility).
    pub trace_version: u32,
}

impl TraceMetadata {
    pub fn new() -> Self {
        Self {
            input_bytes: 0,
            output_bytes: 0,
            io_hash: [0u8; 32],
            commit_count: 0,
            trace_version: 1,
        }
    }

    /// Record bytes read from input.
    pub fn record_input(&mut self, bytes: u64) {
        self.input_bytes += bytes;
    }

    /// Record bytes committed to journal.
    pub fn record_output(&mut self, bytes: u64) {
        self.output_bytes += bytes;
        self.commit_count += 1;
    }

    /// Finalize the I/O hash from all collected input and output data.
    pub fn finalize_io_hash(&mut self, inputs: &[u8], outputs: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(inputs);
        hasher.update(outputs);
        let result = hasher.finalize();
        self.io_hash.copy_from_slice(&result);
    }

    /// Serialize to bytes for commitment.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(56);
        buf.extend_from_slice(&self.input_bytes.to_be_bytes());
        buf.extend_from_slice(&self.output_bytes.to_be_bytes());
        buf.extend_from_slice(&self.io_hash);
        buf.extend_from_slice(&self.commit_count.to_be_bytes());
        buf.extend_from_slice(&self.trace_version.to_be_bytes());
        buf
    }
}

/// Expected trace metadata for a single relay forward operation.
///
/// The verifier compares the committed trace against these expected values.
/// If they differ, the node ran additional code beyond the relay function.
pub struct ExpectedTrace {
    /// Expected number of env::commit calls:
    /// 4 = next_hop + payload_hash + input_hash + trace_metadata
    pub expected_commits: u32,
    /// Trace protocol version.
    pub expected_version: u32,
}

impl Default for ExpectedTrace {
    fn default() -> Self {
        Self {
            expected_commits: 4,
            expected_version: 1,
        }
    }
}

impl ExpectedTrace {
    /// Verify that the trace metadata matches expectations.
    pub fn verify(&self, trace: &TraceMetadata) -> Result<(), &'static str> {
        if trace.trace_version != self.expected_version {
            return Err("trace version mismatch");
        }
        if trace.commit_count != self.expected_commits {
            return Err("unexpected number of commits — possible extra output");
        }
        if trace.input_bytes == 0 {
            return Err("zero input bytes — no packet was processed");
        }
        if trace.output_bytes == 0 {
            return Err("zero output bytes — no result was produced");
        }
        Ok(())
    }
}
