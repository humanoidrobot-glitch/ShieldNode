//! TEE remote attestation for relay nodes.
//!
//! Nodes running inside a TEE (AMD SEV-SNP, Intel SGX/TDX, AWS Nitro)
//! produce a hardware-signed attestation report proving:
//! 1. The relay binary is running inside a genuine hardware enclave
//! 2. The host OS cannot read enclave memory
//! 3. The binary hash matches the audited open-source build
//!
//! The attestation report is submitted at registration and verified by
//! clients before circuit selection. TEE-attested nodes get a scoring
//! bonus and are preferred for the entry position (most sensitive hop).

use serde::{Deserialize, Serialize};

/// Supported TEE platforms.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TeePlatform {
    /// AMD Secure Encrypted Virtualization — Secure Nested Paging.
    AmdSevSnp,
    /// Intel Software Guard Extensions.
    IntelSgx,
    /// Intel Trust Domain Extensions.
    IntelTdx,
    /// AWS Nitro Enclaves.
    AwsNitro,
    /// Unknown or unsupported platform.
    Unknown(String),
}

/// An attestation report from a TEE-enabled relay node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    /// The TEE platform that produced this report.
    pub platform: TeePlatform,
    /// SHA-256 hash of the relay binary running inside the enclave.
    pub binary_hash: [u8; 32],
    /// The hardware-signed attestation data (platform-specific format).
    /// For SEV-SNP: the signed report structure.
    /// For Nitro: the NSM attestation document.
    pub report_data: Vec<u8>,
    /// Timestamp when the attestation was generated (Unix seconds).
    pub timestamp: u64,
    /// Node ID this attestation belongs to.
    pub node_id: String,
}

/// Result of verifying an attestation report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AttestationVerdict {
    /// Attestation passes structural validation: correct size, binary hash
    /// matches expected, report is fresh. Full hardware signature verification
    /// is TODO (requires platform-specific SDKs: sevctl, Intel DCAP, AWS NSM).
    StructurallyValid {
        platform: TeePlatform,
        binary_hash: [u8; 32],
    },
    /// Attestation report could not be parsed or is malformed.
    Malformed(String),
    /// Hardware signature is invalid or from an untrusted root.
    InvalidSignature(String),
    /// Binary hash doesn't match the expected reproducible build.
    BinaryMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// Attestation is too old (stale).
    Expired {
        age_seconds: u64,
    },
    /// No attestation provided.
    NotAttested,
}

/// Maximum age of an attestation before it's considered stale (24 hours).
const MAX_ATTESTATION_AGE: u64 = 24 * 60 * 60;

/// Scoring bonus for TEE-attested nodes (added to base score).
pub const TEE_SCORE_BONUS: f64 = 20.0;

/// Verify an attestation report against an expected binary hash.
///
/// In production, this would verify the hardware-specific signature chain:
/// - SEV-SNP: verify against AMD's root signing key (ARK → ASK → VCEK → report)
/// - SGX: verify against Intel's attestation service
/// - Nitro: verify against AWS Nitro root certificate
///
/// Currently implements structural validation + binary hash comparison.
/// Full hardware signature verification requires platform-specific SDKs.
pub fn verify_attestation(
    report: &AttestationReport,
    expected_binary_hash: &[u8; 32],
    current_timestamp: u64,
) -> AttestationVerdict {
    // Check attestation freshness.
    if current_timestamp > report.timestamp {
        let age = current_timestamp - report.timestamp;
        if age > MAX_ATTESTATION_AGE {
            return AttestationVerdict::Expired { age_seconds: age };
        }
    }

    // Verify binary hash matches the reproducible build.
    if report.binary_hash != *expected_binary_hash {
        return AttestationVerdict::BinaryMismatch {
            expected: *expected_binary_hash,
            actual: report.binary_hash,
        };
    }

    // Verify report data is non-empty (structural check).
    if report.report_data.is_empty() {
        return AttestationVerdict::Malformed("empty report data".to_string());
    }

    // Platform-specific hardware signature verification.
    // TODO: Implement full verification chains per platform.
    // For now, structural validation passes if report data is present
    // and binary hash matches. Full verification requires:
    // - SEV-SNP: sevctl or sev crate for AMD certificate chain
    // - SGX: Intel DCAP library
    // - Nitro: AWS Nitro SDK attestation document parsing
    match report.platform {
        TeePlatform::AmdSevSnp => {
            // Minimum SEV-SNP report size: 1184 bytes (REPORT structure).
            if report.report_data.len() < 1184 {
                return AttestationVerdict::Malformed(format!(
                    "SEV-SNP report too small: {} bytes (expected ≥1184)",
                    report.report_data.len()
                ));
            }
        }
        TeePlatform::AwsNitro => {
            // Nitro attestation documents are CBOR-encoded, typically 2-4 KB.
            if report.report_data.len() < 100 {
                return AttestationVerdict::Malformed(format!(
                    "Nitro attestation too small: {} bytes",
                    report.report_data.len()
                ));
            }
        }
        _ => {}
    }

    AttestationVerdict::StructurallyValid {
        platform: report.platform.clone(),
        binary_hash: report.binary_hash,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a sample attestation with fake report_data.
    /// Passes structural size check only — no real hardware signature.
    fn sample_report(hash: [u8; 32]) -> AttestationReport {
        AttestationReport {
            platform: TeePlatform::AmdSevSnp,
            binary_hash: hash,
            report_data: vec![0xAB; 1200], // fake data, >1184 bytes for size check
            timestamp: 1000,
            node_id: "node-1".into(),
        }
    }

    #[test]
    fn valid_attestation() {
        let hash = [0x42; 32];
        let report = sample_report(hash);
        let verdict = verify_attestation(&report, &hash, 1500);
        assert_eq!(
            verdict,
            AttestationVerdict::StructurallyValid {
                platform: TeePlatform::AmdSevSnp,
                binary_hash: hash,
            }
        );
    }

    #[test]
    fn binary_mismatch() {
        let report = sample_report([0x42; 32]);
        let expected = [0xFF; 32];
        match verify_attestation(&report, &expected, 1500) {
            AttestationVerdict::BinaryMismatch { .. } => {}
            other => panic!("expected BinaryMismatch, got {other:?}"),
        }
    }

    #[test]
    fn expired_attestation() {
        let report = sample_report([0x42; 32]);
        // 2 days after timestamp → expired
        let now = report.timestamp + 2 * 24 * 60 * 60;
        match verify_attestation(&report, &[0x42; 32], now) {
            AttestationVerdict::Expired { .. } => {}
            other => panic!("expected Expired, got {other:?}"),
        }
    }

    #[test]
    fn empty_report_data() {
        let mut report = sample_report([0x42; 32]);
        report.report_data = vec![];
        match verify_attestation(&report, &[0x42; 32], 1500) {
            AttestationVerdict::Malformed(_) => {}
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn sevsnp_report_too_small() {
        let mut report = sample_report([0x42; 32]);
        report.report_data = vec![0; 100]; // <1184
        match verify_attestation(&report, &[0x42; 32], 1500) {
            AttestationVerdict::Malformed(_) => {}
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn not_attested_is_separate() {
        // NotAttested is for nodes that don't provide any attestation.
        assert_eq!(AttestationVerdict::NotAttested, AttestationVerdict::NotAttested);
    }
}
