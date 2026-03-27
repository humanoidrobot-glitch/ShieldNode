//! Node-side challenge responder.
//!
//! Listens for on-chain ChallengeIssued events and responds with a signed
//! proof before the deadline. Uses the node's operator key to sign EIP-712
//! challenge responses.

use std::sync::LazyLock;

use alloy::primitives::{keccak256, B256, U256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use serde::{Deserialize, Serialize};
use tracing::info;

pub use super::eip712::compute_domain_separator;

/// EIP-712 typehash for challenge responses (computed once, matches ChallengeManager.sol).
static RESPONSE_TYPEHASH: LazyLock<B256> = LazyLock::new(|| {
    keccak256("ChallengeResponse(uint256 challengeId,bytes32 nodeId,bytes32 responseHash)")
});

/// A challenge received from the ChallengeManager contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncomingChallenge {
    pub challenge_id: u64,
    pub node_id: [u8; 32],
    pub challenge_type: u8,
    pub deadline: u64,
    pub challenge_data: [u8; 32],
}

/// A signed response to an on-chain challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub challenge_id: u64,
    pub node_id: [u8; 32],
    pub response_hash: [u8; 32],
    pub signature: Vec<u8>,
}

/// Generate a response to a challenge.
pub async fn respond_to_challenge(
    challenge: &IncomingChallenge,
    domain_separator: &B256,
    signer: &PrivateKeySigner,
) -> Result<ChallengeResponse, String> {
    // Generate response hash based on challenge type.
    let response_hash: [u8; 32] = match challenge.challenge_type {
        0 => {
            // BandwidthVerification
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let mut data = Vec::with_capacity(40);
            data.extend_from_slice(&challenge.challenge_data);
            data.extend_from_slice(&ts.to_be_bytes());
            keccak256(&data).0
        }
        1 => {
            // LivenessCheck
            let mut data = Vec::with_capacity(48);
            data.extend_from_slice(b"alive");
            data.extend_from_slice(&challenge.node_id);
            data.extend_from_slice(&challenge.challenge_id.to_be_bytes());
            keccak256(&data).0
        }
        _ => challenge.challenge_data,
    };

    // Compute EIP-712 struct hash.
    let typehash = *RESPONSE_TYPEHASH;
    let mut struct_buf = Vec::with_capacity(4 * 32);
    struct_buf.extend_from_slice(typehash.as_slice());
    struct_buf.extend_from_slice(&U256::from(challenge.challenge_id).to_be_bytes::<32>());
    struct_buf.extend_from_slice(&challenge.node_id);
    struct_buf.extend_from_slice(&response_hash);
    let struct_hash = keccak256(&struct_buf);

    // EIP-712 envelope.
    let mut envelope = Vec::with_capacity(66);
    envelope.push(0x19);
    envelope.push(0x01);
    envelope.extend_from_slice(domain_separator.as_slice());
    envelope.extend_from_slice(struct_hash.as_slice());
    let digest = keccak256(&envelope);

    // Sign.
    let signature = signer
        .sign_hash(&digest)
        .await
        .map_err(|e| format!("failed to sign challenge response: {e}"))?;

    info!(
        challenge_id = challenge.challenge_id,
        challenge_type = challenge.challenge_type,
        "challenge response signed"
    );

    Ok(ChallengeResponse {
        challenge_id: challenge.challenge_id,
        node_id: challenge.node_id,
        response_hash,
        signature: signature.as_bytes().to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, FixedBytes};

    #[tokio::test]
    async fn liveness_response_produces_65_byte_sig() {
        let signer = PrivateKeySigner::from_bytes(&FixedBytes::from([0x01u8; 32])).unwrap();
        let domain_sep = compute_domain_separator(11155111, Address::ZERO);

        let challenge = IncomingChallenge {
            challenge_id: 42,
            node_id: [0xAB; 32],
            challenge_type: 1, // LivenessCheck
            deadline: 9999999999,
            challenge_data: [0; 32],
        };

        let resp = respond_to_challenge(&challenge, &domain_sep, &signer)
            .await
            .unwrap();

        assert_eq!(resp.challenge_id, 42);
        assert_eq!(resp.signature.len(), 65);
        assert_ne!(resp.response_hash, [0; 32]);
    }

}
