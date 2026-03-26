// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IRiscZeroVerifier
/// @notice Interface for the RISC Zero Groth16 on-chain verifier.
///         The actual verifier is deployed by RISC Zero and verified against
///         their image ID system. See: https://dev.risczero.com/api/blockchain-integration
interface IRiscZeroVerifier {
    function verify(
        bytes calldata seal,
        bytes32 imageId,
        bytes32 journalDigest
    ) external view;
}

/// @title RelayProofVerifier
/// @notice Verifies ZK-VM proofs that a relay node correctly forwarded
///         a specific packet. Used by ChallengeManager to validate
///         challenge responses with cryptographic proof instead of
///         trust-based attestations.
///
///         The proof demonstrates:
///         1. The relay decrypted the Sphinx layer (ChaCha20-Poly1305)
///         2. The correct next_hop was extracted
///         3. The inner payload was not modified
///
///         Public outputs (journal):
///         - next_hop: bytes32 — the routing destination
///         - payload_hash: bytes32 — SHA-256 of the forwarded payload
///         - input_hash: bytes32 — SHA-256 of the encrypted input packet
contract RelayProofVerifier {
    // ──────────────────────────────────────────────────────────────
    //  Immutables
    // ──────────────────────────────────────────────────────────────

    /// @notice The RISC Zero verifier contract.
    IRiscZeroVerifier public immutable riscZeroVerifier;

    /// @notice The image ID of the relay forwarding guest program.
    ///         This is the hash of the compiled guest ELF binary —
    ///         it uniquely identifies the program that was executed.
    bytes32 public immutable relayImageId;

    // ──────────────────────────────────────────────────────────────
    //  Events
    // ──────────────────────────────────────────────────────────────

    event RelayProofVerified(
        bytes32 indexed inputHash,
        bytes32 nextHop,
        bytes32 payloadHash
    );

    // ──────────────────────────────────────────────────────────────
    //  Errors
    // ──────────────────────────────────────────────────────────────

    error ProofVerificationFailed();
    error InvalidJournalLength();

    // ──────────────────────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────────────────────

    /// @param _verifier Address of the deployed RISC Zero verifier.
    /// @param _imageId Image ID of the relay forwarding guest program.
    constructor(address _verifier, bytes32 _imageId) {
        require(_verifier != address(0), "RelayProofVerifier: zero verifier");
        riscZeroVerifier = IRiscZeroVerifier(_verifier);
        relayImageId = _imageId;
    }

    // ──────────────────────────────────────────────────────────────
    //  Verification
    // ──────────────────────────────────────────────────────────────

    /// @notice Verify a ZK-VM proof of correct relay forwarding.
    /// @param seal The RISC Zero proof (Groth16 SNARK).
    /// @param journal The public outputs (next_hop + payload_hash + input_hash).
    /// @return nextHop The proven routing destination.
    /// @return payloadHash SHA-256 of the forwarded payload.
    /// @return inputHash SHA-256 of the encrypted input (for challenge matching).
    function verifyRelayProof(
        bytes calldata seal,
        bytes calldata journal
    ) external returns (
        bytes32 nextHop,
        bytes32 payloadHash,
        bytes32 inputHash
    ) {
        // Journal must contain exactly 3 × 32 bytes.
        if (journal.length != 96) revert InvalidJournalLength();

        // Compute journal digest for verification.
        bytes32 journalDigest = sha256(journal);

        // Verify the RISC Zero proof.
        // This reverts if the proof is invalid.
        try riscZeroVerifier.verify(seal, relayImageId, journalDigest) {
            // Proof valid — extract public outputs.
        } catch {
            revert ProofVerificationFailed();
        }

        // Decode journal: [32 bytes next_hop][32 bytes payload_hash][32 bytes input_hash]
        nextHop = bytes32(journal[0:32]);
        payloadHash = bytes32(journal[32:64]);
        inputHash = bytes32(journal[64:96]);

        emit RelayProofVerified(inputHash, nextHop, payloadHash);
    }
}
