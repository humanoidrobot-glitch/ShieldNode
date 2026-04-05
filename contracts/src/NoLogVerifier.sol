// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IRiscZeroVerifier} from "./RelayProofVerifier.sol";

/// @title NoLogVerifier
/// @notice Verifies ZK no-log compliance proofs — proves a relay node's
///         runtime state contains no connection metadata beyond active
///         sessions.
///
///         The node periodically submits a ZK proof that its session
///         registry and bandwidth tracker satisfy structural invariants:
///         - No stale/orphaned entries
///         - No zero-key sessions
///         - No duplicate session IDs
///         - Bandwidth entries match session registry
///
///         Nodes with recent compliance proofs receive a scoring bonus.
///         This proves the *declared state* has no logs. It cannot prove
///         the operator isn't maintaining a separate logging process
///         outside the node binary (that requires TEE attestation).
contract NoLogVerifier {
    // ──────────────────────────────────────────────────────────────
    //  Constants
    // ──────────────────────────────────────────────────────────────

    /// @notice Compliance journal layout:
    ///         [32 state_hash][32 node_id][8 timestamp][4 session_count][1 compliant][1 check_flags]
    uint256 public constant COMPLIANCE_JOURNAL_LEN = 78;

    /// @notice Maximum age (seconds) for a compliance proof to be considered fresh.
    ///         Default: 6 hours (matches heartbeat cadence).
    uint256 public constant PROOF_FRESHNESS = 6 hours;

    /// @notice All check flags must be set for full compliance (0x3F = 6 bits).
    uint8 public constant ALL_CHECKS_PASSED = 0x3F;

    // ──────────────────────────────────────────────────────────────
    //  Immutables
    // ──────────────────────────────────────────────────────────────

    IRiscZeroVerifier public immutable riscZeroVerifier;
    bytes32 public immutable complianceImageId;

    // ──────────────────────────────────────────────────────────────
    //  State
    // ──────────────────────────────────────────────────────────────

    /// @notice Last compliance proof timestamp per node.
    mapping(bytes32 => uint256) public lastProofTimestamp;

    /// @notice Last compliance state hash per node.
    mapping(bytes32 => bytes32) public lastStateHash;

    /// @notice Last active session count per node.
    mapping(bytes32 => uint32) public lastSessionCount;

    /// @notice Total compliance proofs submitted per node (lifetime).
    mapping(bytes32 => uint256) public proofCount;

    // ──────────────────────────────────────────────────────────────
    //  Events
    // ──────────────────────────────────────────────────────────────

    event ComplianceVerified(
        bytes32 indexed nodeId,
        bytes32 stateHash,
        uint256 timestamp,
        uint32 sessionCount,
        uint8 checkFlags
    );

    event ComplianceFailed(
        bytes32 indexed nodeId,
        uint8 checkFlags
    );

    // ──────────────────────────────────────────────────────────────
    //  Errors
    // ──────────────────────────────────────────────────────────────

    error ProofVerificationFailed();
    error InvalidJournalLength();
    error NotCompliant(uint8 checkFlags);
    error TimestampInFuture();
    error TimestampTooOld();

    // ──────────────────────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────────────────────

    constructor(address _verifier, bytes32 _imageId) {
        require(_verifier != address(0), "NoLogVerifier: zero verifier");
        riscZeroVerifier = IRiscZeroVerifier(_verifier);
        complianceImageId = _imageId;
    }

    // ──────────────────────────────────────────────────────────────
    //  Verification
    // ──────────────────────────────────────────────────────────────

    /// @notice Submit a no-log compliance proof for a node.
    /// @param seal The RISC Zero proof.
    /// @param journal The public outputs from the compliance guest.
    function verifyCompliance(
        bytes calldata seal,
        bytes calldata journal
    ) external {
        if (journal.length != COMPLIANCE_JOURNAL_LEN) revert InvalidJournalLength();

        // Verify the RISC Zero proof.
        bytes32 journalDigest = sha256(journal);
        try riscZeroVerifier.verify(seal, complianceImageId, journalDigest) {}
        catch { revert ProofVerificationFailed(); }

        // Decode journal: [32 state_hash][32 node_id][8 timestamp][4 session_count][1 compliant][1 check_flags]
        bytes32 stateHash = bytes32(journal[0:32]);
        bytes32 nodeId = bytes32(journal[32:64]);
        uint64 timestamp = uint64(bytes8(journal[64:72]));
        uint32 sessionCount = uint32(bytes4(journal[72:76]));
        uint8 compliant = uint8(journal[76]);
        uint8 checkFlags = uint8(journal[77]);

        // Timestamp sanity: not in future, not older than 2x freshness window.
        if (timestamp > block.timestamp + 60) revert TimestampInFuture();
        if (timestamp + PROOF_FRESHNESS * 2 < block.timestamp) revert TimestampTooOld();

        if (compliant != 1) {
            emit ComplianceFailed(nodeId, checkFlags);
            revert NotCompliant(checkFlags);
        }

        // Update state.
        lastProofTimestamp[nodeId] = timestamp;
        lastStateHash[nodeId] = stateHash;
        lastSessionCount[nodeId] = sessionCount;
        proofCount[nodeId]++;

        emit ComplianceVerified(
            nodeId,
            stateHash,
            timestamp,
            sessionCount,
            checkFlags
        );
    }

    // ──────────────────────────────────────────────────────────────
    //  Queries
    // ──────────────────────────────────────────────────────────────

    /// @notice Check whether a node has a fresh compliance proof.
    /// @param nodeId The node's identifier.
    /// @return True if the last proof is within the freshness window.
    function isCompliant(bytes32 nodeId) external view returns (bool) {
        uint256 lastProof = lastProofTimestamp[nodeId];
        if (lastProof == 0) return false;
        return block.timestamp <= lastProof + PROOF_FRESHNESS;
    }

    /// @notice Get the compliance status for a node.
    /// @param nodeId The node's identifier.
    /// @return lastTimestamp Last proof timestamp (0 if never proved).
    /// @return sessions Active session count at last proof.
    /// @return totalProofs Lifetime proof count.
    /// @return fresh Whether the last proof is within the freshness window.
    function getComplianceStatus(bytes32 nodeId) external view returns (
        uint256 lastTimestamp,
        uint32 sessions,
        uint256 totalProofs,
        bool fresh
    ) {
        lastTimestamp = lastProofTimestamp[nodeId];
        sessions = lastSessionCount[nodeId];
        totalProofs = proofCount[nodeId];
        fresh = lastTimestamp != 0 && block.timestamp <= lastTimestamp + PROOF_FRESHNESS;
    }
}
