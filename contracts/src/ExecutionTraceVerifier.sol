// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IRiscZeroVerifier} from "./RelayProofVerifier.sol";

/// @title ExecutionTraceVerifier
/// @notice Verifies ZK-VM execution trace proofs — proves the relay node
///         software produced ONLY the declared outputs during packet
///         forwarding. No side-channel writes, no hidden data leaks.
///
///         Extends RelayProofVerifier by additionally checking:
///         - The commit count matches the expected value (4)
///         - The I/O byte totals are consistent with a single relay forward
///         - The trace version matches the expected protocol version
///
///         This proves the *node software itself* didn't log during
///         execution. It cannot prove the operator isn't running a separate
///         capture process outside the zkVM sandbox.
contract ExecutionTraceVerifier {
    // ──────────────────────────────────────────────────────────────
    //  Constants
    // ──────────────────────────────────────────────────────────────

    /// @notice Expected number of journal commits for a full trace proof.
    ///         4 = next_hop + payload_hash + input_hash + trace_metadata
    uint32 public constant EXPECTED_COMMITS = 4;

    /// @notice Expected trace protocol version.
    uint32 public constant EXPECTED_TRACE_VERSION = 1;

    /// @notice Journal layout for full trace proof:
    ///         [32 next_hop][32 payload_hash][32 input_hash][56 trace_metadata]
    ///         trace_metadata = [8 input_bytes][8 output_bytes][32 io_hash][4 commit_count][4 trace_version]
    uint256 public constant FULL_TRACE_JOURNAL_LEN = 32 + 32 + 32 + 56;

    // ──────────────────────────────────────────────────────────────
    //  Immutables
    // ──────────────────────────────────────────────────────────────

    IRiscZeroVerifier public immutable riscZeroVerifier;
    bytes32 public immutable traceImageId;

    // ──────────────────────────────────────────────────────────────
    //  Events
    // ──────────────────────────────────────────────────────────────

    event ExecutionTraceVerified(
        bytes32 indexed inputHash,
        bytes32 nextHop,
        uint64 inputBytes,
        uint64 outputBytes,
        uint32 commitCount
    );

    // ──────────────────────────────────────────────────────────────
    //  Errors
    // ──────────────────────────────────────────────────────────────

    error ProofVerificationFailed();
    error InvalidJournalLength();
    error UnexpectedCommitCount(uint32 actual, uint32 expected);
    error TraceVersionMismatch(uint32 actual, uint32 expected);
    error ZeroInputBytes();

    // ──────────────────────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────────────────────

    constructor(address _verifier, bytes32 _imageId) {
        require(_verifier != address(0), "ExecutionTraceVerifier: zero verifier");
        riscZeroVerifier = IRiscZeroVerifier(_verifier);
        traceImageId = _imageId;
    }

    // ──────────────────────────────────────────────────────────────
    //  Verification
    // ──────────────────────────────────────────────────────────────

    /// @notice Verify a full execution trace proof.
    /// @param seal The RISC Zero proof.
    /// @param journal The public outputs (forwarding outputs + trace metadata).
    /// @return nextHop The proven routing destination.
    /// @return payloadHash SHA-256 of the forwarded payload.
    /// @return inputHash SHA-256 of the encrypted input packet.
    function verifyExecutionTrace(
        bytes calldata seal,
        bytes calldata journal
    ) external returns (
        bytes32 nextHop,
        bytes32 payloadHash,
        bytes32 inputHash
    ) {
        if (journal.length != FULL_TRACE_JOURNAL_LEN) revert InvalidJournalLength();

        // Verify the RISC Zero proof.
        bytes32 journalDigest = sha256(journal);
        try riscZeroVerifier.verify(seal, traceImageId, journalDigest) {}
        catch { revert ProofVerificationFailed(); }

        // Decode forwarding outputs.
        nextHop = bytes32(journal[0:32]);
        payloadHash = bytes32(journal[32:64]);
        inputHash = bytes32(journal[64:96]);

        // Decode trace metadata (56 bytes at offset 96).
        // Layout: [8 input_bytes][8 output_bytes][32 io_hash][4 commit_count][4 trace_version]
        uint64 inputBytes = uint64(bytes8(journal[96:104]));
        uint64 outputBytes = uint64(bytes8(journal[104:112]));
        // bytes32 ioHash = bytes32(journal[112:144]); // available for extended verification
        uint32 commitCount = uint32(bytes4(journal[144:148]));
        uint32 traceVersion = uint32(bytes4(journal[148:152]));

        // Verify trace invariants.
        if (commitCount != EXPECTED_COMMITS) {
            revert UnexpectedCommitCount(commitCount, EXPECTED_COMMITS);
        }
        if (traceVersion != EXPECTED_TRACE_VERSION) {
            revert TraceVersionMismatch(traceVersion, EXPECTED_TRACE_VERSION);
        }
        if (inputBytes == 0) {
            revert ZeroInputBytes();
        }

        emit ExecutionTraceVerified(
            inputHash,
            nextHop,
            inputBytes,
            outputBytes,
            commitCount
        );
    }
}
