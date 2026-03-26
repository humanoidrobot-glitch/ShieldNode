// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {ExecutionTraceVerifier, IRiscZeroVerifier} from "../src/ExecutionTraceVerifier.sol";

contract MockVerifier is IRiscZeroVerifier {
    bool public shouldPass = true;
    function setResult(bool _pass) external { shouldPass = _pass; }
    function verify(bytes calldata, bytes32, bytes32) external view override {
        require(shouldPass, "mock: proof invalid");
    }
}

contract ExecutionTraceVerifierTest is Test {
    ExecutionTraceVerifier public verifier;
    MockVerifier public mock;
    bytes32 constant IMAGE_ID = keccak256("shieldnode-execution-trace-v1");

    function setUp() public {
        mock = new MockVerifier();
        verifier = new ExecutionTraceVerifier(address(mock), IMAGE_ID);
    }

    function _buildJournal(
        bytes32 nextHop,
        bytes32 payloadHash,
        bytes32 inputHash,
        uint64 inputBytes,
        uint64 outputBytes,
        bytes32 ioHash,
        uint32 commitCount,
        uint32 traceVersion
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            nextHop, payloadHash, inputHash,
            inputBytes, outputBytes, ioHash,
            commitCount, traceVersion
        );
    }

    function _validJournal() internal pure returns (bytes memory) {
        return _buildJournal(
            keccak256("next-hop"),
            keccak256("payload"),
            keccak256("input"),
            1024,  // input bytes
            152,   // output bytes (32+32+32+56)
            keccak256("io-binding"),
            4,     // expected commits
            1      // version
        );
    }

    // ── valid proof ─────────────────────────────────────────────

    function test_verify_valid_trace() public {
        bytes memory journal = _validJournal();
        (bytes32 nextHop, bytes32 payloadHash, bytes32 inputHash) =
            verifier.verifyExecutionTrace(hex"deadbeef", journal);

        assertEq(nextHop, keccak256("next-hop"));
        assertEq(payloadHash, keccak256("payload"));
        assertEq(inputHash, keccak256("input"));
    }

    // ── invalid proof ───────────────────────────────────────────

    function test_invalid_proof_reverts() public {
        mock.setResult(false);
        vm.expectRevert(ExecutionTraceVerifier.ProofVerificationFailed.selector);
        verifier.verifyExecutionTrace(hex"deadbeef", _validJournal());
    }

    // ── wrong journal length ────────────────────────────────────

    function test_short_journal_reverts() public {
        vm.expectRevert(ExecutionTraceVerifier.InvalidJournalLength.selector);
        verifier.verifyExecutionTrace(hex"deadbeef", hex"0011");
    }

    // ── unexpected commit count ──────────────────────────────────

    function test_extra_commits_detected() public {
        bytes memory journal = _buildJournal(
            keccak256("a"), keccak256("b"), keccak256("c"),
            1024, 200, keccak256("io"),
            5,   // 5 commits instead of expected 4 — suspicious!
            1
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                ExecutionTraceVerifier.UnexpectedCommitCount.selector, 5, 4
            )
        );
        verifier.verifyExecutionTrace(hex"deadbeef", journal);
    }

    function test_fewer_commits_detected() public {
        bytes memory journal = _buildJournal(
            keccak256("a"), keccak256("b"), keccak256("c"),
            1024, 96, keccak256("io"),
            3,   // 3 commits — missing trace metadata
            1
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                ExecutionTraceVerifier.UnexpectedCommitCount.selector, 3, 4
            )
        );
        verifier.verifyExecutionTrace(hex"deadbeef", journal);
    }

    // ── trace version mismatch ──────────────────────────────────

    function test_wrong_version_reverts() public {
        bytes memory journal = _buildJournal(
            keccak256("a"), keccak256("b"), keccak256("c"),
            1024, 148, keccak256("io"),
            4,
            2    // wrong version
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                ExecutionTraceVerifier.TraceVersionMismatch.selector, 2, 1
            )
        );
        verifier.verifyExecutionTrace(hex"deadbeef", journal);
    }

    // ── zero input bytes ────────────────────────────────────────

    function test_zero_input_reverts() public {
        bytes memory journal = _buildJournal(
            keccak256("a"), keccak256("b"), keccak256("c"),
            0,    // zero input — no packet processed
            148, keccak256("io"),
            4, 1
        );

        vm.expectRevert(ExecutionTraceVerifier.ZeroInputBytes.selector);
        verifier.verifyExecutionTrace(hex"deadbeef", journal);
    }

    // ── constants ───────────────────────────────────────────────

    function test_constants() public view {
        assertEq(verifier.EXPECTED_COMMITS(), 4);
        assertEq(verifier.EXPECTED_TRACE_VERSION(), 1);
        assertEq(verifier.FULL_TRACE_JOURNAL_LEN(), 152);
    }
}
