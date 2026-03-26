// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {RelayProofVerifier, IRiscZeroVerifier} from "../src/RelayProofVerifier.sol";

/// @notice Mock RISC Zero verifier that always passes.
contract MockRiscZeroVerifier is IRiscZeroVerifier {
    bool public shouldPass = true;

    function setResult(bool _pass) external {
        shouldPass = _pass;
    }

    function verify(bytes calldata, bytes32, bytes32) external view override {
        require(shouldPass, "mock: proof invalid");
    }
}

contract RelayProofVerifierTest is Test {
    RelayProofVerifier public verifier;
    MockRiscZeroVerifier public mockRisc;
    bytes32 constant IMAGE_ID = keccak256("shieldnode-relay-forward-v1");

    function setUp() public {
        mockRisc = new MockRiscZeroVerifier();
        verifier = new RelayProofVerifier(address(mockRisc), IMAGE_ID);
    }

    // ── helpers ──────────────────────────────────────────────────

    function _buildJournal(
        bytes32 nextHop,
        bytes32 payloadHash,
        bytes32 inputHash
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(nextHop, payloadHash, inputHash);
    }

    // ── tests ───────────────────────────────────────────────────

    function test_verify_valid_proof() public {
        bytes32 nextHop = keccak256("next-hop");
        bytes32 payloadHash = keccak256("payload");
        bytes32 inputHash = keccak256("input");

        bytes memory journal = _buildJournal(nextHop, payloadHash, inputHash);
        bytes memory seal = hex"deadbeef"; // mock accepts any seal

        (bytes32 rNextHop, bytes32 rPayload, bytes32 rInput) =
            verifier.verifyRelayProof(seal, journal);

        assertEq(rNextHop, nextHop);
        assertEq(rPayload, payloadHash);
        assertEq(rInput, inputHash);
    }

    function test_verify_invalid_proof_reverts() public {
        mockRisc.setResult(false);

        bytes memory journal = _buildJournal(
            keccak256("a"), keccak256("b"), keccak256("c")
        );

        vm.expectRevert(RelayProofVerifier.ProofVerificationFailed.selector);
        verifier.verifyRelayProof(hex"deadbeef", journal);
    }

    function test_invalid_journal_length_reverts() public {
        vm.expectRevert(RelayProofVerifier.InvalidJournalLength.selector);
        verifier.verifyRelayProof(hex"deadbeef", hex"0011"); // too short
    }

    function test_image_id_stored() public view {
        assertEq(verifier.relayImageId(), IMAGE_ID);
    }

    function test_verifier_address_stored() public view {
        assertEq(address(verifier.riscZeroVerifier()), address(mockRisc));
    }
}
