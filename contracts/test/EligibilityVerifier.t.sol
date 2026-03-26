// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {EligibilityVerifier, IEligibilityProofVerifier} from "../src/EligibilityVerifier.sol";

contract MockEligibilityVerifier is IEligibilityProofVerifier {
    bool public shouldPass = true;
    function setResult(bool _pass) external { shouldPass = _pass; }
    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[5] calldata
    ) external view override returns (bool) {
        return shouldPass;
    }
}

contract EligibilityVerifierTest is Test {
    EligibilityVerifier public ev;
    MockEligibilityVerifier public mock;

    function setUp() public {
        mock = new MockEligibilityVerifier();
        ev = new EligibilityVerifier(address(mock));
        ev.updateRegistryRoot(12345);
    }

    function _dummyProof()
        internal pure
        returns (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c)
    {
        a = [uint256(0), 0];
        b = [[uint256(0), 0], [uint256(0), 0]];
        c = [uint256(0), 0];
    }

    function _validSignals(uint256 nullifier) internal view returns (uint256[5] memory) {
        return [
            ev.registryRoot(),
            ev.DEFAULT_MIN_STAKE(),
            ev.DEFAULT_MAX_SLASHES(),
            ev.DEFAULT_MIN_UPTIME(),
            nullifier
        ];
    }

    // ── valid proof ─────────────────────────────────────────────

    function test_verify_valid_eligibility() public {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _dummyProof();
        uint256[5] memory signals = _validSignals(42);

        ev.verifyEligibility(a, b, c, signals);

        assertTrue(ev.usedNullifiers(42));
    }

    // ── double use ──────────────────────────────────────────────

    function test_nullifier_reuse_reverts() public {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _dummyProof();
        uint256[5] memory signals = _validSignals(99);

        ev.verifyEligibility(a, b, c, signals);

        vm.expectRevert(EligibilityVerifier.NullifierAlreadyUsed.selector);
        ev.verifyEligibility(a, b, c, signals);
    }

    // ── invalid proof ───────────────────────────────────────────

    function test_invalid_proof_reverts() public {
        mock.setResult(false);
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _dummyProof();

        // When mock returns false, contract should revert with InvalidProof.
        // Use a fresh EligibilityVerifier with the mock already set to false.
        MockEligibilityVerifier freshMock = new MockEligibilityVerifier();
        freshMock.setResult(false);
        EligibilityVerifier freshEv = new EligibilityVerifier(address(freshMock));
        freshEv.updateRegistryRoot(12345);

        uint256[5] memory signals = [
            uint256(12345),
            freshEv.DEFAULT_MIN_STAKE(),
            freshEv.DEFAULT_MAX_SLASHES(),
            freshEv.DEFAULT_MIN_UPTIME(),
            uint256(1)
        ];

        vm.expectRevert(EligibilityVerifier.InvalidProof.selector);
        freshEv.verifyEligibility(a, b, c, signals);
    }

    // ── wrong registry root ─────────────────────────────────────

    function test_wrong_root_reverts() public {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _dummyProof();
        uint256[5] memory signals = _validSignals(1);
        signals[0] = 99999; // wrong root

        vm.expectRevert(EligibilityVerifier.RegistryRootMismatch.selector);
        ev.verifyEligibility(a, b, c, signals);
    }

    // ── wrong thresholds ────────────────────────────────────────

    function test_wrong_min_stake_reverts() public {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _dummyProof();
        uint256[5] memory signals = _validSignals(1);
        signals[1] = 1 ether; // different from DEFAULT_MIN_STAKE

        vm.expectRevert(abi.encodeWithSelector(
            EligibilityVerifier.ThresholdMismatch.selector, "minStake"
        ));
        ev.verifyEligibility(a, b, c, signals);
    }

    // ── admin ───────────────────────────────────────────────────

    function test_update_root() public {
        ev.updateRegistryRoot(67890);
        assertEq(ev.registryRoot(), 67890);
    }

    function test_update_root_not_owner() public {
        vm.prank(makeAddr("random"));
        vm.expectRevert(EligibilityVerifier.NotOwner.selector);
        ev.updateRegistryRoot(1);
    }

    // ── constants ───────────────────────────────────────────────

    function test_default_thresholds() public view {
        assertEq(ev.DEFAULT_MIN_STAKE(), 0.1 ether);
        assertEq(ev.DEFAULT_MAX_SLASHES(), 1);
        assertEq(ev.DEFAULT_MIN_UPTIME(), 900);
    }
}
