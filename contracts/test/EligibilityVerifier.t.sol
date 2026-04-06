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
        uint256[6] calldata
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
        _timelockUpdateRoot(ev, 12345);
    }

    /// @dev Propose + warp + execute a registry root update through the timelock.
    function _timelockUpdateRoot(EligibilityVerifier _ev, uint256 newRoot) internal {
        uint256 id = _ev.proposeRegistryRoot(newRoot);
        vm.warp(block.timestamp + _ev.ROOT_TIMELOCK());
        _ev.executeRegistryRoot(id);
    }

    function _dummyProof()
        internal pure
        returns (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c)
    {
        a = [uint256(0), 0];
        b = [[uint256(0), 0], [uint256(0), 0]];
        c = [uint256(0), 0];
    }

    function _validSignals(uint256 nullifier) internal view returns (uint256[6] memory) {
        return [
            ev.registryRoot(),
            ev.DEFAULT_MIN_STAKE(),
            ev.DEFAULT_MAX_SLASHES(),
            ev.DEFAULT_MIN_UPTIME(),
            uint256(1),  // epoch
            nullifier
        ];
    }

    // ── valid proof ─────────────────────────────────────────────

    function test_verify_valid_eligibility() public {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _dummyProof();
        uint256[6] memory signals = _validSignals(42);

        ev.verifyEligibility(a, b, c, signals);

        assertTrue(ev.usedNullifiers(42));
    }

    // ── double use ──────────────────────────────────────────────

    function test_nullifier_reuse_reverts() public {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _dummyProof();
        uint256[6] memory signals = _validSignals(99);

        ev.verifyEligibility(a, b, c, signals);

        vm.expectRevert(EligibilityVerifier.NullifierAlreadyUsed.selector);
        ev.verifyEligibility(a, b, c, signals);
    }

    // ── invalid proof ───────────────────────────────────────────

    function test_invalid_proof_reverts() public {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _dummyProof();

        MockEligibilityVerifier freshMock = new MockEligibilityVerifier();
        freshMock.setResult(false);
        EligibilityVerifier freshEv = new EligibilityVerifier(address(freshMock));
        _timelockUpdateRoot(freshEv, 12345);

        uint256[6] memory signals = [
            uint256(12345),
            freshEv.DEFAULT_MIN_STAKE(),
            freshEv.DEFAULT_MAX_SLASHES(),
            freshEv.DEFAULT_MIN_UPTIME(),
            uint256(1),  // epoch
            uint256(1)   // nullifier
        ];

        vm.expectRevert(EligibilityVerifier.InvalidProof.selector);
        freshEv.verifyEligibility(a, b, c, signals);
    }

    // ── wrong registry root ─────────────────────────────────────

    function test_wrong_root_reverts() public {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _dummyProof();
        uint256[6] memory signals = _validSignals(1);
        signals[0] = 99999; // wrong root

        vm.expectRevert(EligibilityVerifier.RegistryRootMismatch.selector);
        ev.verifyEligibility(a, b, c, signals);
    }

    // ── wrong thresholds ────────────────────────────────────────

    function test_wrong_min_stake_reverts() public {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _dummyProof();
        uint256[6] memory signals = _validSignals(1);
        signals[1] = 1 ether; // different from DEFAULT_MIN_STAKE

        vm.expectRevert(abi.encodeWithSelector(
            EligibilityVerifier.ThresholdMismatch.selector, "minStake"
        ));
        ev.verifyEligibility(a, b, c, signals);
    }

    // ── admin (timelocked) ──────────────────────────────────────

    function test_update_root_timelocked() public {
        _timelockUpdateRoot(ev, 67890);
        assertEq(ev.registryRoot(), 67890);
    }

    function test_propose_root_not_owner() public {
        vm.prank(makeAddr("random"));
        vm.expectRevert(EligibilityVerifier.NotOwner.selector);
        ev.proposeRegistryRoot(1);
    }

    function test_execute_root_before_timelock_reverts() public {
        uint256 id = ev.proposeRegistryRoot(99999);
        vm.expectRevert("EligibilityVerifier: timelock active");
        ev.executeRegistryRoot(id);
    }

    function test_execute_root_twice_reverts() public {
        uint256 id = ev.proposeRegistryRoot(99999);
        vm.warp(block.timestamp + ev.ROOT_TIMELOCK());
        ev.executeRegistryRoot(id);

        vm.expectRevert("EligibilityVerifier: already executed");
        ev.executeRegistryRoot(id);
    }

    // ── two-step ownership ───────────────────────────────────

    function test_transferOwnership_twoStep() public {
        address newOwner = makeAddr("newOwner");
        ev.transferOwnership(newOwner);
        assertEq(ev.pendingOwner(), newOwner);

        vm.prank(newOwner);
        ev.acceptOwnership();
        assertEq(ev.owner(), newOwner);
        assertEq(ev.pendingOwner(), address(0));
    }

    function test_acceptOwnership_notPending_reverts() public {
        vm.prank(makeAddr("random"));
        vm.expectRevert("EligibilityVerifier: not pending owner");
        ev.acceptOwnership();
    }

    // ── constants ───────────────────────────────────────────────

    function test_default_thresholds() public view {
        assertEq(ev.DEFAULT_MIN_STAKE(), 0.1 ether);
        assertEq(ev.DEFAULT_MAX_SLASHES(), 1);
        assertEq(ev.DEFAULT_MIN_UPTIME(), 900);
    }
}
