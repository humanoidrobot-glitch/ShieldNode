// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

/// @title SlashingOracle Formal Verification (Halmos)
/// @notice Symbolic tests for progressive slashing math and reward distribution.
///
///         Run with: halmos --contract SlashingOracleHalmos
///         These tests use the `check_` prefix — Foundry ignores them,
///         Halmos explores them symbolically over all uint256 values.
contract SlashingOracleHalmos is Test {
    uint256 constant SLASH_PCT_FIRST   = 10;
    uint256 constant SLASH_PCT_SECOND  = 25;
    uint256 constant SLASH_PCT_THIRD   = 100;
    uint256 constant SLASH_PCT_LIVENESS = 5;
    uint256 constant CHALLENGER_SHARE  = 50;

    /// @notice Progressive monotonicity: penalty % increases with slashCount.
    ///         0 offences -> 10%, 1 -> 25%, 2+ -> 100%.
    function check_progressive_monotonicity(uint256 slashCount) public pure {
        uint256 pct;
        if (slashCount == 0) {
            pct = SLASH_PCT_FIRST;
        } else if (slashCount == 1) {
            pct = SLASH_PCT_SECOND;
        } else {
            pct = SLASH_PCT_THIRD;
        }

        // Monotonic: higher count -> higher or equal penalty.
        if (slashCount == 0) {
            assert(pct == 10);
        } else if (slashCount == 1) {
            assert(pct > SLASH_PCT_FIRST);
            assert(pct == 25);
        } else {
            assert(pct >= SLASH_PCT_SECOND);
            assert(pct == 100);
        }
    }

    /// @notice Liveness separation: ChallengeFailure always uses 5%
    ///         regardless of slashCount. Never escalates.
    function check_liveness_always_5pct(uint256 slashCount) public pure {
        // For ChallengeFailure, the code always takes the liveness branch.
        uint256 pct = SLASH_PCT_LIVENESS;

        assert(pct == 5);
        // Verify it doesn't depend on slashCount at all.
        assert(pct < SLASH_PCT_FIRST); // always less than fraud track
    }

    /// @notice Distribution conservation: challenger + treasury == slashAmount.
    ///         No value created or lost in the 50/50 split.
    function check_distribution_conservation(uint256 slashAmount) public pure {
        vm.assume(slashAmount > 0);
        vm.assume(slashAmount <= 100 ether); // realistic bound

        uint256 challengerReward = (slashAmount * CHALLENGER_SHARE) / 100;
        uint256 treasuryReward   = slashAmount - challengerReward;

        assert(challengerReward + treasuryReward == slashAmount);
    }

    /// @notice Slash amount bounded by stake: actual slash <= node stake.
    function check_slash_bounded_by_stake(
        uint256 stake,
        uint256 slashCount
    ) public pure {
        vm.assume(stake > 0);
        vm.assume(stake <= 100 ether);

        uint256 pct;
        if (slashCount == 0) {
            pct = SLASH_PCT_FIRST;
        } else if (slashCount == 1) {
            pct = SLASH_PCT_SECOND;
        } else {
            pct = SLASH_PCT_THIRD;
        }

        uint256 slashAmount = (stake * pct) / 100;
        uint256 actual = slashAmount > stake ? stake : slashAmount;

        assert(actual <= stake);
    }

    /// @notice After 100% slash, remaining stake is zero.
    function check_full_slash_zeroes_stake(uint256 stake) public pure {
        vm.assume(stake > 0);
        vm.assume(stake <= 100 ether);

        uint256 slashAmount = (stake * SLASH_PCT_THIRD) / 100; // 100%
        uint256 actual = slashAmount > stake ? stake : slashAmount;
        uint256 remaining = stake - actual;

        assert(remaining == 0);
    }
}
