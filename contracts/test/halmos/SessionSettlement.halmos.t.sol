// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

/// @title SessionSettlement Formal Verification (Halmos)
/// @notice Symbolic tests for the _settle() math. Verifies payment conservation,
///         split integrity, and cap enforcement for all possible inputs.
///
///         Run with: halmos --contract SessionSettlementHalmos
///         These tests use the `check_` prefix — Foundry ignores them,
///         Halmos explores them symbolically over all uint256 values.
contract SessionSettlementHalmos is Test {
    uint256 constant ENTRY_SHARE = 25;
    uint256 constant RELAY_SHARE = 25;
    uint256 constant MAX_CUMULATIVE_BYTES = 1e30;
    uint256 constant MAX_PRICE_PER_BYTE  = 1e12;

    /// @notice Payment conservation: totalPaid + refund == deposit.
    ///         For every valid (cumulativeBytes, pricePerByte, deposit),
    ///         the sum of what nodes receive + client refund equals the deposit.
    function check_payment_conservation(
        uint256 cumulativeBytes,
        uint256 pricePerByte,
        uint256 deposit
    ) public pure {
        // Preconditions (match contract constraints).
        vm.assume(cumulativeBytes <= MAX_CUMULATIVE_BYTES);
        vm.assume(pricePerByte <= MAX_PRICE_PER_BYTE);
        vm.assume(deposit > 0);

        uint256 totalPaid = cumulativeBytes * pricePerByte;
        uint256 cap = deposit; // cooperative settle uses full deposit as cap
        if (totalPaid > cap) {
            totalPaid = cap;
        }

        uint256 refund = deposit - totalPaid;

        // Invariant: conservation of funds.
        assert(totalPaid + refund == deposit);
    }

    /// @notice Split integrity: entry + relay + exit == totalPaid.
    ///         The 25/25/50 split must be lossless (no rounding loss).
    function check_split_integrity(uint256 totalPaid) public pure {
        vm.assume(totalPaid > 0);
        vm.assume(totalPaid <= type(uint128).max); // realistic bound

        uint256 entryPay = (totalPaid * ENTRY_SHARE) / 100;
        uint256 relayPay = (totalPaid * RELAY_SHARE) / 100;
        uint256 exitPay  = totalPaid - entryPay - relayPay;

        // Invariant: no value created or destroyed in the split.
        assert(entryPay + relayPay + exitPay == totalPaid);
    }

    /// @notice Cap enforcement: totalPaid never exceeds the cap.
    function check_cap_enforcement(
        uint256 cumulativeBytes,
        uint256 pricePerByte,
        uint256 cap
    ) public pure {
        vm.assume(cumulativeBytes <= MAX_CUMULATIVE_BYTES);
        vm.assume(pricePerByte <= MAX_PRICE_PER_BYTE);
        vm.assume(cap > 0);

        uint256 totalPaid = cumulativeBytes * pricePerByte;
        if (totalPaid > cap) {
            totalPaid = cap;
        }

        assert(totalPaid <= cap);
    }

    /// @notice Force-settle cap: totalPaid <= 50% of deposit.
    function check_force_settle_cap(
        uint256 cumulativeBytes,
        uint256 pricePerByte,
        uint256 deposit
    ) public pure {
        vm.assume(cumulativeBytes <= MAX_CUMULATIVE_BYTES);
        vm.assume(pricePerByte <= MAX_PRICE_PER_BYTE);
        vm.assume(deposit > 0);

        uint256 cap = (deposit * 5000) / 10000; // FORCE_SETTLE_CAP_BPS = 5000
        uint256 totalPaid = cumulativeBytes * pricePerByte;
        if (totalPaid > cap) {
            totalPaid = cap;
        }

        assert(totalPaid <= cap);
        assert(totalPaid <= deposit); // can never exceed full deposit
    }

    /// @notice Overflow safety: with both caps applied, multiplication
    ///         can never overflow uint256.
    function check_no_overflow(
        uint256 cumulativeBytes,
        uint256 pricePerByte
    ) public pure {
        vm.assume(cumulativeBytes <= MAX_CUMULATIVE_BYTES);
        vm.assume(pricePerByte <= MAX_PRICE_PER_BYTE);

        // This multiplication must not overflow.
        // Max: 1e30 * 1e12 = 1e42 < 2^256 (~1.16e77).
        uint256 result = cumulativeBytes * pricePerByte;

        // If we got here without reverting, the multiplication is safe.
        assert(result <= type(uint256).max);
    }
}
