// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {NodeRegistry}       from "../src/NodeRegistry.sol";
import {SessionSettlement}  from "../src/SessionSettlement.sol";
import {ISessionSettlement} from "../src/interfaces/ISessionSettlement.sol";
import {EIP712Utils}        from "../src/lib/EIP712Utils.sol";

/// @title StressTest
/// @notice Stress test: 100+ concurrent sessions opened and settled.
///         Measures gas per operation and checks for degradation.
contract StressTest is Test {
    NodeRegistry      public registry;
    SessionSettlement public settlement;

    address public oracle = makeAddr("oracle");

    // We reuse 3 node operators for all sessions (realistic: sessions
    // share the same node pool).
    uint256 constant ENTRY_KEY = 0xE001;
    uint256 constant RELAY_KEY = 0xE002;
    uint256 constant EXIT_KEY  = 0xE003;

    address public entryOp;
    address public relayOp;
    address public exitOp;

    bytes32 public entryId = keccak256("stress-entry");
    bytes32 public relayId = keccak256("stress-relay");
    bytes32 public exitId  = keccak256("stress-exit");

    bytes32[3] public nodeIds;

    bytes32 constant RECEIPT_TYPEHASH = EIP712Utils.RECEIPT_TYPEHASH;

    uint256 constant NUM_SESSIONS = 120;

    function setUp() public {
        entryOp = vm.addr(ENTRY_KEY);
        relayOp = vm.addr(RELAY_KEY);
        exitOp  = vm.addr(EXIT_KEY);

        vm.deal(entryOp, 100 ether);
        vm.deal(relayOp, 100 ether);
        vm.deal(exitOp,  100 ether);

        registry   = new NodeRegistry(oracle);
        settlement = new SessionSettlement(address(registry));

        _registerNode(entryOp, entryId, "entry-stress", "10.0.0.1:51820");
        _registerNode(relayOp, relayId, "relay-stress", "10.0.0.2:51820");
        _registerNode(exitOp,  exitId,  "exit-stress",  "10.0.0.3:51820");

        vm.prank(exitOp);
        registry.updatePricePerByte(exitId, 1); // 1 wei per byte

        nodeIds = [entryId, relayId, exitId];
    }

    // ────────────────────── Helpers ──────────────────────

    function _registerNode(
        address op,
        bytes32 id,
        string memory pubSeed,
        string memory endpoint
    ) internal {
        vm.prank(op);
        registry.register{value: 0.1 ether}(id, keccak256(bytes(pubSeed)), endpoint);
    }

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256("ShieldNode"),
                keccak256("1"),
                block.chainid,
                address(settlement)
            )
        );
    }

    function _digest(
        uint256 sessionId,
        uint256 cumulativeBytes,
        uint256 ts
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(RECEIPT_TYPEHASH, sessionId, cumulativeBytes, ts)
        );
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
    }

    function _sign(uint256 pk, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }

    // ────────────────────── Stress tests ──────────────────────

    /// @notice Open 120 sessions from unique clients and verify all succeed.
    function test_open_120_sessions() public {
        uint256 gasTotal;

        for (uint256 i; i < NUM_SESSIONS; ++i) {
            address client = vm.addr(0xC000 + i + 1);
            vm.deal(client, 1 ether);

            vm.prank(client);
            uint256 gasBefore = gasleft();
            settlement.openSession{value: 0.01 ether}(nodeIds);
            gasTotal += gasBefore - gasleft();
        }

        // Verify all sessions were created.
        assertEq(settlement.nextSessionId(), NUM_SESSIONS);

        uint256 avgGas = gasTotal / NUM_SESSIONS;
        emit log_named_uint("open_session avg gas", avgGas);
        emit log_named_uint("open_session total gas (120 sessions)", gasTotal);

        // Sanity: avg gas should be under 200k per the gas budget.
        assertLt(avgGas, 200_000, "open_session gas exceeded budget");
    }

    /// @notice Open and settle 120 sessions with valid dual-signed receipts.
    function test_open_and_settle_120_sessions() public {
        uint256 openGasTotal;
        uint256 settleGasTotal;

        // Phase 1: Open all sessions.
        for (uint256 i; i < NUM_SESSIONS; ++i) {
            address client = vm.addr(0xC000 + i + 1);
            vm.deal(client, 1 ether);

            vm.prank(client);
            uint256 gasBefore = gasleft();
            settlement.openSession{value: 0.01 ether}(nodeIds);
            openGasTotal += gasBefore - gasleft();
        }

        // Phase 2: Settle all sessions.
        for (uint256 i; i < NUM_SESSIONS; ++i) {
            address client = vm.addr(0xC000 + i + 1);
            uint256 clientKey = 0xC000 + i + 1;

            uint256 cumBytes = 1000 + i; // slight variation per session
            uint256 ts = block.timestamp;

            bytes32 d = _digest(i, cumBytes, ts);
            bytes memory clientSig = _sign(clientKey, d);
            bytes memory nodeSig   = _sign(EXIT_KEY, d);

            bytes memory receipt = abi.encode(i, cumBytes, ts, clientSig, nodeSig);

            vm.prank(client);
            uint256 gasBefore = gasleft();
            settlement.settleSession(i, receipt);
            settleGasTotal += gasBefore - gasleft();
        }

        // Verify all settled.
        for (uint256 i; i < NUM_SESSIONS; ++i) {
            ISessionSettlement.SessionInfo memory s = settlement.getSession(i);
            assertTrue(s.settled, "session not settled");
        }

        uint256 avgOpen   = openGasTotal / NUM_SESSIONS;
        uint256 avgSettle = settleGasTotal / NUM_SESSIONS;

        emit log_named_uint("sessions", NUM_SESSIONS);
        emit log_named_uint("open_session avg gas", avgOpen);
        emit log_named_uint("settle_session avg gas", avgSettle);
        emit log_named_uint("total gas (open + settle)", openGasTotal + settleGasTotal);

        // Gas budget assertions (from CLAUDE.md).
        assertLt(avgOpen, 200_000, "open gas exceeded budget");
        assertLt(avgSettle, 200_000, "settle gas exceeded budget");
    }

    /// @notice Verify node balances after settling all sessions.
    function test_payment_distribution_at_scale() public {
        uint256 totalBytes;

        // Open and settle all sessions.
        for (uint256 i; i < NUM_SESSIONS; ++i) {
            address client = vm.addr(0xC000 + i + 1);
            uint256 clientKey = 0xC000 + i + 1;
            vm.deal(client, 1 ether);

            vm.prank(client);
            settlement.openSession{value: 0.01 ether}(nodeIds);

            uint256 cumBytes = 1000;
            totalBytes += cumBytes;
            uint256 ts = block.timestamp;

            bytes32 d = _digest(i, cumBytes, ts);
            bytes memory receipt = abi.encode(
                i, cumBytes, ts, _sign(clientKey, d), _sign(EXIT_KEY, d)
            );

            vm.prank(client);
            settlement.settleSession(i, receipt);
        }

        // At 1 wei/byte, 1000 bytes/session, 120 sessions:
        // Total paid = 120,000 wei
        // Entry 25% = 30,000, Relay 25% = 30,000, Exit 50% = 60,000
        uint256 expectedTotal = totalBytes * 1; // 1 wei/byte
        uint256 expectedEntry = (expectedTotal * 25) / 100;
        uint256 expectedRelay = (expectedTotal * 25) / 100;
        uint256 expectedExit  = expectedTotal - expectedEntry - expectedRelay;

        // Node balances should have increased by the expected amounts.
        // Initial balance was 100 ether minus 0.1 ether stake = 99.9 ether.
        uint256 entryExpected = 99.9 ether + expectedEntry;
        uint256 relayExpected = 99.9 ether + expectedRelay;
        uint256 exitExpected  = 99.9 ether + expectedExit;

        assertEq(entryOp.balance, entryExpected, "entry balance wrong");
        assertEq(relayOp.balance, relayExpected, "relay balance wrong");
        assertEq(exitOp.balance,  exitExpected,  "exit balance wrong");

        emit log_named_uint("total sessions settled", NUM_SESSIONS);
        emit log_named_uint("total bytes across all sessions", totalBytes);
        emit log_named_uint("total wei paid to nodes", expectedTotal);
    }

    /// @notice Force-settle after timeout works at scale.
    function test_force_settle_at_scale() public {
        uint256 count = 50; // force-settle subset

        for (uint256 i; i < count; ++i) {
            address client = vm.addr(0xD000 + i + 1);
            vm.deal(client, 1 ether);

            vm.prank(client);
            settlement.openSession{value: 0.01 ether}(nodeIds);
        }

        // Warp past force-settle timeout.
        vm.warp(block.timestamp + 2 hours);

        uint256 gasTotal;

        for (uint256 i; i < count; ++i) {
            uint256 cumBytes = 500;
            uint256 ts = block.timestamp;

            bytes32 d = _digest(i, cumBytes, ts);
            bytes memory nodeSig = _sign(EXIT_KEY, d);
            bytes memory receipt = abi.encode(i, cumBytes, ts, nodeSig);

            vm.prank(exitOp);
            uint256 gasBefore = gasleft();
            settlement.forceSettle(i, receipt);
            gasTotal += gasBefore - gasleft();
        }

        uint256 avgGas = gasTotal / count;
        emit log_named_uint("force_settle avg gas", avgGas);
        emit log_named_uint("force_settle count", count);

        // All should be settled.
        for (uint256 i; i < count; ++i) {
            assertTrue(settlement.getSession(i).settled);
        }
    }
}
