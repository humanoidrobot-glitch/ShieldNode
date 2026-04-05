// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {NodeRegistry}       from "../src/NodeRegistry.sol";
import {SessionSettlement}  from "../src/SessionSettlement.sol";
import {ISessionSettlement} from "../src/interfaces/ISessionSettlement.sol";
import {EIP712Utils}        from "../src/lib/EIP712Utils.sol";

contract StressTest is Test {
    NodeRegistry      public registry;
    SessionSettlement public settlement;

    address public oracle = makeAddr("oracle");

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
        registry.updatePricePerByte(exitId, 1);

        nodeIds = [entryId, relayId, exitId];
    }

    function _registerNode(address op, bytes32 id, string memory pub_, string memory ep) internal {
        vm.prank(op);
        registry.register{value: 0.1 ether}(id, keccak256(bytes(pub_)), ep);
    }

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("ShieldNode"), keccak256("1"), block.chainid, address(settlement)
        ));
    }

    function _digest(uint256 sid, uint256 cb, uint256 ts) internal view returns (bytes32) {
        bytes32 sh = keccak256(abi.encode(RECEIPT_TYPEHASH, sid, cb, ts));
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), sh));
    }

    function _sign(uint256 pk, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }

    function test_open_120_sessions() public {
        uint256 gasTotal;
        for (uint256 i; i < NUM_SESSIONS; ++i) {
            address c = vm.addr(0xC000 + i + 1);
            vm.deal(c, 1 ether);
            vm.prank(c);
            uint256 g = gasleft();
            settlement.openSession{value: 0.01 ether}(nodeIds);
            gasTotal += g - gasleft();
        }
        assertEq(settlement.nextSessionId(), NUM_SESSIONS);
        uint256 avg = gasTotal / NUM_SESSIONS;
        emit log_named_uint("open_session avg gas", avg);
        // Budget increased: now snapshots 3 owners + reads price.
        assertLt(avg, 300_000, "open_session gas exceeded budget");
    }

    function test_open_and_settle_120_sessions() public {
        uint256 openGas; uint256 settleGas;

        for (uint256 i; i < NUM_SESSIONS; ++i) {
            address c = vm.addr(0xC000 + i + 1);
            vm.deal(c, 1 ether);
            vm.prank(c);
            uint256 g = gasleft();
            settlement.openSession{value: 0.01 ether}(nodeIds);
            openGas += g - gasleft();
        }

        for (uint256 i; i < NUM_SESSIONS; ++i) {
            address c = vm.addr(0xC000 + i + 1);
            uint256 ck = 0xC000 + i + 1;
            uint256 cb = 1000 + i;
            bytes32 d = _digest(i, cb, block.timestamp);
            bytes memory receipt = abi.encode(i, cb, block.timestamp, _sign(ck, d), _sign(EXIT_KEY, d));
            vm.prank(c);
            uint256 g = gasleft();
            settlement.settleSession(i, receipt);
            settleGas += g - gasleft();
        }

        for (uint256 i; i < NUM_SESSIONS; ++i) {
            assertTrue(settlement.getSession(i).settled);
        }

        emit log_named_uint("open avg gas", openGas / NUM_SESSIONS);
        emit log_named_uint("settle avg gas", settleGas / NUM_SESSIONS);
        assertLt(openGas / NUM_SESSIONS, 300_000, "open gas exceeded budget");
        assertLt(settleGas / NUM_SESSIONS, 200_000, "settle gas exceeded budget");
    }

    function test_payment_distribution_at_scale() public {
        uint256 totalBytes;

        for (uint256 i; i < NUM_SESSIONS; ++i) {
            address c = vm.addr(0xC000 + i + 1);
            uint256 ck = 0xC000 + i + 1;
            vm.deal(c, 1 ether);
            vm.prank(c);
            settlement.openSession{value: 0.01 ether}(nodeIds);

            uint256 cb = 1000;
            totalBytes += cb;
            bytes32 d = _digest(i, cb, block.timestamp);
            bytes memory receipt = abi.encode(i, cb, block.timestamp, _sign(ck, d), _sign(EXIT_KEY, d));
            vm.prank(c);
            settlement.settleSession(i, receipt);
        }

        // Pull-payment: check pending withdrawals instead of balances.
        uint256 expectedTotal = totalBytes * 1;
        uint256 expectedEntry = (expectedTotal * 25) / 100;
        uint256 expectedRelay = (expectedTotal * 25) / 100;
        uint256 expectedExit  = expectedTotal - expectedEntry - expectedRelay;

        assertEq(settlement.pendingWithdrawals(entryOp), expectedEntry, "entry pending wrong");
        assertEq(settlement.pendingWithdrawals(relayOp), expectedRelay, "relay pending wrong");
        assertEq(settlement.pendingWithdrawals(exitOp),  expectedExit,  "exit pending wrong");
    }

    function test_force_settle_at_scale() public {
        uint256 count = 50;

        for (uint256 i; i < count; ++i) {
            address c = vm.addr(0xD000 + i + 1);
            vm.deal(c, 1 ether);
            vm.prank(c);
            settlement.openSession{value: 0.01 ether}(nodeIds);
        }

        vm.warp(block.timestamp + 2 hours);
        uint256 gasTotal;

        for (uint256 i; i < count; ++i) {
            uint256 cb = 500;
            bytes32 d = _digest(i, cb, block.timestamp);
            // 2-of-3 sigs: exit + relay.
            bytes memory receipt = abi.encode(i, cb, block.timestamp, _sign(EXIT_KEY, d), _sign(RELAY_KEY, d));
            vm.prank(exitOp);
            uint256 g = gasleft();
            settlement.forceSettle(i, receipt);
            gasTotal += g - gasleft();
        }

        emit log_named_uint("force_settle avg gas", gasTotal / count);
        for (uint256 i; i < count; ++i) {
            assertTrue(settlement.getSession(i).settled);
        }
    }
}
