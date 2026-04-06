// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {NodeRegistry}       from "../src/NodeRegistry.sol";
import {SessionSettlement}  from "../src/SessionSettlement.sol";
import {ISessionSettlement} from "../src/interfaces/ISessionSettlement.sol";
import {EIP712Utils}        from "../src/lib/EIP712Utils.sol";

contract SessionSettlementTest is Test {
    NodeRegistry      public registry;
    SessionSettlement public settlement;

    address public oracle = makeAddr("oracle");

    uint256 constant ENTRY_KEY = 0xA001;
    uint256 constant RELAY_KEY = 0xA002;
    uint256 constant EXIT_KEY  = 0xA003;
    uint256 constant CLIENT_KEY = 0xB001;

    address public entryOp;
    address public relayOp;
    address public exitOp;
    address public client;

    bytes32 public entryId = keccak256("entry");
    bytes32 public relayId = keccak256("relay");
    bytes32 public exitId  = keccak256("exit");

    bytes32[3] public nodeIds;

    bytes32 constant RECEIPT_TYPEHASH = EIP712Utils.RECEIPT_TYPEHASH;

    function setUp() public {
        entryOp = vm.addr(ENTRY_KEY);
        relayOp = vm.addr(RELAY_KEY);
        exitOp  = vm.addr(EXIT_KEY);
        client  = vm.addr(CLIENT_KEY);

        vm.deal(entryOp, 10 ether);
        vm.deal(relayOp, 10 ether);
        vm.deal(exitOp,  10 ether);
        vm.deal(client,  10 ether);

        registry   = new NodeRegistry(oracle);
        settlement = new SessionSettlement(address(registry), address(this));

        _registerNode(entryOp, entryId, "entry-pub", "1.1.1.1:51820");
        _registerNode(relayOp, relayId, "relay-pub", "2.2.2.2:51820");
        _registerNode(exitOp,  exitId,  "exit-pub",  "3.3.3.3:51820");

        // Set a price per byte on the exit node (required: non-zero).
        vm.prank(exitOp);
        registry.updatePricePerByte(exitId, 1); // 1 wei per byte

        nodeIds = [entryId, relayId, exitId];
    }

    // ────────────────────── Helpers ──────────────────────

    function _registerNode(
        address op, bytes32 id, string memory pubSeed, string memory endpoint
    ) internal {
        vm.prank(op);
        registry.register{value: 0.1 ether}(id, keccak256(bytes(pubSeed)), endpoint);
    }

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("ShieldNode"),
                keccak256("1"),
                block.chainid,
                address(settlement)
            )
        );
    }

    function _digest(uint256 sid, uint256 cb, uint256 ts) internal view returns (bytes32) {
        bytes32 sh = keccak256(abi.encode(RECEIPT_TYPEHASH, sid, cb, ts));
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), sh));
    }

    function _sign(uint256 pk, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }

    // ────────────────────── Open session ──────────────────────

    function test_open_session() public {
        vm.prank(client);
        settlement.openSession{value: 0.01 ether}(nodeIds, type(uint256).max);

        ISessionSettlement.SessionInfo memory s = settlement.getSession(0);
        assertEq(s.client, client);
        assertEq(s.deposit, 0.01 ether);
        assertFalse(s.settled);
        assertEq(s.nodeOwners[0], entryOp);
        assertEq(s.nodeOwners[1], relayOp);
        assertEq(s.nodeOwners[2], exitOp);
        assertEq(s.pricePerByte, 1);
    }

    function test_open_session_insufficient_deposit() public {
        vm.prank(client);
        vm.expectRevert("Session: deposit too low");
        settlement.openSession{value: 0.0001 ether}(nodeIds, type(uint256).max);
    }

    function test_open_session_inactive_node() public {
        vm.prank(relayOp);
        registry.deregister(relayId);
        vm.prank(client);
        vm.expectRevert("Session: node not active");
        settlement.openSession{value: 0.01 ether}(nodeIds, type(uint256).max);
    }

    function test_open_session_zero_price() public {
        // Exit node has pricePerByte = 0 by default on a new node.
        bytes32 cheapId = keccak256("cheap");
        address cheapOp = makeAddr("cheapOp");
        vm.deal(cheapOp, 1 ether);
        vm.prank(cheapOp);
        registry.register{value: 0.1 ether}(cheapId, keccak256("cheapPub"), "4.4.4.4:51820");
        // Don't set pricePerByte — defaults to 0.
        bytes32[3] memory ids = [entryId, relayId, cheapId];
        vm.prank(client);
        vm.expectRevert("Session: zero price");
        settlement.openSession{value: 0.01 ether}(ids, type(uint256).max);
    }

    function test_open_session_duplicate_nodes() public {
        bytes32[3] memory dupes = [entryId, entryId, exitId];
        vm.prank(client);
        vm.expectRevert("Session: duplicate nodes");
        settlement.openSession{value: 0.01 ether}(dupes, type(uint256).max);
    }

    // ────────────────────── Settle session (pull-payment) ──────────────────────

    function test_settle_session() public {
        vm.prank(client);
        settlement.openSession{value: 1 ether}(nodeIds, type(uint256).max);

        uint256 sessionId = 0;
        uint256 cumBytes   = 1000;
        uint256 ts         = block.timestamp;

        bytes32 d = _digest(sessionId, cumBytes, ts);
        bytes memory receipt = abi.encode(sessionId, cumBytes, ts, _sign(CLIENT_KEY, d), _sign(EXIT_KEY, d));

        vm.prank(client);
        settlement.settleSession(sessionId, receipt);

        // Pull-payment: check credited amounts.
        assertEq(settlement.pendingWithdrawals(entryOp), 250);
        assertEq(settlement.pendingWithdrawals(relayOp), 250);
        assertEq(settlement.pendingWithdrawals(exitOp),  500);
        assertEq(settlement.pendingWithdrawals(client),  1 ether - 1000);

        // Withdraw and verify.
        uint256 entryBefore = entryOp.balance;
        vm.prank(entryOp);
        settlement.withdraw();
        assertEq(entryOp.balance - entryBefore, 250);

        ISessionSettlement.SessionInfo memory s = settlement.getSession(sessionId);
        assertTrue(s.settled);
        assertEq(s.cumulativeBytes, cumBytes);
    }

    // ────────────────────── Force settle (2-of-3 sigs) ──────────────────────

    function test_force_settle_after_timeout() public {
        vm.prank(client);
        settlement.openSession{value: 1 ether}(nodeIds, type(uint256).max);

        uint256 sessionId = 0;
        uint256 cumBytes   = 500;
        uint256 ts         = block.timestamp;

        vm.warp(block.timestamp + 2 hours);

        bytes32 d = _digest(sessionId, cumBytes, ts);
        // 2-of-3: exit + relay sign.
        bytes memory receipt = abi.encode(sessionId, cumBytes, ts, _sign(EXIT_KEY, d), _sign(RELAY_KEY, d));

        vm.prank(exitOp);
        settlement.forceSettle(sessionId, receipt);

        ISessionSettlement.SessionInfo memory s = settlement.getSession(sessionId);
        assertTrue(s.settled);
    }

    function test_force_settle_too_early() public {
        vm.prank(client);
        settlement.openSession{value: 1 ether}(nodeIds, type(uint256).max);

        uint256 sessionId = 0;
        uint256 cumBytes   = 500;
        uint256 ts         = block.timestamp;

        bytes32 d = _digest(sessionId, cumBytes, ts);
        bytes memory receipt = abi.encode(sessionId, cumBytes, ts, _sign(EXIT_KEY, d), _sign(RELAY_KEY, d));

        vm.prank(exitOp);
        vm.expectRevert("Session: too early");
        settlement.forceSettle(sessionId, receipt);
    }

    // ────────────────────── Double settle guard ──────────────────────

    function test_double_settle_reverts() public {
        vm.prank(client);
        settlement.openSession{value: 1 ether}(nodeIds, type(uint256).max);

        uint256 sessionId = 0;
        uint256 cumBytes   = 100;
        uint256 ts         = block.timestamp;

        bytes32 d = _digest(sessionId, cumBytes, ts);
        bytes memory receipt = abi.encode(sessionId, cumBytes, ts, _sign(CLIENT_KEY, d), _sign(EXIT_KEY, d));

        vm.prank(client);
        settlement.settleSession(sessionId, receipt);

        vm.prank(client);
        vm.expectRevert("Session: already settled");
        settlement.settleSession(sessionId, receipt);
    }
}
