// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {NodeRegistry}       from "../src/NodeRegistry.sol";
import {SessionSettlement}  from "../src/SessionSettlement.sol";
import {ISessionSettlement} from "../src/interfaces/ISessionSettlement.sol";
import {EIP712Utils}        from "../src/lib/EIP712Utils.sol";
import {TestKeys}           from "./helpers/TestKeys.sol";

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

    bytes32 public entryPub;
    bytes32 public relayPub;
    bytes32 public exitPub;

    bytes32 public entryId;
    bytes32 public relayId;
    bytes32 public exitId;

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

        // Derive nodeIds from operator + publicKey (Finding 14).
        entryPub = keccak256(bytes("entry-pub"));
        relayPub = keccak256(bytes("relay-pub"));
        exitPub  = keccak256(bytes("exit-pub"));
        entryId  = keccak256(abi.encode(entryOp, entryPub));
        relayId  = keccak256(abi.encode(relayOp, relayPub));
        exitId   = keccak256(abi.encode(exitOp,  exitPub));

        registry   = new NodeRegistry(oracle);
        settlement = new SessionSettlement(address(registry), address(this));

        _registerNode(entryOp, entryId, entryPub, "1.1.1.1:51820", TestKeys.entry_key());
        _registerNode(relayOp, relayId, relayPub, "2.2.2.2:51820", TestKeys.relay_key());
        _registerNode(exitOp,  exitId,  exitPub,  "3.3.3.3:51820", TestKeys.exit_key());

        // Set price on all nodes (Finding 11: per-node prices).
        vm.prank(entryOp);
        registry.updatePricePerByte(entryId, 1);
        vm.prank(relayOp);
        registry.updatePricePerByte(relayId, 1);
        vm.prank(exitOp);
        registry.updatePricePerByte(exitId, 1);

        nodeIds = [entryId, relayId, exitId];
    }

    // ────────────────────── Helpers ──────────────────────

    function _registerNode(
        address op, bytes32 id, bytes32 pubKey, string memory endpoint, bytes memory secp256k1Key
    ) internal {
        vm.prank(op);
        registry.register{value: 0.1 ether}(id, pubKey, endpoint, secp256k1Key);
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

    /// @dev Build a cooperative settlement receipt (client + 3 node sigs).
    function _coopReceipt(uint256 sid, uint256 cb, uint256 ts) internal view returns (bytes memory) {
        bytes32 d = _digest(sid, cb, ts);
        return abi.encode(
            sid, cb, ts,
            _sign(CLIENT_KEY, d),
            _sign(ENTRY_KEY, d),
            _sign(RELAY_KEY, d),
            _sign(EXIT_KEY, d)
        );
    }

    /// @dev Build a force-settle receipt (3 node sigs, no client sig).
    function _forceReceipt(uint256 sid, uint256 cb, uint256 ts) internal view returns (bytes memory) {
        bytes32 d = _digest(sid, cb, ts);
        return abi.encode(
            sid, cb, ts,
            _sign(ENTRY_KEY, d),
            _sign(RELAY_KEY, d),
            _sign(EXIT_KEY, d)
        );
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
        assertEq(s.nodePrices[0], 1);
        assertEq(s.nodePrices[1], 1);
        assertEq(s.nodePrices[2], 1);
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
        // A node with pricePerByte = 0 should be rejected.
        bytes32 cheapPub = keccak256("cheapPub");
        uint256 cheapPk = 0xDEAD1;
        address cheapOp = vm.addr(cheapPk);
        vm.deal(cheapOp, 1 ether);
        bytes32 cheapId = keccak256(abi.encode(cheapOp, cheapPub));
        vm.prank(cheapOp);
        registry.register{value: 0.1 ether}(cheapId, cheapPub, "4.4.4.4:51820", TestKeys.operator_key());
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

        vm.prank(client);
        settlement.settleSession(sessionId, _coopReceipt(sessionId, cumBytes, ts));

        // Per-node prices are all 1 wei/byte.
        // entryPay = 1000 * 1 * 25 / 100 = 250
        // relayPay = 1000 * 1 * 25 / 100 = 250
        // exitPay  = 1000 * 1 * 50 / 100 = 500
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

    // ────────────────────── Force settle (3 node sigs) ──────────────────────

    function test_force_settle_after_timeout() public {
        vm.prank(client);
        settlement.openSession{value: 1 ether}(nodeIds, type(uint256).max);

        uint256 sessionId = 0;
        uint256 cumBytes   = 500;
        uint256 ts         = block.timestamp;

        vm.warp(block.timestamp + 2 hours);

        vm.prank(exitOp);
        settlement.forceSettle(sessionId, _forceReceipt(sessionId, cumBytes, ts));

        ISessionSettlement.SessionInfo memory s = settlement.getSession(sessionId);
        assertTrue(s.settled);
    }

    function test_force_settle_too_early() public {
        vm.prank(client);
        settlement.openSession{value: 1 ether}(nodeIds, type(uint256).max);

        uint256 sessionId = 0;
        uint256 cumBytes   = 500;
        uint256 ts         = block.timestamp;

        vm.prank(exitOp);
        vm.expectRevert("Session: too early");
        settlement.forceSettle(sessionId, _forceReceipt(sessionId, cumBytes, ts));
    }

    // ────────────────────── Double settle guard ──────────────────────

    function test_double_settle_reverts() public {
        vm.prank(client);
        settlement.openSession{value: 1 ether}(nodeIds, type(uint256).max);

        uint256 sessionId = 0;
        uint256 cumBytes   = 100;
        uint256 ts         = block.timestamp;
        bytes memory receipt = _coopReceipt(sessionId, cumBytes, ts);

        vm.prank(client);
        settlement.settleSession(sessionId, receipt);

        vm.prank(client);
        vm.expectRevert("Session: already settled");
        settlement.settleSession(sessionId, receipt);
    }

    // ────────────────────── Zero-byte settlement ──────────────────────

    function test_settle_zero_bytes_refunds_deposit() public {
        vm.prank(client);
        settlement.openSession{value: 1 ether}(nodeIds, type(uint256).max);

        uint256 sessionId = 0;
        uint256 cumBytes   = 0;
        uint256 ts         = block.timestamp;

        vm.prank(client);
        settlement.settleSession(sessionId, _coopReceipt(sessionId, cumBytes, ts));

        // Zero bytes → zero payment → full refund.
        assertEq(settlement.pendingWithdrawals(entryOp), 0);
        assertEq(settlement.pendingWithdrawals(relayOp), 0);
        assertEq(settlement.pendingWithdrawals(exitOp),  0);
        assertEq(settlement.pendingWithdrawals(client),  1 ether);

        ISessionSettlement.SessionInfo memory s = settlement.getSession(sessionId);
        assertTrue(s.settled);
        assertEq(s.cumulativeBytes, 0);
    }

    // ────────────────────── Idle session cleanup ──────────────────────

    function test_cleanup_after_timeout() public {
        vm.prank(client);
        settlement.openSession{value: 1 ether}(nodeIds, type(uint256).max);

        // Cannot clean up before timeout.
        vm.expectRevert("Session: cleanup too early");
        settlement.cleanupSession(0);

        // Warp past 30-day timeout.
        vm.warp(block.timestamp + 30 days + 1);

        // Anyone can trigger cleanup.
        address anyone = makeAddr("anyone");
        vm.prank(anyone);
        settlement.cleanupSession(0);

        // Full deposit refunded to client.
        assertEq(settlement.pendingWithdrawals(client), 1 ether);

        // Session marked settled.
        ISessionSettlement.SessionInfo memory s = settlement.getSession(0);
        assertTrue(s.settled);

        // Open session count decremented — nodes can unstake.
        assertEq(settlement.openSessionCount(entryId), 0);
        assertEq(settlement.openSessionCount(relayId), 0);
        assertEq(settlement.openSessionCount(exitId),  0);
    }

    function test_cleanup_already_settled_reverts() public {
        vm.prank(client);
        settlement.openSession{value: 1 ether}(nodeIds, type(uint256).max);

        // Settle normally first.
        uint256 ts = block.timestamp;
        vm.prank(client);
        settlement.settleSession(0, _coopReceipt(0, 100, ts));

        // Cleanup should fail.
        vm.warp(block.timestamp + 30 days + 1);
        vm.expectRevert("Session: already settled");
        settlement.cleanupSession(0);
    }

    // ────────────────────── cumulativeBytes cap (Fix 4) ──────────────────────

    function test_settle_bytes_overflow_reverts() public {
        vm.prank(client);
        settlement.openSession{value: 1 ether}(nodeIds, type(uint256).max);

        uint256 sessionId = 0;
        uint256 cumBytes   = 1e30 + 1; // exceeds MAX_CUMULATIVE_BYTES
        uint256 ts         = block.timestamp;

        vm.prank(client);
        vm.expectRevert("Session: bytes overflow");
        settlement.settleSession(sessionId, _coopReceipt(sessionId, cumBytes, ts));
    }
}
