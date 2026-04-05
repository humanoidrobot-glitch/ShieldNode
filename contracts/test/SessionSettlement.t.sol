// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {NodeRegistry}       from "../src/NodeRegistry.sol";
import {SessionSettlement}  from "../src/SessionSettlement.sol";
import {INodeRegistry}      from "../src/interfaces/INodeRegistry.sol";
import {ISessionSettlement} from "../src/interfaces/ISessionSettlement.sol";
import {EIP712Utils}        from "../src/lib/EIP712Utils.sol";

/// @title SessionSettlementTest
/// @notice Foundry tests for the SessionSettlement contract.
contract SessionSettlementTest is Test {
    NodeRegistry      public registry;
    SessionSettlement public settlement;

    address public oracle = makeAddr("oracle");

    // Three node operators + a client (all with private keys for signing).
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

    // EIP-712 constants — imported from shared library.
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
        settlement = new SessionSettlement(address(registry));

        // Register three nodes.
        _registerNode(entryOp, entryId, "entry-pub", "1.1.1.1:51820");
        _registerNode(relayOp, relayId, "relay-pub", "2.2.2.2:51820");
        _registerNode(exitOp,  exitId,  "exit-pub",  "3.3.3.3:51820");

        // Set a price per byte on the exit node.
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

    /// @dev Build the EIP-712 domain separator matching SessionSettlement.
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

    // ────────────────────── Open session ──────────────────────

    function test_open_session() public {
        vm.prank(client);
        settlement.openSession{value: 0.01 ether}(nodeIds);

        ISessionSettlement.SessionInfo memory s = settlement.getSession(0);
        assertEq(s.client, client);
        assertEq(s.deposit, 0.01 ether);
        assertFalse(s.settled);
        assertEq(s.nodeIds[0], entryId);
        assertEq(s.nodeIds[1], relayId);
        assertEq(s.nodeIds[2], exitId);
    }

    function test_open_session_insufficient_deposit() public {
        vm.prank(client);
        vm.expectRevert("Session: deposit too low");
        settlement.openSession{value: 0.0001 ether}(nodeIds);
    }

    function test_open_session_inactive_node() public {
        // Deregister the relay node.
        vm.prank(relayOp);
        registry.deregister(relayId);

        vm.prank(client);
        vm.expectRevert("Session: node not active");
        settlement.openSession{value: 0.01 ether}(nodeIds);
    }

    // ────────────────────── Settle session ──────────────────────

    function test_settle_session() public {
        vm.prank(client);
        settlement.openSession{value: 1 ether}(nodeIds);

        uint256 sessionId = 0;
        uint256 cumBytes   = 1000; // 1000 bytes at 1 wei/byte = 1000 wei total
        uint256 ts         = block.timestamp;

        bytes32 d = _digest(sessionId, cumBytes, ts);
        bytes memory clientSig = _sign(CLIENT_KEY, d);
        bytes memory nodeSig   = _sign(EXIT_KEY, d);

        bytes memory receipt = abi.encode(sessionId, cumBytes, ts, clientSig, nodeSig);

        uint256 entryBefore = entryOp.balance;
        uint256 relayBefore = relayOp.balance;
        uint256 exitBefore  = exitOp.balance;
        uint256 clientBefore = client.balance;

        vm.prank(client);
        settlement.settleSession(sessionId, receipt);

        // Total paid = 1000 wei.  Entry 25% = 250, Relay 25% = 250, Exit 50% = 500.
        assertEq(entryOp.balance - entryBefore, 250);
        assertEq(relayOp.balance - relayBefore, 250);
        assertEq(exitOp.balance  - exitBefore,  500);

        // Client refund = 1 ether - 1000 wei.
        assertEq(client.balance - clientBefore, 1 ether - 1000);

        ISessionSettlement.SessionInfo memory s = settlement.getSession(sessionId);
        assertTrue(s.settled);
        assertEq(s.cumulativeBytes, cumBytes);
    }

    // ────────────────────── Force settle ──────────────────────

    function test_force_settle_after_timeout() public {
        vm.prank(client);
        settlement.openSession{value: 1 ether}(nodeIds);

        uint256 sessionId = 0;
        uint256 cumBytes   = 500;
        uint256 ts         = block.timestamp;

        // Warp past FORCE_SETTLE_TIMEOUT (1 hour).
        vm.warp(block.timestamp + 2 hours);

        bytes32 d = _digest(sessionId, cumBytes, ts);
        bytes memory nodeSig = _sign(EXIT_KEY, d);

        bytes memory receipt = abi.encode(sessionId, cumBytes, ts, nodeSig);

        vm.prank(exitOp);
        settlement.forceSettle(sessionId, receipt);

        ISessionSettlement.SessionInfo memory s = settlement.getSession(sessionId);
        assertTrue(s.settled);
    }

    function test_force_settle_too_early() public {
        vm.prank(client);
        settlement.openSession{value: 1 ether}(nodeIds);

        uint256 sessionId = 0;
        uint256 cumBytes   = 500;
        uint256 ts         = block.timestamp;

        bytes32 d = _digest(sessionId, cumBytes, ts);
        bytes memory nodeSig = _sign(EXIT_KEY, d);

        bytes memory receipt = abi.encode(sessionId, cumBytes, ts, nodeSig);

        // Do NOT warp — should be too early.
        vm.prank(exitOp);
        vm.expectRevert("Session: too early");
        settlement.forceSettle(sessionId, receipt);
    }

    // ────────────────────── Double settle guard ──────────────────────

    function test_double_settle_reverts() public {
        vm.prank(client);
        settlement.openSession{value: 1 ether}(nodeIds);

        uint256 sessionId = 0;
        uint256 cumBytes   = 100;
        uint256 ts         = block.timestamp;

        bytes32 d = _digest(sessionId, cumBytes, ts);
        bytes memory receipt = abi.encode(
            sessionId, cumBytes, ts, _sign(CLIENT_KEY, d), _sign(EXIT_KEY, d)
        );

        vm.prank(client);
        settlement.settleSession(sessionId, receipt);

        vm.prank(client);
        vm.expectRevert("Session: already settled");
        settlement.settleSession(sessionId, receipt);
    }
}
