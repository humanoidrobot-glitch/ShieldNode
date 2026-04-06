// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {NodeRegistry}       from "../../src/NodeRegistry.sol";
import {SessionSettlement}  from "../../src/SessionSettlement.sol";
import {EIP712Utils}        from "../../src/lib/EIP712Utils.sol";

/// @title SessionSettlement fuzz tests
/// @notice Fuzz settlement math: conservation, caps, and split correctness.
contract SessionSettlementFuzzTest is Test {
    NodeRegistry      public registry;
    SessionSettlement public settlement;

    address public oracle = makeAddr("oracle");

    uint256 constant ENTRY_KEY  = 0xA001;
    uint256 constant RELAY_KEY  = 0xA002;
    uint256 constant EXIT_KEY   = 0xA003;
    uint256 constant CLIENT_KEY = 0xB001;

    address public entryOp;
    address public relayOp;
    address public exitOp;
    address public client;

    bytes32 public entryId = keccak256("entry");
    bytes32 public relayId = keccak256("relay");
    bytes32 public exitId  = keccak256("exit");

    bytes32[3] public nodeIds;

    function setUp() public {
        entryOp = vm.addr(ENTRY_KEY);
        relayOp = vm.addr(RELAY_KEY);
        exitOp  = vm.addr(EXIT_KEY);
        client  = vm.addr(CLIENT_KEY);

        vm.deal(entryOp, 100 ether);
        vm.deal(relayOp, 100 ether);
        vm.deal(exitOp,  100 ether);
        vm.deal(client,  100 ether);

        registry   = new NodeRegistry(oracle);
        settlement = new SessionSettlement(address(registry), address(this));

        vm.prank(entryOp);
        registry.register{value: 0.1 ether}(entryId, keccak256("entry-pub"), "1.1.1.1:51820");
        vm.prank(relayOp);
        registry.register{value: 0.1 ether}(relayId, keccak256("relay-pub"), "2.2.2.2:51820");
        vm.prank(exitOp);
        registry.register{value: 0.1 ether}(exitId, keccak256("exit-pub"), "3.3.3.3:51820");

        nodeIds = [entryId, relayId, exitId];
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
        bytes32 sh = keccak256(abi.encode(EIP712Utils.RECEIPT_TYPEHASH, sid, cb, ts));
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), sh));
    }

    function _sign(uint256 pk, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }

    /// @notice Cooperative settlement: entry + relay + exit + refund == deposit.
    function testFuzz_settle_conservation(
        uint256 pricePerByte,
        uint256 cumBytes,
        uint256 deposit
    ) public {
        // Bound inputs to reasonable ranges.
        deposit = bound(deposit, 0.001 ether, 10 ether);
        pricePerByte = bound(pricePerByte, 1, 1e12);
        cumBytes = bound(cumBytes, 0, 1e18);

        // Set exit node price.
        vm.prank(exitOp);
        registry.updatePricePerByte(exitId, pricePerByte);

        // Open session.
        vm.prank(client);
        settlement.openSession{value: deposit}(nodeIds, type(uint256).max);

        uint256 sessionId = 0;
        uint256 ts = block.timestamp;

        bytes32 d = _digest(sessionId, cumBytes, ts);
        bytes memory receipt = abi.encode(sessionId, cumBytes, ts, _sign(CLIENT_KEY, d), _sign(EXIT_KEY, d));

        vm.prank(client);
        settlement.settleSession(sessionId, receipt);

        // Conservation: all credited amounts must sum to exactly the deposit.
        uint256 total = settlement.pendingWithdrawals(entryOp)
                      + settlement.pendingWithdrawals(relayOp)
                      + settlement.pendingWithdrawals(exitOp)
                      + settlement.pendingWithdrawals(client);
        assertEq(total, deposit, "conservation violated: credits != deposit");
    }

    /// @notice Force settlement: total paid to nodes <= 50% of deposit.
    function testFuzz_forceSettle_cap(
        uint256 cumBytes,
        uint256 deposit
    ) public {
        deposit = bound(deposit, 0.001 ether, 10 ether);
        cumBytes = bound(cumBytes, 0, 1e18);

        // Set exit node price.
        vm.prank(exitOp);
        registry.updatePricePerByte(exitId, 1);

        // Open session.
        vm.prank(client);
        settlement.openSession{value: deposit}(nodeIds, type(uint256).max);

        uint256 sessionId = 0;
        uint256 ts = block.timestamp;

        // Warp past timeout.
        vm.warp(block.timestamp + 2 hours);

        bytes32 d = _digest(sessionId, cumBytes, ts);
        bytes memory receipt = abi.encode(sessionId, cumBytes, ts, _sign(EXIT_KEY, d), _sign(RELAY_KEY, d));

        vm.prank(exitOp);
        settlement.forceSettle(sessionId, receipt);

        // Cap: node payments must be at most 50% of deposit.
        uint256 nodePay = settlement.pendingWithdrawals(entryOp)
                        + settlement.pendingWithdrawals(relayOp)
                        + settlement.pendingWithdrawals(exitOp);
        uint256 cap = (deposit * 5000) / 10000;
        assertLe(nodePay, cap, "force-settle cap violated");

        // Conservation still holds.
        uint256 total = nodePay + settlement.pendingWithdrawals(client);
        assertEq(total, deposit, "conservation violated in force-settle");
    }
}
