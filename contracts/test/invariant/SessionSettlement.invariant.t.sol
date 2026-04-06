// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {NodeRegistry}       from "../../src/NodeRegistry.sol";
import {SessionSettlement}  from "../../src/SessionSettlement.sol";
import {EIP712Utils}        from "../../src/lib/EIP712Utils.sol";

/// @title SessionSettlement Handler
/// @notice Drives random open/settle/withdraw sequences for invariant testing.
contract SettlementHandler is Test {
    NodeRegistry      public registry;
    SessionSettlement public settlement;

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

    uint256 public openCount;
    address[] public knownAddresses;

    constructor(NodeRegistry _registry, SessionSettlement _settlement) {
        registry   = _registry;
        settlement = _settlement;

        entryOp = vm.addr(ENTRY_KEY);
        relayOp = vm.addr(RELAY_KEY);
        exitOp  = vm.addr(EXIT_KEY);
        client  = vm.addr(CLIENT_KEY);

        nodeIds = [entryId, relayId, exitId];
        knownAddresses.push(entryOp);
        knownAddresses.push(relayOp);
        knownAddresses.push(exitOp);
        knownAddresses.push(client);
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

    /// @notice Open a new session with a random deposit.
    function openSession(uint256 deposit) external {
        deposit = bound(deposit, 0.001 ether, 1 ether);
        vm.deal(client, client.balance + deposit);
        vm.prank(client);
        settlement.openSession{value: deposit}(nodeIds, type(uint256).max);
        openCount++;
    }

    /// @notice Settle a random open session.
    function settleSession(uint256 sessionSeed, uint256 cumBytes) external {
        if (openCount == 0) return;
        uint256 sessionId = sessionSeed % openCount;
        cumBytes = bound(cumBytes, 0, 1e15);

        uint256 ts = block.timestamp;
        bytes32 d = _digest(sessionId, cumBytes, ts);
        bytes memory receipt = abi.encode(sessionId, cumBytes, ts, _sign(CLIENT_KEY, d), _sign(EXIT_KEY, d));

        vm.prank(client);
        try settlement.settleSession(sessionId, receipt) {} catch {}
    }

    /// @notice Withdraw for a random known address.
    function withdraw(uint256 addrSeed) external {
        address who = knownAddresses[addrSeed % knownAddresses.length];
        vm.prank(who);
        try settlement.withdraw() {} catch {}
    }
}

/// @title SessionSettlement Invariant Test
/// @notice Verifies: sum(pendingWithdrawals) <= contract balance.
contract SessionSettlementInvariantTest is Test {
    NodeRegistry       public registry;
    SessionSettlement  public settlement;
    SettlementHandler  public handler;

    function setUp() public {
        address oracle = makeAddr("oracle");
        registry   = new NodeRegistry(oracle);
        settlement = new SessionSettlement(address(registry), address(this));

        handler = new SettlementHandler(registry, settlement);

        // Register nodes.
        address entryOp = handler.entryOp();
        address relayOp = handler.relayOp();
        address exitOp  = handler.exitOp();

        vm.deal(entryOp, 10 ether);
        vm.deal(relayOp, 10 ether);
        vm.deal(exitOp, 10 ether);

        vm.prank(entryOp);
        registry.register{value: 0.1 ether}(handler.entryId(), keccak256("entry-pub"), "1.1.1.1:51820");
        vm.prank(relayOp);
        registry.register{value: 0.1 ether}(handler.relayId(), keccak256("relay-pub"), "2.2.2.2:51820");
        vm.prank(exitOp);
        registry.register{value: 0.1 ether}(handler.exitId(), keccak256("exit-pub"), "3.3.3.3:51820");

        vm.prank(exitOp);
        registry.updatePricePerByte(handler.exitId(), 1);

        targetContract(address(handler));
    }

    /// @notice Solvency: total owed via pull-payment never exceeds contract balance.
    function invariant_solvency() public view {
        uint256 totalOwed = settlement.pendingWithdrawals(handler.entryOp())
                          + settlement.pendingWithdrawals(handler.relayOp())
                          + settlement.pendingWithdrawals(handler.exitOp())
                          + settlement.pendingWithdrawals(handler.client());
        assertLe(totalOwed, address(settlement).balance, "solvency violated: owed > balance");
    }
}
