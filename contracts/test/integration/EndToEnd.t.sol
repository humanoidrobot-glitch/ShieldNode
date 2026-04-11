// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {Treasury}           from "../../src/Treasury.sol";
import {NodeRegistry}       from "../../src/NodeRegistry.sol";
import {SessionSettlement}  from "../../src/SessionSettlement.sol";
import {SlashingOracle}     from "../../src/SlashingOracle.sol";
import {ChallengeManager}   from "../../src/ChallengeManager.sol";
import {ISessionSettlement} from "../../src/interfaces/ISessionSettlement.sol";
import {EIP712Utils}        from "../../src/lib/EIP712Utils.sol";
import {TestKeys}           from "../helpers/TestKeys.sol";

/// @title EndToEndTest
/// @notice Full lifecycle integration test: deploy → register → session → settle.
contract EndToEndTest is Test {
    Treasury          treasury;
    NodeRegistry      registry;
    SessionSettlement settlement;
    SlashingOracle    oracle;
    ChallengeManager  cm;

    uint256 constant ENTRY_PK  = 0xA001;
    uint256 constant RELAY_PK  = 0xA002;
    uint256 constant EXIT_PK   = 0xA003;
    uint256 constant CLIENT_PK = 0xB001;

    address entryOp;
    address relayOp;
    address exitOp;
    address client;

    bytes32 entryId;
    bytes32 relayId;
    bytes32 exitId;

    bytes32[3] nodeIds;

    function setUp() public {
        entryOp = vm.addr(ENTRY_PK);
        relayOp = vm.addr(RELAY_PK);
        exitOp  = vm.addr(EXIT_PK);
        client  = vm.addr(CLIENT_PK);

        vm.deal(entryOp, 10 ether);
        vm.deal(relayOp, 10 ether);
        vm.deal(exitOp,  10 ether);
        vm.deal(client,  10 ether);

        // Deploy contracts (mirrors Deploy.s.sol ordering).
        address predictedOracle = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 3);
        treasury   = new Treasury(address(this));
        registry   = new NodeRegistry(predictedOracle);
        settlement = new SessionSettlement(address(registry), address(this));
        oracle     = new SlashingOracle(address(registry), address(treasury), address(settlement), address(this));
        require(address(oracle) == predictedOracle, "oracle address mismatch");
        cm = new ChallengeManager(address(registry), payable(address(oracle)));

        // Register 3 nodes with secp256k1 keys.
        bytes32 entryPub = keccak256("entry-pub");
        bytes32 relayPub = keccak256("relay-pub");
        bytes32 exitPub  = keccak256("exit-pub");
        entryId = keccak256(abi.encode(entryOp, entryPub));
        relayId = keccak256(abi.encode(relayOp, relayPub));
        exitId  = keccak256(abi.encode(exitOp,  exitPub));

        _registerNode(entryOp, entryId, entryPub, "1.1.1.1:51820", TestKeys.entry_key());
        _registerNode(relayOp, relayId, relayPub, "2.2.2.2:51820", TestKeys.relay_key());
        _registerNode(exitOp,  exitId,  exitPub,  "3.3.3.3:51820", TestKeys.exit_key());

        // Set prices.
        vm.prank(entryOp); registry.updatePricePerByte(entryId, 100);
        vm.prank(relayOp); registry.updatePricePerByte(relayId, 100);
        vm.prank(exitOp);  registry.updatePricePerByte(exitId,  100);

        nodeIds = [entryId, relayId, exitId];
    }

    function _registerNode(
        address op, bytes32 id, bytes32 pubKey, string memory endpoint, bytes memory secp256k1Key
    ) internal {
        vm.prank(op);
        registry.register{value: 0.1 ether}(id, pubKey, endpoint, secp256k1Key);
    }

    // ── Test: Full session lifecycle ──────────────────────────────────

    function test_full_session_lifecycle() public {
        // 1. Verify all 3 nodes are active.
        assertTrue(registry.isNodeActive(entryId), "entry not active");
        assertTrue(registry.isNodeActive(relayId), "relay not active");
        assertTrue(registry.isNodeActive(exitId),  "exit not active");

        bytes32[] memory activeNodes = registry.getActiveNodes(0, 10);
        assertEq(activeNodes.length, 3, "expected 3 active nodes");

        // 2. Client opens a session.
        vm.prank(client);
        settlement.openSession{value: 1 ether}(nodeIds, type(uint256).max);

        uint256 sessionId = 0;
        ISessionSettlement.SessionInfo memory session = settlement.getSession(sessionId);
        assertEq(session.client, client);
        assertEq(session.deposit, 1 ether);
        assertFalse(session.settled);

        // 3. Simulate bandwidth usage and create a receipt.
        uint256 cumBytes  = 10_000;
        uint256 timestamp = block.timestamp;

        bytes32 digest = _digest(sessionId, cumBytes, timestamp);

        // 4. All parties sign the receipt.
        bytes memory clientSig = _sign(CLIENT_PK, digest);
        bytes memory entrySig  = _sign(ENTRY_PK, digest);
        bytes memory relaySig  = _sign(RELAY_PK, digest);
        bytes memory exitSig   = _sign(EXIT_PK, digest);

        bytes memory receipt = abi.encode(
            sessionId, cumBytes, timestamp,
            clientSig, entrySig, relaySig, exitSig
        );

        // 5. Client settles the session.
        vm.prank(client);
        settlement.settleSession(sessionId, receipt);

        session = settlement.getSession(sessionId);
        assertTrue(session.settled, "session not settled");
        assertEq(session.cumulativeBytes, cumBytes);

        // 6. Verify payments were credited.
        // price=100, cumBytes=10000
        // entryPay = 10000 * 100 * 25 / 100 = 250_000
        // relayPay = 10000 * 100 * 25 / 100 = 250_000
        // exitPay  = 10000 * 100 * 50 / 100 = 500_000
        uint256 totalPaid = 250_000 + 250_000 + 500_000;
        assertEq(settlement.pendingWithdrawals(entryOp), 250_000);
        assertEq(settlement.pendingWithdrawals(relayOp), 250_000);
        assertEq(settlement.pendingWithdrawals(exitOp),  500_000);
        assertEq(settlement.pendingWithdrawals(client),  1 ether - totalPaid);

        // 7. Nodes withdraw their payments.
        uint256 entryBefore = entryOp.balance;
        vm.prank(entryOp);
        settlement.withdraw();
        assertEq(entryOp.balance - entryBefore, 250_000);

        // 8. Open session count is zero — node can unstake.
        assertEq(settlement.openSessionCount(entryId), 0);
        assertEq(settlement.openSessionCount(relayId), 0);
        assertEq(settlement.openSessionCount(exitId),  0);
    }

    // ── Test: Force settle after timeout ──────────────────────────────

    function test_force_settle_lifecycle() public {
        vm.prank(client);
        settlement.openSession{value: 1 ether}(nodeIds, type(uint256).max);

        uint256 sessionId = 0;
        uint256 cumBytes  = 5000;
        uint256 timestamp = block.timestamp;

        bytes32 digest = _digest(sessionId, cumBytes, timestamp);
        bytes memory receipt = abi.encode(
            sessionId, cumBytes, timestamp,
            _sign(ENTRY_PK, digest),
            _sign(RELAY_PK, digest),
            _sign(EXIT_PK, digest)
        );

        // Warp past force-settle timeout.
        vm.warp(block.timestamp + 2 hours);

        vm.prank(exitOp);
        settlement.forceSettle(sessionId, receipt);

        ISessionSettlement.SessionInfo memory session = settlement.getSession(sessionId);
        assertTrue(session.settled);
    }

    // ── Test: Session cleanup after 30 days ───────────────────────────

    function test_cleanup_lifecycle() public {
        vm.prank(client);
        settlement.openSession{value: 1 ether}(nodeIds, type(uint256).max);

        // Warp 30 days.
        vm.warp(block.timestamp + 30 days + 1);

        // Anyone can clean up.
        settlement.cleanupSession(0);

        ISessionSettlement.SessionInfo memory session = settlement.getSession(0);
        assertTrue(session.settled);
        assertEq(settlement.pendingWithdrawals(client), 1 ether); // full refund
    }

    // ── Test: Heartbeat + deregistration ──────────────────────────────

    function test_heartbeat_and_deregister() public {
        // Heartbeat.
        vm.prank(entryOp);
        registry.heartbeat(entryId);

        // Deregister.
        vm.prank(entryOp);
        registry.deregister(entryId);
        assertFalse(registry.isNodeActive(entryId));

        // Active nodes should be 2 now.
        bytes32[] memory active = registry.getActiveNodes(0, 10);
        assertEq(active.length, 2);
    }

    // ── Test: Commitment setter ──────────────────────────────────────

    function test_set_commitment() public {
        bytes32 commitment = keccak256("my-zk-commitment");
        vm.prank(entryOp);
        registry.setCommitment(entryId, commitment);

        assertEq(registry.getNode(entryId).commitment, commitment);
    }

    // ── Helpers ───────────────────────────────────────────────────────

    function _digest(uint256 sid, uint256 cb, uint256 ts) internal view returns (bytes32) {
        bytes32 typehash = EIP712Utils.RECEIPT_TYPEHASH;
        bytes32 sh = keccak256(abi.encode(typehash, sid, cb, ts));
        bytes32 domainSep = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("ShieldNode"),
                keccak256("1"),
                block.chainid,
                address(settlement)
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSep, sh));
    }

    function _sign(uint256 pk, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }
}
