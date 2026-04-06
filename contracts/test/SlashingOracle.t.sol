// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {NodeRegistry}       from "../src/NodeRegistry.sol";
import {SessionSettlement}  from "../src/SessionSettlement.sol";
import {SlashingOracle}     from "../src/SlashingOracle.sol";
import {ISlashingOracle}    from "../src/interfaces/ISlashingOracle.sol";
import {INodeRegistry}      from "../src/interfaces/INodeRegistry.sol";
import {Treasury}           from "../src/Treasury.sol";

/// @title SlashingOracleTest
/// @notice Comprehensive Foundry tests for the SlashingOracle contract,
///         including on-chain evidence verification for all three slash reasons.
contract SlashingOracleTest is Test {
    NodeRegistry      public registry;
    SessionSettlement public settlement;
    SlashingOracle    public oracle;
    Treasury          public treasury;

    // Actors
    address public deployer    = makeAddr("deployer");
    address public challenger  = makeAddr("challenger");
    address public rando       = makeAddr("rando");

    // Client keypair for signing receipts.
    uint256 internal clientPk  = 0xA11CE;
    address internal clientAddr;

    // Node operator keypair for signing receipts.
    uint256 internal nodePk    = 0xB0B;
    address internal nodeAddr;

    // Challenger keypair for attestations.
    uint256 internal challPk   = 0xC0DE;
    address internal challAddr;

    bytes32 constant NODE_ID       = keccak256("node-1");
    bytes32 constant PUB_KEY       = keccak256("pubkey-1");
    string  constant ENDPOINT      = "192.168.1.1:51820";
    bytes32 constant UNKNOWN_NODE  = keccak256("non-existent-node");

    // Extra node operators for session creation.
    uint256 internal entryPk = 0xE001;
    uint256 internal relayPk = 0xE002;
    address internal entryAddr;
    address internal relayAddr;
    bytes32 constant ENTRY_ID = keccak256("entry-node");
    bytes32 constant RELAY_ID = keccak256("relay-node");

    // EIP-712 constants — read from deployed contracts in setUp().
    bytes32 internal domainSep;
    bytes32 internal attestationDomainSep;
    bytes32 internal RECEIPT_TYPEHASH;
    bytes32 internal ATTESTATION_TYPEHASH;

    function setUp() public {
        clientAddr = vm.addr(clientPk);
        nodeAddr   = vm.addr(nodePk);
        challAddr  = vm.addr(challPk);
        entryAddr  = vm.addr(entryPk);
        relayAddr  = vm.addr(relayPk);

        vm.startPrank(deployer);

        // Deploy contracts in the same order as Deploy.s.sol.
        treasury = new Treasury(deployer);

        // Predict oracle address (deployed 2 contracts later).
        uint64 nonce = vm.getNonce(deployer);
        address predictedOracle = vm.computeCreateAddress(deployer, nonce + 2);

        registry   = new NodeRegistry(predictedOracle);
        settlement = new SessionSettlement(address(registry), deployer);
        oracle     = new SlashingOracle(
            address(registry),
            address(treasury),
            address(settlement),
            deployer
        );
        require(address(oracle) == predictedOracle, "oracle address mismatch");

        // Authorise the challenger (timelocked: propose → warp → execute).
        oracle.proposeChallenger(challAddr, true);
        vm.warp(block.timestamp + oracle.CHALLENGER_TIMELOCK() + 1);
        oracle.executeChallenger(0);

        vm.stopPrank();

        // Fund actors.
        vm.deal(nodeAddr, 10 ether);
        vm.deal(clientAddr, 10 ether);
        vm.deal(challAddr, 10 ether);
        vm.deal(entryAddr, 10 ether);
        vm.deal(relayAddr, 10 ether);

        // Register nodes for 3-hop session.
        vm.prank(entryAddr);
        registry.register{value: 0.1 ether}(ENTRY_ID, keccak256("entry-pub"), "1.1.1.1:51820");
        vm.prank(relayAddr);
        registry.register{value: 0.1 ether}(RELAY_ID, keccak256("relay-pub"), "2.2.2.2:51820");
        vm.prank(nodeAddr);
        registry.register{value: 1 ether}(NODE_ID, PUB_KEY, ENDPOINT);

        // Set exit price (NODE_ID as exit) and open a session for fraud tests.
        vm.prank(nodeAddr);
        registry.updatePricePerByte(NODE_ID, 1);
        bytes32[3] memory sNodeIds = [ENTRY_ID, RELAY_ID, NODE_ID];
        vm.prank(clientAddr);
        settlement.openSession{value: 1 ether}(sNodeIds, type(uint256).max);

        // Read EIP-712 constants from the deployed contracts.
        domainSep = oracle.DOMAIN_SEPARATOR();
        attestationDomainSep = oracle.ATTESTATION_DOMAIN_SEPARATOR();
        RECEIPT_TYPEHASH = oracle.RECEIPT_TYPEHASH();
        ATTESTATION_TYPEHASH = oracle.ATTESTATION_TYPEHASH();
    }

    // ────────────────────── Helpers ──────────────────────

    /// @dev Sign a BandwidthReceipt with the given private key.
    function _signReceipt(
        uint256 pk,
        uint256 sessionId,
        uint256 cumBytes,
        uint256 ts
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(RECEIPT_TYPEHASH, sessionId, cumBytes, ts)
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSep, structHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @dev Sign a SlashAttestation with the given private key.
    function _signAttestation(
        uint256 pk,
        bytes32 nodeId,
        uint256 ts,
        bytes32 descHash
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(ATTESTATION_TYPEHASH, nodeId, ts, descHash)
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", attestationDomainSep, structHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @dev Build BandwidthFraud evidence with two conflicting receipts.
    function _buildFraudEvidence(
        uint256 sessionId,
        uint256 bytes1_, uint256 ts1,
        uint256 bytes2_, uint256 ts2
    ) internal view returns (bytes memory) {
        bytes memory cSig1 = _signReceipt(clientPk, sessionId, bytes1_, ts1);
        bytes memory nSig1 = _signReceipt(nodePk, sessionId, bytes1_, ts1);
        bytes memory cSig2 = _signReceipt(clientPk, sessionId, bytes2_, ts2);
        bytes memory nSig2 = _signReceipt(nodePk, sessionId, bytes2_, ts2);

        SlashingOracle.FraudReceipt memory r1 = SlashingOracle.FraudReceipt(bytes1_, ts1, cSig1, nSig1);
        SlashingOracle.FraudReceipt memory r2 = SlashingOracle.FraudReceipt(bytes2_, ts2, cSig2, nSig2);

        return abi.encode(sessionId, r1, r2);
    }

    /// @dev Build a challenger attestation for ProvableLogging or SelectiveDenial.
    function _buildAttestation(
        bytes32 nodeId,
        uint256 ts,
        bytes32 descHash
    ) internal view returns (bytes memory) {
        bytes memory sig = _signAttestation(challPk, nodeId, ts, descHash);
        return abi.encode(nodeId, ts, descHash, sig);
    }

    /// @dev Propose and then execute a slash (advancing time past grace period).
    function _proposeAndExecute(
        bytes32 nodeId,
        uint8 reason,
        bytes memory evidence
    ) internal returns (uint256 proposalId) {
        proposalId = oracle.nextProposalId();
        vm.prank(challAddr);
        oracle.proposeSlash(nodeId, reason, evidence);
        vm.warp(block.timestamp + oracle.GRACE_PERIOD() + 1);
        oracle.executeSlash(proposalId);
    }

    // ════════════════════════════════════════════════════════════
    //  BandwidthFraud tests
    // ════════════════════════════════════════════════════════════

    function test_bandwidthFraud_validEvidence() public {
        bytes memory evidence = _buildFraudEvidence(0, 1000, 100, 2000, 200);

        vm.prank(challAddr);
        oracle.proposeSlash(NODE_ID, uint8(ISlashingOracle.SlashReason.BandwidthFraud), evidence);

        // Proposal should be stored.
        (bytes32 nid,,,, bool executed) = oracle.proposals(0);
        assertEq(nid, NODE_ID);
        assertFalse(executed);
    }

    function test_bandwidthFraud_sameBytes_reverts() public {
        // Two receipts with identical byte counts — not fraud.
        bytes memory evidence = _buildFraudEvidence(0, 1000, 100, 1000, 200);

        vm.prank(challAddr);
        vm.expectRevert(abi.encodeWithSelector(
            SlashingOracle.InvalidEvidence.selector, "byte counts match"
        ));
        oracle.proposeSlash(NODE_ID, uint8(ISlashingOracle.SlashReason.BandwidthFraud), evidence);
    }

    function test_bandwidthFraud_wrongNodeSigner_reverts() public {
        // Build evidence where node sigs come from a different key (not in session).
        uint256 wrongPk = 0xDEAD;
        bytes memory cSig1 = _signReceipt(clientPk, 0, 1000, 100);
        bytes memory nSig1 = _signReceipt(wrongPk, 0, 1000, 100);
        bytes memory cSig2 = _signReceipt(clientPk, 0, 2000, 200);
        bytes memory nSig2 = _signReceipt(wrongPk, 0, 2000, 200);

        SlashingOracle.FraudReceipt memory r1 = SlashingOracle.FraudReceipt(1000, 100, cSig1, nSig1);
        SlashingOracle.FraudReceipt memory r2 = SlashingOracle.FraudReceipt(2000, 200, cSig2, nSig2);
        bytes memory evidence = abi.encode(uint256(0), r1, r2);

        vm.prank(challAddr);
        vm.expectRevert(abi.encodeWithSelector(
            SlashingOracle.InvalidEvidence.selector, "node signer not in session"
        ));
        oracle.proposeSlash(NODE_ID, uint8(ISlashingOracle.SlashReason.BandwidthFraud), evidence);
    }

    function test_bandwidthFraud_differentClients_reverts() public {
        uint256 otherClientPk = 0xF00D;
        bytes memory cSig1 = _signReceipt(clientPk, 0, 1000, 100);
        bytes memory nSig1 = _signReceipt(nodePk, 0, 1000, 100);
        bytes memory cSig2 = _signReceipt(otherClientPk, 0, 2000, 200);
        bytes memory nSig2 = _signReceipt(nodePk, 0, 2000, 200);

        SlashingOracle.FraudReceipt memory r1 = SlashingOracle.FraudReceipt(1000, 100, cSig1, nSig1);
        SlashingOracle.FraudReceipt memory r2 = SlashingOracle.FraudReceipt(2000, 200, cSig2, nSig2);
        bytes memory evidence = abi.encode(uint256(0), r1, r2);

        vm.prank(challAddr);
        vm.expectRevert(abi.encodeWithSelector(
            SlashingOracle.InvalidEvidence.selector, "client signers differ"
        ));
        oracle.proposeSlash(NODE_ID, uint8(ISlashingOracle.SlashReason.BandwidthFraud), evidence);
    }

    // ════════════════════════════════════════════════════════════
    //  ProvableLogging / SelectiveDenial attestation tests
    // ════════════════════════════════════════════════════════════

    function test_provableLogging_validAttestation() public {
        bytes32 descHash = keccak256("node correlated entry/exit traffic at 2024-01-01T12:00:00Z");
        bytes memory evidence = _buildAttestation(NODE_ID, block.timestamp, descHash);

        vm.prank(challAddr);
        oracle.proposeSlash(NODE_ID, uint8(ISlashingOracle.SlashReason.ProvableLogging), evidence);

        (bytes32 nid,,,, bool executed) = oracle.proposals(0);
        assertEq(nid, NODE_ID);
        assertFalse(executed);
    }

    function test_selectiveDenial_validAttestation() public {
        bytes32 descHash = keccak256("node dropped 80% of traffic to destination X");
        bytes memory evidence = _buildAttestation(NODE_ID, block.timestamp, descHash);

        vm.prank(challAddr);
        oracle.proposeSlash(NODE_ID, uint8(ISlashingOracle.SlashReason.SelectiveDenial), evidence);

        (bytes32 nid,,,, bool executed) = oracle.proposals(0);
        assertEq(nid, NODE_ID);
        assertFalse(executed);
    }

    function test_attestation_wrongNodeId_reverts() public {
        bytes32 wrongNode = keccak256("other-node");
        bytes memory evidence = _buildAttestation(wrongNode, block.timestamp, keccak256("desc"));

        vm.prank(challAddr);
        vm.expectRevert(abi.encodeWithSelector(
            SlashingOracle.InvalidEvidence.selector, "attestation nodeId mismatch"
        ));
        oracle.proposeSlash(NODE_ID, uint8(ISlashingOracle.SlashReason.ProvableLogging), evidence);
    }

    function test_attestation_futureTimestamp_reverts() public {
        bytes memory evidence = _buildAttestation(
            NODE_ID, block.timestamp + 1 hours, keccak256("desc")
        );

        vm.prank(challAddr);
        vm.expectRevert(abi.encodeWithSelector(
            SlashingOracle.InvalidEvidence.selector, "attestation timestamp in the future"
        ));
        oracle.proposeSlash(NODE_ID, uint8(ISlashingOracle.SlashReason.ProvableLogging), evidence);
    }

    function test_attestation_wrongSigner_reverts() public {
        // Sign with a different key than the caller.
        uint256 wrongPk = 0xBAD;
        bytes memory sig = _signAttestation(wrongPk, NODE_ID, block.timestamp, keccak256("desc"));
        bytes memory evidence = abi.encode(NODE_ID, block.timestamp, keccak256("desc"), sig);

        vm.prank(challAddr);
        vm.expectRevert(abi.encodeWithSelector(
            SlashingOracle.InvalidEvidence.selector, "attestation signer mismatch"
        ));
        oracle.proposeSlash(NODE_ID, uint8(ISlashingOracle.SlashReason.ProvableLogging), evidence);
    }

    // ════════════════════════════════════════════════════════════
    //  Proposal lifecycle tests
    // ════════════════════════════════════════════════════════════

    function test_proposeSlash_notChallenger_reverts() public {
        bytes memory evidence = _buildAttestation(NODE_ID, block.timestamp, keccak256("desc"));

        vm.prank(rando);
        vm.expectRevert(SlashingOracle.NotChallenger.selector);
        oracle.proposeSlash(NODE_ID, uint8(ISlashingOracle.SlashReason.ProvableLogging), evidence);
    }

    function test_proposeSlash_badReason_reverts() public {
        vm.prank(challAddr);
        vm.expectRevert(SlashingOracle.BadReason.selector);
        oracle.proposeSlash(NODE_ID, 99, "");
    }

    function test_executeSlash_beforeGracePeriod_reverts() public {
        bytes memory evidence = _buildAttestation(NODE_ID, block.timestamp, keccak256("desc"));

        vm.prank(challAddr);
        oracle.proposeSlash(NODE_ID, uint8(ISlashingOracle.SlashReason.ProvableLogging), evidence);

        // Try to execute immediately.
        vm.expectRevert(SlashingOracle.GracePeriodActive.selector);
        oracle.executeSlash(0);
    }

    function test_executeSlash_unknownProposal_reverts() public {
        vm.expectRevert(SlashingOracle.UnknownProposal.selector);
        oracle.executeSlash(999);
    }

    function test_executeSlash_alreadyExecuted_reverts() public {
        bytes memory evidence = _buildAttestation(NODE_ID, block.timestamp, keccak256("desc"));

        _proposeAndExecute(NODE_ID, uint8(ISlashingOracle.SlashReason.ProvableLogging), evidence);

        vm.expectRevert(SlashingOracle.AlreadyExecuted.selector);
        oracle.executeSlash(0);
    }

    // ════════════════════════════════════════════════════════════
    //  Progressive slashing + reward distribution
    // ════════════════════════════════════════════════════════════

    function test_firstSlash_10percent() public {
        INodeRegistry.NodeInfo memory before_ = registry.getNode(NODE_ID);
        uint256 expectedSlash = (before_.stake * 10) / 100; // 10%

        bytes memory evidence = _buildAttestation(NODE_ID, block.timestamp, keccak256("first"));
        _proposeAndExecute(NODE_ID, uint8(ISlashingOracle.SlashReason.ProvableLogging), evidence);

        INodeRegistry.NodeInfo memory after_ = registry.getNode(NODE_ID);
        assertEq(after_.stake, before_.stake - expectedSlash);
        assertEq(after_.slashCount, 1);

        // Pull-payment: 50/50 split credited to pendingWithdrawals.
        assertEq(oracle.pendingWithdrawals(challAddr), expectedSlash / 2);
        assertEq(oracle.pendingWithdrawals(address(treasury)), expectedSlash - expectedSlash / 2);

        // Withdraw and verify.
        uint256 challBefore = challAddr.balance;
        vm.prank(challAddr);
        oracle.withdraw();
        assertEq(challAddr.balance - challBefore, expectedSlash / 2);

        uint256 treasuryBefore = address(treasury).balance;
        vm.prank(address(treasury));
        oracle.withdraw();
        assertEq(address(treasury).balance - treasuryBefore, expectedSlash - expectedSlash / 2);
    }

    function test_secondSlash_25percent() public {
        // First slash.
        bytes memory ev1 = _buildAttestation(NODE_ID, block.timestamp, keccak256("first"));
        _proposeAndExecute(NODE_ID, uint8(ISlashingOracle.SlashReason.ProvableLogging), ev1);

        INodeRegistry.NodeInfo memory mid = registry.getNode(NODE_ID);
        uint256 expectedSlash = (mid.stake * 25) / 100; // 25%

        // Second slash — warp past slash cooldown.
        vm.warp(block.timestamp + oracle.GRACE_PERIOD() + 1);
        bytes memory ev2 = _buildAttestation(NODE_ID, block.timestamp, keccak256("second"));
        _proposeAndExecute(NODE_ID, uint8(ISlashingOracle.SlashReason.SelectiveDenial), ev2);

        INodeRegistry.NodeInfo memory after_ = registry.getNode(NODE_ID);
        assertEq(after_.stake, mid.stake - expectedSlash);
        assertEq(after_.slashCount, 2);
    }

    function test_thirdSlash_100percent_andBan() public {
        // First slash (10%).
        bytes memory ev1 = _buildAttestation(NODE_ID, block.timestamp, keccak256("first"));
        _proposeAndExecute(NODE_ID, uint8(ISlashingOracle.SlashReason.ProvableLogging), ev1);

        // Second slash (25%) — warp past slash cooldown.
        vm.warp(block.timestamp + oracle.GRACE_PERIOD() + 1);
        bytes memory ev2 = _buildAttestation(NODE_ID, block.timestamp, keccak256("second"));
        _proposeAndExecute(NODE_ID, uint8(ISlashingOracle.SlashReason.SelectiveDenial), ev2);

        // Third slash (100% + ban) — warp past slash cooldown.
        vm.warp(block.timestamp + oracle.GRACE_PERIOD() + 1);
        bytes memory ev3 = _buildAttestation(NODE_ID, block.timestamp, keccak256("third"));
        _proposeAndExecute(NODE_ID, uint8(ISlashingOracle.SlashReason.ProvableLogging), ev3);

        INodeRegistry.NodeInfo memory after_ = registry.getNode(NODE_ID);
        assertEq(after_.stake, 0);
        assertEq(after_.slashCount, 3);
        // Node should be banned (isNodeActive returns false).
        assertFalse(registry.isNodeActive(NODE_ID));
    }

    // ════════════════════════════════════════════════════════════
    //  Admin tests
    // ════════════════════════════════════════════════════════════

    function test_proposeChallenger_onlyOwner() public {
        vm.prank(rando);
        vm.expectRevert(SlashingOracle.NotOwner.selector);
        oracle.proposeChallenger(rando, true);
    }

    function test_proposeChallenger_works() public {
        vm.prank(deployer);
        oracle.proposeChallenger(rando, true);
        vm.warp(block.timestamp + oracle.CHALLENGER_TIMELOCK() + 1);
        vm.prank(deployer);
        oracle.executeChallenger(1); // proposalId 1 (0 was setUp)
        assertTrue(oracle.challengers(rando));
    }

    function test_challenger_timelock_enforced() public {
        vm.prank(deployer);
        oracle.proposeChallenger(rando, true);
        vm.prank(deployer);
        vm.expectRevert("SlashingOracle: timelock active");
        oracle.executeChallenger(1);
    }

    function test_emergencyRevokeChallenger() public {
        vm.prank(deployer);
        oracle.emergencyRevokeChallenger(challAddr);
        assertFalse(oracle.challengers(challAddr));
    }

    // ════════════════════════════════════════════════════════════
    //  Edge case: unregistered node
    // ════════════════════════════════════════════════════════════

    function test_proposeSlash_unregisteredNode_succeeds() public {
        // Attestation verification doesn't check the registry, so proposing
        // a slash on a non-existent node succeeds.
        bytes32 unknownNode = UNKNOWN_NODE;
        bytes memory evidence = _buildAttestation(unknownNode, block.timestamp, keccak256("desc"));

        vm.prank(challAddr);
        oracle.proposeSlash(unknownNode, uint8(ISlashingOracle.SlashReason.ProvableLogging), evidence);

        (bytes32 nid,,,, bool executed) = oracle.proposals(0);
        assertEq(nid, unknownNode);
        assertFalse(executed);
    }

    function test_executeSlash_unregisteredNode_reverts() public {
        // Proposal succeeds, but execution reverts at registry.slash because
        // the node has owner == address(0).
        bytes32 unknownNode = UNKNOWN_NODE;
        bytes memory evidence = _buildAttestation(unknownNode, block.timestamp, keccak256("desc"));

        vm.prank(challAddr);
        oracle.proposeSlash(unknownNode, uint8(ISlashingOracle.SlashReason.ProvableLogging), evidence);

        vm.warp(block.timestamp + oracle.GRACE_PERIOD() + 1);
        vm.expectRevert("NodeRegistry: node not found");
        oracle.executeSlash(0);
    }

    // ════════════════════════════════════════════════════════════
    //  Treasury claim integration (Fix 1)
    // ════════════════════════════════════════════════════════════

    function test_treasury_claimFromOracle() public {
        // Slash the node → treasury gets credited in SlashingOracle.
        bytes memory evidence = _buildAttestation(NODE_ID, block.timestamp, keccak256("claim-test"));
        _proposeAndExecute(NODE_ID, uint8(ISlashingOracle.SlashReason.ProvableLogging), evidence);

        uint256 treasuryPending = oracle.pendingWithdrawals(address(treasury));
        assertGt(treasuryPending, 0);

        // Treasury claims via claimFromOracle.
        uint256 balBefore = address(treasury).balance;
        vm.prank(deployer); // deployer is treasury owner
        treasury.claimFromOracle(address(oracle));
        assertEq(address(treasury).balance - balBefore, treasuryPending);
        assertEq(oracle.pendingWithdrawals(address(treasury)), 0);
    }

    // ════════════════════════════════════════════════════════════
    //  Liveness ban threshold (Fix 3)
    // ════════════════════════════════════════════════════════════

    function test_liveness_threshold_deactivates_node() public {
        uint256 threshold = oracle.LIVENESS_BAN_THRESHOLD();

        // Execute threshold liveness slashes, heartbeating between each
        // to keep the node fresh (time warps for grace periods would
        // otherwise make the heartbeat stale).
        for (uint256 i; i < threshold; ++i) {
            vm.prank(nodeAddr);
            registry.heartbeat(NODE_ID);

            bytes memory evidence = abi.encode(uint256(i + 1000));
            uint256 pid = oracle.nextProposalId();

            vm.prank(challAddr);
            oracle.proposeSlash(NODE_ID, uint8(ISlashingOracle.SlashReason.ChallengeFailure), evidence);
            vm.warp(block.timestamp + oracle.GRACE_PERIOD() + 1);
            oracle.executeSlash(pid);
        }

        // Node should be deactivated (not permanently banned).
        INodeRegistry.NodeInfo memory info = registry.getNode(NODE_ID);
        assertFalse(info.isActive);
        assertFalse(registry.permanentBan(NODE_ID));

        // Liveness count should be reset.
        assertEq(oracle.livenessFailureCount(NODE_ID), 0);
    }

    function test_liveness_below_threshold_stays_active() public {
        uint256 threshold = oracle.LIVENESS_BAN_THRESHOLD();

        // Execute threshold - 1 liveness slashes.
        for (uint256 i; i < threshold - 1; ++i) {
            vm.prank(nodeAddr);
            registry.heartbeat(NODE_ID);

            bytes memory evidence = abi.encode(uint256(i + 2000));
            uint256 pid = oracle.nextProposalId();

            vm.prank(challAddr);
            oracle.proposeSlash(NODE_ID, uint8(ISlashingOracle.SlashReason.ChallengeFailure), evidence);
            vm.warp(block.timestamp + oracle.GRACE_PERIOD() + 1);
            oracle.executeSlash(pid);
        }

        // Heartbeat to stay fresh after final warp.
        vm.prank(nodeAddr);
        registry.heartbeat(NODE_ID);

        // Node should still be active.
        assertTrue(registry.isNodeActive(NODE_ID));
        assertEq(oracle.livenessFailureCount(NODE_ID), threshold - 1);
    }
}
