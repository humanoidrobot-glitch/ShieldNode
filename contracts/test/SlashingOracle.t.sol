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
    address public operator    = makeAddr("operator");
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

    bytes32 constant NODE_ID    = keccak256("node-1");
    bytes32 constant PUB_KEY    = keccak256("pubkey-1");
    string  constant ENDPOINT   = "192.168.1.1:51820";

    // EIP-712 domain separator (computed to match SessionSettlement).
    bytes32 internal domainSep;

    bytes32 constant RECEIPT_TYPEHASH = keccak256(
        "BandwidthReceipt(uint256 sessionId,uint256 cumulativeBytes,uint256 timestamp)"
    );
    bytes32 constant ATTESTATION_TYPEHASH = keccak256(
        "SlashAttestation(bytes32 nodeId,uint256 timestamp,bytes32 descriptionHash)"
    );

    function setUp() public {
        clientAddr = vm.addr(clientPk);
        nodeAddr   = vm.addr(nodePk);
        challAddr  = vm.addr(challPk);

        vm.startPrank(deployer);

        // Deploy contracts in the same order as Deploy.s.sol.
        treasury = new Treasury();

        // Predict oracle address (deployed 2 contracts later).
        uint64 nonce = vm.getNonce(deployer);
        address predictedOracle = vm.computeCreateAddress(deployer, nonce + 2);

        registry   = new NodeRegistry(predictedOracle);
        settlement = new SessionSettlement(address(registry));
        oracle     = new SlashingOracle(
            address(registry),
            address(treasury),
            address(settlement)
        );
        require(address(oracle) == predictedOracle, "oracle address mismatch");

        // Authorise the challenger.
        oracle.setChallenger(challAddr, true);

        vm.stopPrank();

        // Fund actors.
        vm.deal(nodeAddr, 10 ether);
        vm.deal(clientAddr, 10 ether);
        vm.deal(challAddr, 10 ether);

        // Register a node as `nodeAddr` (using nodeAddr as the operator).
        vm.prank(nodeAddr);
        registry.register{value: 1 ether}(NODE_ID, PUB_KEY, ENDPOINT);

        // Compute the domain separator to match SessionSettlement.
        domainSep = keccak256(
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
            abi.encodePacked("\x19\x01", domainSep, structHash)
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

        return abi.encode(
            sessionId,
            bytes1_, ts1, cSig1, nSig1,
            bytes2_, ts2, cSig2, nSig2
        );
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
        bytes memory evidence = _buildFraudEvidence(42, 1000, 100, 2000, 200);

        vm.prank(challAddr);
        oracle.proposeSlash(NODE_ID, uint8(ISlashingOracle.SlashReason.BandwidthFraud), evidence);

        // Proposal should be stored.
        (bytes32 nid,,,, bool executed) = oracle.proposals(0);
        assertEq(nid, NODE_ID);
        assertFalse(executed);
    }

    function test_bandwidthFraud_sameBytes_reverts() public {
        // Two receipts with identical byte counts — not fraud.
        bytes memory evidence = _buildFraudEvidence(42, 1000, 100, 1000, 200);

        vm.prank(challAddr);
        vm.expectRevert(abi.encodeWithSelector(
            SlashingOracle.InvalidEvidence.selector, "byte counts match"
        ));
        oracle.proposeSlash(NODE_ID, uint8(ISlashingOracle.SlashReason.BandwidthFraud), evidence);
    }

    function test_bandwidthFraud_wrongNodeSigner_reverts() public {
        // Build evidence where node sigs come from a different key.
        uint256 wrongPk = 0xDEAD;
        bytes memory cSig1 = _signReceipt(clientPk, 42, 1000, 100);
        bytes memory nSig1 = _signReceipt(wrongPk, 42, 1000, 100);
        bytes memory cSig2 = _signReceipt(clientPk, 42, 2000, 200);
        bytes memory nSig2 = _signReceipt(wrongPk, 42, 2000, 200);

        bytes memory evidence = abi.encode(
            uint256(42),
            uint256(1000), uint256(100), cSig1, nSig1,
            uint256(2000), uint256(200), cSig2, nSig2
        );

        vm.prank(challAddr);
        vm.expectRevert(abi.encodeWithSelector(
            SlashingOracle.InvalidEvidence.selector, "node signer is not accused node owner"
        ));
        oracle.proposeSlash(NODE_ID, uint8(ISlashingOracle.SlashReason.BandwidthFraud), evidence);
    }

    function test_bandwidthFraud_differentClients_reverts() public {
        uint256 otherClientPk = 0xF00D;
        bytes memory cSig1 = _signReceipt(clientPk, 42, 1000, 100);
        bytes memory nSig1 = _signReceipt(nodePk, 42, 1000, 100);
        bytes memory cSig2 = _signReceipt(otherClientPk, 42, 2000, 200);
        bytes memory nSig2 = _signReceipt(nodePk, 42, 2000, 200);

        bytes memory evidence = abi.encode(
            uint256(42),
            uint256(1000), uint256(100), cSig1, nSig1,
            uint256(2000), uint256(200), cSig2, nSig2
        );

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

        uint256 challBefore = challAddr.balance;
        uint256 treasuryBefore = address(treasury).balance;

        bytes memory evidence = _buildAttestation(NODE_ID, block.timestamp, keccak256("first"));
        _proposeAndExecute(NODE_ID, uint8(ISlashingOracle.SlashReason.ProvableLogging), evidence);

        INodeRegistry.NodeInfo memory after_ = registry.getNode(NODE_ID);
        assertEq(after_.stake, before_.stake - expectedSlash);
        assertEq(after_.slashCount, 1);

        // 50/50 split.
        assertEq(challAddr.balance - challBefore, expectedSlash / 2);
        assertEq(address(treasury).balance - treasuryBefore, expectedSlash - expectedSlash / 2);
    }

    function test_secondSlash_25percent() public {
        // First slash.
        bytes memory ev1 = _buildAttestation(NODE_ID, block.timestamp, keccak256("first"));
        _proposeAndExecute(NODE_ID, uint8(ISlashingOracle.SlashReason.ProvableLogging), ev1);

        INodeRegistry.NodeInfo memory mid = registry.getNode(NODE_ID);
        uint256 expectedSlash = (mid.stake * 25) / 100; // 25%

        // Second slash.
        vm.warp(block.timestamp + 1); // new timestamp for attestation
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

        // Second slash (25%).
        vm.warp(block.timestamp + 1);
        bytes memory ev2 = _buildAttestation(NODE_ID, block.timestamp, keccak256("second"));
        _proposeAndExecute(NODE_ID, uint8(ISlashingOracle.SlashReason.SelectiveDenial), ev2);

        // Third slash (100% + ban) — use attestation to test all three paths.
        vm.warp(block.timestamp + 1);
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

    function test_setChallenger_onlyOwner() public {
        vm.prank(rando);
        vm.expectRevert(SlashingOracle.NotOwner.selector);
        oracle.setChallenger(rando, true);
    }

    function test_setChallenger_works() public {
        vm.prank(deployer);
        oracle.setChallenger(rando, true);
        assertTrue(oracle.challengers(rando));
    }
}
