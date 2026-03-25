// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {NodeRegistry}       from "../src/NodeRegistry.sol";
import {SessionSettlement}  from "../src/SessionSettlement.sol";
import {SlashingOracle}     from "../src/SlashingOracle.sol";
import {ChallengeManager}   from "../src/ChallengeManager.sol";
import {Treasury}           from "../src/Treasury.sol";
import {EIP712Utils}        from "../src/lib/EIP712Utils.sol";
import {INodeRegistry}      from "../src/interfaces/INodeRegistry.sol";

contract ChallengeManagerTest is Test {
    NodeRegistry      public registry;
    SessionSettlement public settlement;
    SlashingOracle    public oracle;
    Treasury          public treasury;
    ChallengeManager  public cm;

    address public deployer = makeAddr("deployer");
    address public challenger = makeAddr("challenger");

    uint256 constant NODE_KEY = 0xA101;
    address public nodeOp;
    bytes32 public nodeId = keccak256("test-node");

    function setUp() public {
        // Start at a reasonable timestamp (Foundry default is 1).
        vm.warp(1_700_000_000);

        nodeOp = vm.addr(NODE_KEY);
        vm.deal(nodeOp, 10 ether);

        // Deploy with a temporary oracle address, then redeploy properly.
        // SlashingOracle checks for zero addresses, so use deployer as placeholder.
        vm.startPrank(deployer);
        treasury = new Treasury();

        // Deploy registry with deployer as temporary oracle.
        registry = new NodeRegistry(deployer);
        settlement = new SessionSettlement(address(registry));

        // Deploy real oracle.
        oracle = new SlashingOracle(
            address(registry),
            address(treasury),
            address(settlement)
        );
        vm.stopPrank();

        // Re-deploy registry with real oracle (need fresh for the slashing auth).
        registry = new NodeRegistry(address(oracle));
        settlement = new SessionSettlement(address(registry));

        // Re-deploy oracle with correct registry.
        vm.prank(deployer);
        oracle = new SlashingOracle(
            address(registry),
            address(treasury),
            address(settlement)
        );

        cm = new ChallengeManager(address(registry), payable(address(oracle)));

        // Authorize the challenger.
        vm.prank(deployer);
        oracle.setChallenger(challenger, true);

        // Register a node.
        vm.prank(nodeOp);
        registry.register{value: 0.1 ether}(
            nodeId,
            keccak256("pubkey"),
            "10.0.0.1:51820"
        );
    }

    // ── helpers ──────────────────────────────────────────────────

    function _signResponse(
        uint256 pk,
        uint256 challengeId,
        bytes32 _nodeId,
        bytes32 responseHash
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(cm.RESPONSE_TYPEHASH(), challengeId, _nodeId, responseHash)
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", cm.DOMAIN_SEPARATOR(), structHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    // ── issue challenge ─────────────────────────────────────────

    function test_issue_challenge() public {
        vm.prank(challenger);
        uint256 id = cm.issueChallenge(
            nodeId,
            ChallengeManager.ChallengeType.LivenessCheck,
            bytes32(0)
        );

        ChallengeManager.Challenge memory c = cm.getChallenge(id);
        assertEq(c.nodeId, nodeId);
        assertEq(c.challenger, challenger);
        assertTrue(c.status == ChallengeManager.ChallengeStatus.Active);
        assertEq(c.deadline, block.timestamp + cm.RESPONSE_DEADLINE());
    }

    function test_issue_challenge_not_challenger() public {
        vm.prank(makeAddr("random"));
        vm.expectRevert(ChallengeManager.NotChallenger.selector);
        cm.issueChallenge(nodeId, ChallengeManager.ChallengeType.LivenessCheck, bytes32(0));
    }

    function test_issue_challenge_inactive_node() public {
        vm.prank(nodeOp);
        registry.deregister(nodeId);

        vm.prank(challenger);
        vm.expectRevert(ChallengeManager.NodeNotActive.selector);
        cm.issueChallenge(nodeId, ChallengeManager.ChallengeType.LivenessCheck, bytes32(0));
    }

    function test_challenge_cooldown() public {
        vm.prank(challenger);
        cm.issueChallenge(nodeId, ChallengeManager.ChallengeType.LivenessCheck, bytes32(0));

        // Second challenge before cooldown → revert.
        vm.prank(challenger);
        vm.expectRevert(ChallengeManager.CooldownNotElapsed.selector);
        cm.issueChallenge(nodeId, ChallengeManager.ChallengeType.LivenessCheck, bytes32(0));
    }

    function test_challenge_cooldown_elapsed() public {
        vm.prank(challenger);
        cm.issueChallenge(nodeId, ChallengeManager.ChallengeType.LivenessCheck, bytes32(0));

        // Warp past cooldown.
        vm.warp(block.timestamp + cm.CHALLENGE_COOLDOWN() + 1);

        // Second challenge should succeed.
        vm.prank(challenger);
        cm.issueChallenge(nodeId, ChallengeManager.ChallengeType.BandwidthVerification, bytes32(0));
        assertEq(cm.nextChallengeId(), 2);
    }

    // ── respond to challenge ────────────────────────────────────

    function test_respond_to_challenge() public {
        vm.prank(challenger);
        uint256 id = cm.issueChallenge(
            nodeId,
            ChallengeManager.ChallengeType.LivenessCheck,
            bytes32(0)
        );

        bytes32 responseHash = keccak256("I am alive");
        bytes memory sig = _signResponse(NODE_KEY, id, nodeId, responseHash);

        vm.prank(nodeOp);
        cm.respondToChallenge(id, responseHash, sig);

        ChallengeManager.Challenge memory c = cm.getChallenge(id);
        assertTrue(c.status == ChallengeManager.ChallengeStatus.Responded);
    }

    function test_respond_wrong_signer() public {
        vm.prank(challenger);
        uint256 id = cm.issueChallenge(
            nodeId,
            ChallengeManager.ChallengeType.LivenessCheck,
            bytes32(0)
        );

        // Sign with wrong key.
        bytes memory sig = _signResponse(0xBAD, id, nodeId, keccak256("response"));

        vm.prank(nodeOp);
        vm.expectRevert(ChallengeManager.InvalidResponse.selector);
        cm.respondToChallenge(id, keccak256("response"), sig);
    }

    function test_respond_after_deadline() public {
        vm.prank(challenger);
        uint256 id = cm.issueChallenge(
            nodeId,
            ChallengeManager.ChallengeType.LivenessCheck,
            bytes32(0)
        );

        // Warp past deadline.
        vm.warp(block.timestamp + cm.RESPONSE_DEADLINE() + 1);

        bytes32 responseHash = keccak256("too late");
        bytes memory sig = _signResponse(NODE_KEY, id, nodeId, responseHash);

        vm.prank(nodeOp);
        vm.expectRevert(ChallengeManager.ChallengeNotActive.selector);
        cm.respondToChallenge(id, responseHash, sig);
    }

    // ── expire challenge ────────────────────────────────────────

    function test_expire_challenge() public {
        vm.prank(challenger);
        uint256 id = cm.issueChallenge(
            nodeId,
            ChallengeManager.ChallengeType.LivenessCheck,
            bytes32(0)
        );

        vm.warp(block.timestamp + cm.RESPONSE_DEADLINE() + 1);

        cm.expireChallenge(id);

        ChallengeManager.Challenge memory c = cm.getChallenge(id);
        assertTrue(c.status == ChallengeManager.ChallengeStatus.Expired);
    }

    function test_expire_too_early() public {
        vm.prank(challenger);
        uint256 id = cm.issueChallenge(
            nodeId,
            ChallengeManager.ChallengeType.LivenessCheck,
            bytes32(0)
        );

        vm.expectRevert(ChallengeManager.DeadlineNotPassed.selector);
        cm.expireChallenge(id);
    }

    function test_expire_already_responded() public {
        vm.prank(challenger);
        uint256 id = cm.issueChallenge(
            nodeId,
            ChallengeManager.ChallengeType.LivenessCheck,
            bytes32(0)
        );

        // Respond first.
        bytes32 responseHash = keccak256("alive");
        bytes memory sig = _signResponse(NODE_KEY, id, nodeId, responseHash);
        vm.prank(nodeOp);
        cm.respondToChallenge(id, responseHash, sig);

        // Try to expire → already responded.
        vm.warp(block.timestamp + cm.RESPONSE_DEADLINE() + 1);
        vm.expectRevert(ChallengeManager.ChallengeNotActive.selector);
        cm.expireChallenge(id);
    }

    // ── views ───────────────────────────────────────────────────

    function test_isExpired() public {
        vm.prank(challenger);
        uint256 id = cm.issueChallenge(
            nodeId,
            ChallengeManager.ChallengeType.LivenessCheck,
            bytes32(0)
        );

        assertFalse(cm.isExpired(id));

        vm.warp(block.timestamp + cm.RESPONSE_DEADLINE() + 1);
        assertTrue(cm.isExpired(id));
    }
}
