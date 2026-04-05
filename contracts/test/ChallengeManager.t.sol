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
    address public anyone = makeAddr("anyone");

    uint256 constant NODE_KEY = 0xA101;
    address public nodeOp;
    bytes32 public nodeId = keccak256("test-node");

    uint256 constant BOND = 0.01 ether;

    function setUp() public {
        vm.warp(1_700_000_000);

        nodeOp = vm.addr(NODE_KEY);
        vm.deal(nodeOp, 10 ether);
        vm.deal(challenger, 10 ether);
        vm.deal(anyone, 10 ether);

        vm.startPrank(deployer);
        treasury = new Treasury();
        registry = new NodeRegistry(deployer);
        settlement = new SessionSettlement(address(registry));
        oracle = new SlashingOracle(
            address(registry),
            address(treasury),
            address(settlement)
        );
        vm.stopPrank();

        registry = new NodeRegistry(address(oracle));
        settlement = new SessionSettlement(address(registry));

        vm.prank(deployer);
        oracle = new SlashingOracle(
            address(registry),
            address(treasury),
            address(settlement)
        );

        cm = new ChallengeManager(address(registry), payable(address(oracle)));

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

    // ── issue challenge (bonded) ─────────────────────────────────

    function test_issue_challenge_with_bond() public {
        vm.prank(challenger);
        uint256 id = cm.issueChallenge{value: BOND}(
            nodeId,
            ChallengeManager.ChallengeType.LivenessCheck,
            bytes32(0)
        );

        ChallengeManager.Challenge memory c = cm.getChallenge(id);
        assertEq(c.nodeId, nodeId);
        assertEq(c.challenger, challenger);
        assertEq(c.bond, BOND);
        assertTrue(c.status == ChallengeManager.ChallengeStatus.Active);
        assertEq(c.deadline, block.timestamp + cm.RESPONSE_DEADLINE());
    }

    function test_issue_challenge_anyone_can_challenge() public {
        // No trusted challenger set needed — anyone with a bond can challenge.
        vm.prank(anyone);
        uint256 id = cm.issueChallenge{value: BOND}(
            nodeId,
            ChallengeManager.ChallengeType.BandwidthVerification,
            bytes32(0)
        );
        assertEq(cm.nextChallengeId(), 1);

        ChallengeManager.Challenge memory c = cm.getChallenge(id);
        assertEq(c.challenger, anyone);
    }

    function test_issue_challenge_overpay_bond() public {
        // Overpaying the bond is allowed — full amount stored.
        vm.prank(challenger);
        uint256 id = cm.issueChallenge{value: 0.05 ether}(
            nodeId,
            ChallengeManager.ChallengeType.LivenessCheck,
            bytes32(0)
        );

        ChallengeManager.Challenge memory c = cm.getChallenge(id);
        assertEq(c.bond, 0.05 ether);
    }

    function test_issue_challenge_insufficient_bond() public {
        vm.prank(challenger);
        vm.expectRevert(ChallengeManager.InsufficientBond.selector);
        cm.issueChallenge{value: 0.001 ether}(
            nodeId,
            ChallengeManager.ChallengeType.LivenessCheck,
            bytes32(0)
        );
    }

    function test_issue_challenge_zero_bond() public {
        vm.prank(challenger);
        vm.expectRevert(ChallengeManager.InsufficientBond.selector);
        cm.issueChallenge(nodeId, ChallengeManager.ChallengeType.LivenessCheck, bytes32(0));
    }

    function test_issue_challenge_inactive_node() public {
        vm.prank(nodeOp);
        registry.deregister(nodeId);

        vm.prank(challenger);
        vm.expectRevert(ChallengeManager.NodeNotActive.selector);
        cm.issueChallenge{value: BOND}(nodeId, ChallengeManager.ChallengeType.LivenessCheck, bytes32(0));
    }

    function test_challenge_cooldown() public {
        vm.prank(challenger);
        cm.issueChallenge{value: BOND}(nodeId, ChallengeManager.ChallengeType.LivenessCheck, bytes32(0));

        vm.prank(challenger);
        vm.expectRevert(ChallengeManager.CooldownNotElapsed.selector);
        cm.issueChallenge{value: BOND}(nodeId, ChallengeManager.ChallengeType.LivenessCheck, bytes32(0));
    }

    function test_challenge_cooldown_elapsed() public {
        vm.prank(challenger);
        cm.issueChallenge{value: BOND}(nodeId, ChallengeManager.ChallengeType.LivenessCheck, bytes32(0));

        vm.warp(block.timestamp + cm.CHALLENGE_COOLDOWN() + 1);

        vm.prank(challenger);
        cm.issueChallenge{value: BOND}(nodeId, ChallengeManager.ChallengeType.BandwidthVerification, bytes32(0));
        assertEq(cm.nextChallengeId(), 2);
    }

    function test_different_challengers_no_cooldown() public {
        // Different challengers can challenge the same node independently.
        vm.prank(challenger);
        cm.issueChallenge{value: BOND}(nodeId, ChallengeManager.ChallengeType.LivenessCheck, bytes32(0));

        vm.prank(anyone);
        cm.issueChallenge{value: BOND}(nodeId, ChallengeManager.ChallengeType.LivenessCheck, bytes32(0));

        assertEq(cm.nextChallengeId(), 2);
    }

    // ── respond to challenge (returns bond) ──────────────────────

    function test_respond_returns_bond() public {
        vm.prank(challenger);
        uint256 id = cm.issueChallenge{value: BOND}(
            nodeId,
            ChallengeManager.ChallengeType.LivenessCheck,
            bytes32(0)
        );

        uint256 challengerBalBefore = challenger.balance;

        bytes32 responseHash = keccak256("I am alive");
        bytes memory sig = _signResponse(NODE_KEY, id, nodeId, responseHash);

        vm.prank(nodeOp);
        cm.respondToChallenge(id, responseHash, sig);

        ChallengeManager.Challenge memory c = cm.getChallenge(id);
        assertTrue(c.status == ChallengeManager.ChallengeStatus.Responded);
        assertEq(c.bond, 0); // bond cleared

        // Challenger received bond back.
        assertEq(challenger.balance, challengerBalBefore + BOND);
    }

    function test_respond_wrong_signer() public {
        vm.prank(challenger);
        uint256 id = cm.issueChallenge{value: BOND}(
            nodeId,
            ChallengeManager.ChallengeType.LivenessCheck,
            bytes32(0)
        );

        bytes memory sig = _signResponse(0xBAD, id, nodeId, keccak256("response"));

        vm.prank(nodeOp);
        vm.expectRevert(ChallengeManager.InvalidResponse.selector);
        cm.respondToChallenge(id, keccak256("response"), sig);
    }

    function test_respond_after_deadline() public {
        vm.prank(challenger);
        uint256 id = cm.issueChallenge{value: BOND}(
            nodeId,
            ChallengeManager.ChallengeType.LivenessCheck,
            bytes32(0)
        );

        vm.warp(block.timestamp + cm.RESPONSE_DEADLINE() + 1);

        bytes32 responseHash = keccak256("too late");
        bytes memory sig = _signResponse(NODE_KEY, id, nodeId, responseHash);

        vm.prank(nodeOp);
        vm.expectRevert(ChallengeManager.ChallengeNotActive.selector);
        cm.respondToChallenge(id, responseHash, sig);
    }

    // ── expire challenge (returns bond to challenger) ────────────

    function test_expire_returns_bond() public {
        vm.prank(challenger);
        uint256 id = cm.issueChallenge{value: BOND}(
            nodeId,
            ChallengeManager.ChallengeType.LivenessCheck,
            bytes32(0)
        );

        uint256 challengerBalBefore = challenger.balance;
        vm.warp(block.timestamp + cm.RESPONSE_DEADLINE() + 1);

        cm.expireChallenge(id);

        ChallengeManager.Challenge memory c = cm.getChallenge(id);
        assertTrue(c.status == ChallengeManager.ChallengeStatus.Expired);
        assertEq(c.bond, 0);

        // Challenger gets bond back.
        assertEq(challenger.balance, challengerBalBefore + BOND);
    }

    function test_expire_too_early() public {
        vm.prank(challenger);
        uint256 id = cm.issueChallenge{value: BOND}(
            nodeId,
            ChallengeManager.ChallengeType.LivenessCheck,
            bytes32(0)
        );

        vm.expectRevert(ChallengeManager.DeadlineNotPassed.selector);
        cm.expireChallenge(id);
    }

    function test_expire_already_responded() public {
        vm.prank(challenger);
        uint256 id = cm.issueChallenge{value: BOND}(
            nodeId,
            ChallengeManager.ChallengeType.LivenessCheck,
            bytes32(0)
        );

        bytes32 responseHash = keccak256("alive");
        bytes memory sig = _signResponse(NODE_KEY, id, nodeId, responseHash);
        vm.prank(nodeOp);
        cm.respondToChallenge(id, responseHash, sig);

        vm.warp(block.timestamp + cm.RESPONSE_DEADLINE() + 1);
        vm.expectRevert(ChallengeManager.ChallengeNotActive.selector);
        cm.expireChallenge(id);
    }

    // ── views ───────────────────────────────────────────────────

    function test_isExpired() public {
        vm.prank(challenger);
        uint256 id = cm.issueChallenge{value: BOND}(
            nodeId,
            ChallengeManager.ChallengeType.LivenessCheck,
            bytes32(0)
        );

        assertFalse(cm.isExpired(id));

        vm.warp(block.timestamp + cm.RESPONSE_DEADLINE() + 1);
        assertTrue(cm.isExpired(id));
    }

    function test_canChallenge() public {
        assertTrue(cm.canChallenge(nodeId, challenger));

        vm.prank(challenger);
        cm.issueChallenge{value: BOND}(nodeId, ChallengeManager.ChallengeType.LivenessCheck, bytes32(0));

        // Same challenger: blocked by cooldown.
        assertFalse(cm.canChallenge(nodeId, challenger));

        // Different challenger: allowed.
        assertTrue(cm.canChallenge(nodeId, anyone));

        // After cooldown: allowed again.
        vm.warp(block.timestamp + cm.CHALLENGE_COOLDOWN() + 1);
        assertTrue(cm.canChallenge(nodeId, challenger));
    }
}
