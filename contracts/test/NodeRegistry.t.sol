// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {NodeRegistry}       from "../src/NodeRegistry.sol";
import {INodeRegistry}      from "../src/interfaces/INodeRegistry.sol";
import {SlashingOracle}     from "../src/SlashingOracle.sol";
import {SessionSettlement}  from "../src/SessionSettlement.sol";
import {Treasury}           from "../src/Treasury.sol";

contract NodeRegistryTest is Test {
    NodeRegistry public registry;
    SlashingOracle public oracle;

    address public deployer  = makeAddr("deployer");
    address public operator = makeAddr("operator");
    address public rando    = makeAddr("rando");

    bytes32 public   NODE_ID;
    bytes32 constant PUB_KEY    = keccak256("pubkey-1");
    string  constant ENDPOINT   = "192.168.1.1:51820";

    function setUp() public {
        NODE_ID = keccak256(abi.encode(operator, PUB_KEY));

        vm.startPrank(deployer);
        Treasury treasury = new Treasury(deployer);

        // Deploy oracle first with a dummy registry, then redeploy properly.
        // We need the oracle address for NodeRegistry, and NodeRegistry address for oracle.
        uint64 nonce = vm.getNonce(deployer);
        address predictedOracle = vm.computeCreateAddress(deployer, nonce + 2);

        registry = new NodeRegistry(predictedOracle);
        SessionSettlement settlement = new SessionSettlement(address(registry), deployer);
        oracle = new SlashingOracle(address(registry), address(treasury), address(settlement), deployer);
        vm.stopPrank();

        require(address(oracle) == predictedOracle, "oracle address prediction failed");

        vm.deal(operator, 10 ether);
        vm.deal(rando, 10 ether);
    }

    // ────────────────────── Registration ──────────────────────

    function test_register_node() public {
        vm.prank(operator);
        registry.register{value: 0.1 ether}(NODE_ID, PUB_KEY, ENDPOINT);

        INodeRegistry.NodeInfo memory info = registry.getNode(NODE_ID);
        assertEq(info.owner, operator);
        assertEq(info.publicKey, PUB_KEY);
        assertEq(keccak256(bytes(info.endpoint)), keccak256(bytes(ENDPOINT)));
        assertEq(info.stake, 0.1 ether);
        assertTrue(info.isActive);
        assertEq(info.slashCount, 0);
        assertEq(info.commitment, bytes32(0));
    }

    function test_register_insufficient_stake() public {
        vm.prank(operator);
        vm.expectRevert("NodeRegistry: insufficient stake");
        registry.register{value: 0.01 ether}(NODE_ID, PUB_KEY, ENDPOINT);
    }

    function test_register_duplicate() public {
        vm.startPrank(operator);
        registry.register{value: 0.1 ether}(NODE_ID, PUB_KEY, ENDPOINT);

        vm.expectRevert("NodeRegistry: already registered");
        registry.register{value: 0.1 ether}(NODE_ID, PUB_KEY, ENDPOINT);
        vm.stopPrank();
    }

    // ────────────────────── Heartbeat ──────────────────────

    function test_heartbeat() public {
        vm.prank(operator);
        registry.register{value: 0.1 ether}(NODE_ID, PUB_KEY, ENDPOINT);

        // Advance time
        vm.warp(block.timestamp + 1 hours);

        vm.prank(operator);
        registry.heartbeat(NODE_ID);

        INodeRegistry.NodeInfo memory info = registry.getNode(NODE_ID);
        assertEq(info.lastHeartbeat, block.timestamp);
    }

    function test_heartbeat_not_owner() public {
        vm.prank(operator);
        registry.register{value: 0.1 ether}(NODE_ID, PUB_KEY, ENDPOINT);

        vm.prank(rando);
        vm.expectRevert("NodeRegistry: not node owner");
        registry.heartbeat(NODE_ID);
    }

    // ────────────────────── Deregister & Withdraw ──────────────────────

    function test_deregister_and_withdraw() public {
        vm.prank(operator);
        registry.register{value: 0.5 ether}(NODE_ID, PUB_KEY, ENDPOINT);

        vm.prank(operator);
        registry.deregister(NODE_ID);

        INodeRegistry.NodeInfo memory info = registry.getNode(NODE_ID);
        assertFalse(info.isActive);

        // Warp past cooldown
        vm.warp(block.timestamp + 7 days + 1);

        uint256 balBefore = operator.balance;
        vm.prank(operator);
        registry.withdrawStake(NODE_ID);
        uint256 balAfter = operator.balance;

        assertEq(balAfter - balBefore, 0.5 ether);
    }

    function test_deregister_cooldown_not_passed() public {
        vm.prank(operator);
        registry.register{value: 0.5 ether}(NODE_ID, PUB_KEY, ENDPOINT);

        vm.prank(operator);
        registry.deregister(NODE_ID);

        // Try withdrawing immediately
        vm.prank(operator);
        vm.expectRevert("NodeRegistry: cooldown not passed");
        registry.withdrawStake(NODE_ID);
    }

    // ────────────────────── Active nodes pagination ──────────────────────

    function test_get_active_nodes_pagination() public {
        // Register 5 nodes
        bytes32[5] memory ids;
        for (uint256 i; i < 5; i++) {
            bytes32 pubKey = keccak256(abi.encodePacked("pub", i));
            ids[i] = keccak256(abi.encode(operator, pubKey));
            vm.prank(operator);
            registry.register{value: 0.1 ether}(
                ids[i],
                pubKey,
                "1.2.3.4:51820"
            );
        }

        // Page 1: offset=0, limit=3
        bytes32[] memory page1 = registry.getActiveNodes(0, 3);
        assertEq(page1.length, 3);
        assertEq(page1[0], ids[0]);
        assertEq(page1[1], ids[1]);
        assertEq(page1[2], ids[2]);

        // Page 2: offset=3, limit=3
        bytes32[] memory page2 = registry.getActiveNodes(3, 3);
        assertEq(page2.length, 2);
        assertEq(page2[0], ids[3]);
        assertEq(page2[1], ids[4]);

        // Offset beyond actives
        bytes32[] memory page3 = registry.getActiveNodes(10, 3);
        assertEq(page3.length, 0);
    }

    // ────────────────────── Slashing ──────────────────────

    function test_slash_from_oracle() public {
        vm.prank(operator);
        registry.register{value: 1 ether}(NODE_ID, PUB_KEY, ENDPOINT);

        uint256 oracleBalBefore = address(oracle).balance;

        vm.prank(address(oracle));
        registry.slash(NODE_ID, 0.1 ether, true);

        INodeRegistry.NodeInfo memory info = registry.getNode(NODE_ID);
        assertEq(info.stake, 0.9 ether);
        assertEq(info.slashCount, 1);

        // Oracle should have received the slashed funds.
        assertEq(address(oracle).balance - oracleBalBefore, 0.1 ether);
    }

    function test_slash_unauthorized() public {
        vm.prank(operator);
        registry.register{value: 1 ether}(NODE_ID, PUB_KEY, ENDPOINT);

        vm.prank(rando);
        vm.expectRevert("NodeRegistry: not oracle");
        registry.slash(NODE_ID, 0.1 ether, true);
    }

    // ────────────────────── Endpoint update ──────────────────────

    function test_update_endpoint() public {
        vm.prank(operator);
        registry.register{value: 0.1 ether}(NODE_ID, PUB_KEY, ENDPOINT);

        vm.prank(operator);
        registry.updateEndpoint(NODE_ID, "10.0.0.1:51820");

        INodeRegistry.NodeInfo memory info = registry.getNode(NODE_ID);
        assertEq(keccak256(bytes(info.endpoint)), keccak256(bytes("10.0.0.1:51820")));
    }

    // ────────────────────── isNodeActive freshness ──────────────────────

    function test_node_inactive_after_missed_heartbeats() public {
        vm.prank(operator);
        registry.register{value: 0.1 ether}(NODE_ID, PUB_KEY, ENDPOINT);

        assertTrue(registry.isNodeActive(NODE_ID));

        // Warp beyond MAX_MISSED_HEARTBEATS * HEARTBEAT_INTERVAL
        vm.warp(block.timestamp + 18 hours + 1);
        assertFalse(registry.isNodeActive(NODE_ID));
    }

    // ────────────────────── pricePerByte cap (Fix 4) ──────────────────────

    function test_updatePrice_within_cap() public {
        vm.prank(operator);
        registry.register{value: 0.1 ether}(NODE_ID, PUB_KEY, ENDPOINT);

        vm.prank(operator);
        registry.updatePricePerByte(NODE_ID, 1e12);

        INodeRegistry.NodeInfo memory info = registry.getNode(NODE_ID);
        assertEq(info.pricePerByte, 1e12);
    }

    function test_updatePrice_exceeds_cap_reverts() public {
        vm.prank(operator);
        registry.register{value: 0.1 ether}(NODE_ID, PUB_KEY, ENDPOINT);

        vm.prank(operator);
        vm.expectRevert("NodeRegistry: price too high");
        registry.updatePricePerByte(NODE_ID, 1e12 + 1);
    }
}
