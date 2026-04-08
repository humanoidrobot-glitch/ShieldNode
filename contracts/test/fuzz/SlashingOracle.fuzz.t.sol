// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {NodeRegistry}       from "../../src/NodeRegistry.sol";
import {SessionSettlement}  from "../../src/SessionSettlement.sol";
import {SlashingOracle}     from "../../src/SlashingOracle.sol";
import {ISlashingOracle}    from "../../src/interfaces/ISlashingOracle.sol";
import {INodeRegistry}      from "../../src/interfaces/INodeRegistry.sol";
import {Treasury}           from "../../src/Treasury.sol";

/// @title SlashingOracle fuzz tests
/// @notice Fuzz progressive slashing: amount bounded by stake, correct percentage per tier.
contract SlashingOracleFuzzTest is Test {
    NodeRegistry      public registry;
    SessionSettlement public settlement;
    SlashingOracle    public oracle;
    Treasury          public treasury;

    address public deployer   = makeAddr("deployer");
    address public challAddr;
    uint256 internal challPk  = 0xC0DE;

    bytes32 public constant ATTESTATION_TYPEHASH = keccak256(
        "SlashAttestation(bytes32 nodeId,uint256 timestamp,bytes32 descriptionHash)"
    );

    bytes32 internal attestationDomainSep;

    function setUp() public {
        challAddr = vm.addr(challPk);

        vm.startPrank(deployer);
        treasury = new Treasury(deployer);

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

        oracle.proposeChallenger(challAddr, true);
        vm.warp(block.timestamp + oracle.CHALLENGER_TIMELOCK() + 1);
        oracle.executeChallenger(0);

        vm.stopPrank();

        vm.deal(challAddr, 10 ether);
        attestationDomainSep = oracle.ATTESTATION_DOMAIN_SEPARATOR();
    }

    function _signAttestation(
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
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(challPk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _proposeAndExecute(bytes32 nodeId, bytes memory evidence) internal {
        uint256 proposalId = oracle.nextProposalId();
        vm.prank(challAddr);
        oracle.proposeSlash(nodeId, uint8(ISlashingOracle.SlashReason.ProvableLogging), evidence);
        vm.warp(block.timestamp + oracle.GRACE_PERIOD() + 1);
        oracle.executeSlash(proposalId);
    }

    /// @notice Slash amount is always bounded by the node's stake.
    function testFuzz_slash_bounded(uint256 stake) public {
        stake = bound(stake, 0.1 ether, 100 ether);

        address nodeOp = makeAddr(string(abi.encode("op", stake)));
        bytes32 pubKey = keccak256("pk");
        bytes32 nodeId = keccak256(abi.encode(nodeOp, pubKey));
        vm.deal(nodeOp, stake + 1 ether);

        vm.prank(nodeOp);
        registry.register{value: stake}(nodeId, pubKey, "10.0.0.1:51820");

        INodeRegistry.NodeInfo memory before_ = registry.getNode(nodeId);

        bytes memory evidence = abi.encode(nodeId, block.timestamp, keccak256("desc-1"), _signAttestation(nodeId, block.timestamp, keccak256("desc-1")));

        _proposeAndExecute(nodeId, evidence);

        INodeRegistry.NodeInfo memory after_ = registry.getNode(nodeId);
        uint256 slashed = before_.stake - after_.stake;

        // Slash must not exceed stake.
        assertLe(slashed, before_.stake, "slash exceeded stake");

        // First slash = 10%.
        uint256 expected = (before_.stake * 10) / 100;
        assertEq(slashed, expected, "first slash not 10%");
    }

    /// @notice Progressive slashing through all three tiers.
    function testFuzz_progressive_slashing(uint256 stake) public {
        stake = bound(stake, 0.1 ether, 50 ether);

        address nodeOp = makeAddr(string(abi.encode("prog-op", stake)));
        bytes32 pubKey = keccak256("pk");
        bytes32 nodeId = keccak256(abi.encode(nodeOp, pubKey));
        vm.deal(nodeOp, stake + 1 ether);

        vm.prank(nodeOp);
        registry.register{value: stake}(nodeId, pubKey, "10.0.0.2:51820");

        // First slash: 10%.
        uint256 stakeBefore = registry.getNode(nodeId).stake;
        bytes memory ev1 = abi.encode(nodeId, block.timestamp, keccak256("slash-1"), _signAttestation(nodeId, block.timestamp, keccak256("slash-1")));
        _proposeAndExecute(nodeId, ev1);
        uint256 stakeAfter1 = registry.getNode(nodeId).stake;
        assertEq(stakeBefore - stakeAfter1, (stakeBefore * 10) / 100, "tier 1 wrong");

        // Second slash: 25%.
        vm.warp(block.timestamp + 1);
        bytes memory ev2 = abi.encode(nodeId, block.timestamp, keccak256("slash-2"), _signAttestation(nodeId, block.timestamp, keccak256("slash-2")));
        _proposeAndExecute(nodeId, ev2);
        uint256 stakeAfter2 = registry.getNode(nodeId).stake;
        assertEq(stakeAfter1 - stakeAfter2, (stakeAfter1 * 25) / 100, "tier 2 wrong");

        // Third slash: 100% + ban.
        vm.warp(block.timestamp + 1);
        bytes memory ev3 = abi.encode(nodeId, block.timestamp, keccak256("slash-3"), _signAttestation(nodeId, block.timestamp, keccak256("slash-3")));
        _proposeAndExecute(nodeId, ev3);
        assertEq(registry.getNode(nodeId).stake, 0, "tier 3: stake not zero");
        assertFalse(registry.isNodeActive(nodeId), "tier 3: not banned");
    }
}
