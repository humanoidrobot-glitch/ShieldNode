// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {NodeRegistry}       from "../../src/NodeRegistry.sol";
import {SessionSettlement}  from "../../src/SessionSettlement.sol";
import {SlashingOracle}     from "../../src/SlashingOracle.sol";
import {ISlashingOracle}    from "../../src/interfaces/ISlashingOracle.sol";
import {Treasury}           from "../../src/Treasury.sol";
import {TestKeys}           from "../helpers/TestKeys.sol";

/// @title SlashingOracle Handler
/// @notice Drives random propose/execute sequences for invariant testing.
contract SlashHandler is Test {
    SlashingOracle public oracle;
    NodeRegistry   public registry;

    uint256 internal challPk = 0xC0DE;
    address public challAddr;

    bytes32 public nodeId;
    address public nodeOp;

    bytes32 public constant ATTESTATION_TYPEHASH = keccak256(
        "SlashAttestation(bytes32 nodeId,uint256 timestamp,bytes32 descriptionHash)"
    );

    /// @dev Ghost variable: tracks our own count of unexecuted proposals per node.
    uint256 public ghostPendingCount;

    /// @dev Track which proposals we've created.
    uint256 public proposalCount;

    constructor(
        SlashingOracle _oracle,
        NodeRegistry _registry,
        bytes32 _nodeId,
        address _nodeOp
    ) {
        oracle   = _oracle;
        registry = _registry;
        nodeId   = _nodeId;
        nodeOp   = _nodeOp;
        challAddr = vm.addr(challPk);
    }

    function _signAttestation(uint256 ts, bytes32 descHash) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(ATTESTATION_TYPEHASH, nodeId, ts, descHash)
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", oracle.ATTESTATION_DOMAIN_SEPARATOR(), structHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(challPk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @notice Propose a slash with unique evidence.
    function proposeSlash(uint256 seed) external {
        // Only propose if node is still registered.
        if (registry.getNode(nodeId).owner == address(0)) return;

        bytes32 descHash = keccak256(abi.encode("desc", seed, proposalCount));
        uint256 ts = block.timestamp;
        bytes memory evidence = abi.encode(nodeId, ts, descHash, _signAttestation(ts, descHash));

        vm.prank(challAddr);
        try oracle.proposeSlash(nodeId, uint8(ISlashingOracle.SlashReason.ProvableLogging), evidence) {
            ghostPendingCount++;
            proposalCount++;
        } catch {}
    }

    /// @notice Execute a slash after grace period.
    function executeSlash(uint256 proposalSeed) external {
        if (proposalCount == 0) return;
        uint256 proposalId = proposalSeed % proposalCount;

        vm.warp(block.timestamp + oracle.GRACE_PERIOD() + 1);

        try oracle.executeSlash(proposalId) {
            if (ghostPendingCount > 0) ghostPendingCount--;
        } catch {}
    }
}

/// @title SlashingOracle Invariant Test
/// @notice Verifies: pendingSlashCount[nodeId] matches ghost variable.
contract SlashingOracleInvariantTest is Test {
    NodeRegistry      public registry;
    SessionSettlement public settlement;
    SlashingOracle    public oracle;
    Treasury          public treasury;
    SlashHandler      public handler;

    function setUp() public {
        address deployer = makeAddr("deployer");
        uint256 nodeOpPk = 0xDEAD1;
        address nodeOp   = vm.addr(nodeOpPk);
        bytes32 pubKey   = keccak256("pk");
        bytes32 nodeId   = keccak256(abi.encode(nodeOp, pubKey));

        vm.deal(nodeOp, 10 ether);

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
        require(address(oracle) == predictedOracle, "oracle mismatch");

        handler = new SlashHandler(oracle, registry, nodeId, nodeOp);

        oracle.proposeChallenger(handler.challAddr(), true);
        vm.warp(block.timestamp + oracle.CHALLENGER_TIMELOCK() + 1);
        oracle.executeChallenger(0);

        vm.stopPrank();

        vm.prank(nodeOp);
        registry.register{value: 1 ether}(nodeId, pubKey, "10.0.0.1:51820", TestKeys.operator_key());

        targetContract(address(handler));
    }

    /// @notice pendingSlashCount matches our ghost variable.
    function invariant_pendingSlashCount_consistent() public view {
        assertEq(
            oracle.pendingSlashCount(handler.nodeId()),
            handler.ghostPendingCount(),
            "pendingSlashCount inconsistent with ghost"
        );
    }

    /// @notice Oracle balance >= total owed in pendingWithdrawals.
    function invariant_oracle_solvency() public view {
        uint256 owed = oracle.pendingWithdrawals(handler.challAddr())
                     + oracle.pendingWithdrawals(address(treasury));
        assertLe(owed, address(oracle).balance, "oracle insolvent");
    }
}
