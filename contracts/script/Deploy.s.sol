// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {Treasury}           from "../src/Treasury.sol";
import {SlashingOracle}     from "../src/SlashingOracle.sol";
import {NodeRegistry}       from "../src/NodeRegistry.sol";
import {SessionSettlement}  from "../src/SessionSettlement.sol";
import {ChallengeManager}   from "../src/ChallengeManager.sol";
import {CommitmentTree}     from "../src/CommitmentTree.sol";
import {EligibilityVerifier} from "../src/EligibilityVerifier.sol";

/// @title Deploy
/// @notice Foundry deployment script for the ShieldNode protocol.
///
///  Deployment order (nonce-sensitive):
///
///    N+0  Treasury          (standalone)
///    N+1  NodeRegistry      (needs predicted oracle at N+3)
///    N+2  SessionSettlement (needs registry)
///    N+3  SlashingOracle    (needs registry + treasury + settlement)
///    N+4  ChallengeManager  (needs registry + oracle)
///    N+5  CommitmentTree    (standalone, then init + transfer)
///
///  The circular dependency between NodeRegistry and SlashingOracle
///  is resolved via nonce-based address prediction. The SlashingOracle
///  address is computed before NodeRegistry is deployed, and verified
///  after SlashingOracle is deployed. If any intermediate transaction
///  disrupts the nonce sequence, the require() on line 73 will revert
///  the entire deployment.
///
///  After deployment, all owner roles belong to the deployer EOA.
///  The script proposes ownership transfer to a multisig address
///  (env MULTISIG). The multisig must call acceptOwnership() on each
///  contract to finalize the transfer (two-step pattern).
contract Deploy is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address multisig = vm.envOr("MULTISIG", address(0));

        vm.startBroadcast(deployerKey);

        address deployer = vm.addr(deployerKey);
        uint64 baseNonce = vm.getNonce(deployer);

        // ── Deploy core contracts ──────────────────────────────

        // Predict the SlashingOracle address (deployed at nonce baseNonce + 3).
        address predictedOracle = vm.computeCreateAddress(deployer, baseNonce + 3);

        // N+0: Treasury
        Treasury treasury = new Treasury(deployer);
        console.log("Treasury:", address(treasury));

        // N+1: NodeRegistry (with predicted oracle address)
        NodeRegistry registry = new NodeRegistry(predictedOracle);
        console.log("NodeRegistry:", address(registry));

        // N+2: SessionSettlement
        SessionSettlement settlement = new SessionSettlement(address(registry), deployer);
        console.log("SessionSettlement:", address(settlement));

        // N+3: SlashingOracle
        SlashingOracle oracle = new SlashingOracle(
            address(registry),
            address(treasury),
            address(settlement),
            deployer
        );
        console.log("SlashingOracle:", address(oracle));
        require(address(oracle) == predictedOracle, "Deploy: oracle address mismatch");

        // N+4: ChallengeManager
        ChallengeManager cm = new ChallengeManager(address(registry), payable(address(oracle)));
        console.log("ChallengeManager:", address(cm));

        // N+5: CommitmentTree
        CommitmentTree tree = new CommitmentTree();
        console.log("CommitmentTree:", address(tree));

        // ── Initialize CommitmentTree ──────────────────────────
        // Fill all 512 leaf slots with dummy commitments in one batch.
        // Uses ~18M gas — fits within the 30M mainnet block gas limit.
        bytes32 initSalt = keccak256(abi.encode("shieldnode-init", block.timestamp, deployer));
        tree.initialize(initSalt, 512);
        console.log("CommitmentTree initialized (512 dummies)");

        // ── Post-deployment assertions ─────────────────────────
        require(address(treasury) != address(0), "Deploy: treasury zero");
        require(address(registry) != address(0), "Deploy: registry zero");
        require(address(settlement) != address(0), "Deploy: settlement zero");
        require(address(oracle) != address(0), "Deploy: oracle zero");
        require(address(cm) != address(0), "Deploy: challenge manager zero");
        require(address(tree) != address(0), "Deploy: commitment tree zero");
        require(tree.initialized(), "Deploy: tree not initialized");

        // ── Ownership transfer to multisig ─────────────────────
        // Two-step: deployer proposes, multisig must accept later.
        if (multisig != address(0)) {
            oracle.transferOwnership(multisig);
            treasury.transferOwnership(multisig);
            tree.transferOwnership(multisig);
            console.log("Ownership transfer proposed to:", multisig);
            console.log("  Multisig must call acceptOwnership() on each contract.");
        } else {
            console.log("MULTISIG not set - ownership remains with deployer.");
            console.log("  Set MULTISIG env var to propose ownership transfer.");
        }

        vm.stopBroadcast();
    }
}
