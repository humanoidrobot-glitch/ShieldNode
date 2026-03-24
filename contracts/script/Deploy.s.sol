// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {Treasury}           from "../src/Treasury.sol";
import {SlashingOracle}     from "../src/SlashingOracle.sol";
import {NodeRegistry}       from "../src/NodeRegistry.sol";
import {SessionSettlement}  from "../src/SessionSettlement.sol";

/// @title Deploy
/// @notice Foundry deployment script for the ShieldNode protocol.
///         Deploys contracts in dependency order:
///         1. Treasury
///         2. NodeRegistry (needs a temporary oracle address -- see note)
///         3. SlashingOracle (needs registry + treasury)
///         4. SessionSettlement (needs registry)
///
///         Because NodeRegistry requires the SlashingOracle address at
///         construction (immutable), but the oracle needs the registry address,
///         we use a two-step approach: deploy a placeholder, then re-deploy
///         NodeRegistry with the real oracle address.
contract Deploy is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerKey);

        // 1. Treasury
        Treasury treasury = new Treasury();
        console.log("Treasury deployed at:", address(treasury));

        // 2. Compute the future SlashingOracle address so we can pass it to
        //    NodeRegistry at construction time.  We know it will be the next
        //    contract deployed after NodeRegistry by this EOA.
        address deployer = vm.addr(deployerKey);
        uint64 deployerNonce = vm.getNonce(deployer);
        // NodeRegistry will be deployed at nonce `deployerNonce`.
        // SlashingOracle will be deployed at nonce `deployerNonce + 1`.
        address predictedOracle = vm.computeCreateAddress(deployer, deployerNonce + 1);

        // 3. NodeRegistry (with predicted oracle address)
        NodeRegistry registry = new NodeRegistry(predictedOracle);
        console.log("NodeRegistry deployed at:", address(registry));

        // 4. SlashingOracle
        SlashingOracle oracle = new SlashingOracle(address(registry), address(treasury));
        console.log("SlashingOracle deployed at:", address(oracle));
        require(address(oracle) == predictedOracle, "Deploy: oracle address mismatch");

        // 5. SessionSettlement
        SessionSettlement settlement = new SessionSettlement(address(registry));
        console.log("SessionSettlement deployed at:", address(settlement));

        vm.stopBroadcast();
    }
}
