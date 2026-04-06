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
///         1. Treasury               (nonce N)
///         2. NodeRegistry           (nonce N+1, needs predicted oracle at N+3)
///         3. SessionSettlement      (nonce N+2, needs registry)
///         4. SlashingOracle         (nonce N+3, needs registry + treasury + settlement)
contract Deploy is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerKey);

        address deployer = vm.addr(deployerKey);
        uint64 baseNonce = vm.getNonce(deployer);

        // Predict the SlashingOracle address (deployed at nonce baseNonce + 3).
        address predictedOracle = vm.computeCreateAddress(deployer, baseNonce + 3);

        // 1. Treasury
        Treasury treasury = new Treasury(deployer);
        console.log("Treasury deployed at:", address(treasury));

        // 2. NodeRegistry (with predicted oracle address)
        NodeRegistry registry = new NodeRegistry(predictedOracle);
        console.log("NodeRegistry deployed at:", address(registry));

        // 3. SessionSettlement
        SessionSettlement settlement = new SessionSettlement(address(registry), deployer);
        console.log("SessionSettlement deployed at:", address(settlement));

        // 4. SlashingOracle
        SlashingOracle oracle = new SlashingOracle(
            address(registry),
            address(treasury),
            address(settlement),
            deployer
        );
        console.log("SlashingOracle deployed at:", address(oracle));
        require(address(oracle) == predictedOracle, "Deploy: oracle address mismatch");

        vm.stopBroadcast();
    }
}
