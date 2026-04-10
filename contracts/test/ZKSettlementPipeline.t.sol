// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {NodeRegistry} from "../src/NodeRegistry.sol";
import {SessionSettlement} from "../src/SessionSettlement.sol";
import {SlashingOracle} from "../src/SlashingOracle.sol";
import {Treasury} from "../src/Treasury.sol";
import {ZKSettlement, IGroth16Verifier} from "../src/ZKSettlement.sol";
import {PoseidonT3} from "poseidon-solidity/PoseidonT3.sol";
import {TestKeys} from "./helpers/TestKeys.sol";

/// @dev Mock verifier that always returns true.
contract AlwaysVerifier is IGroth16Verifier {
    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[13] calldata
    ) external pure override returns (bool) {
        return true;
    }
}

/// @title ZK Settlement Pipeline Test
/// @notice End-to-end test: register nodes with secp256k1 keys, open session,
///         make ZK deposit, compute Poseidon commitments, settle with proof.
///         Uses a mock verifier (Groth16 proof is not generated on-chain).
contract ZKSettlementPipelineTest is Test {
    NodeRegistry      registry;
    SessionSettlement settlement;
    SlashingOracle    oracle;
    Treasury          treasury;
    ZKSettlement      zk;
    AlwaysVerifier    verifier;

    address deployer;

    uint256 constant ENTRY_KEY  = 0xA001;
    uint256 constant RELAY_KEY  = 0xA002;
    uint256 constant EXIT_KEY   = 0xA003;
    uint256 constant CLIENT_KEY = 0xB001;

    address entryOp;
    address relayOp;
    address exitOp;
    address client;

    bytes32 entryId;
    bytes32 relayId;
    bytes32 exitId;

    function setUp() public {
        deployer = makeAddr("deployer");
        entryOp  = vm.addr(ENTRY_KEY);
        relayOp  = vm.addr(RELAY_KEY);
        exitOp   = vm.addr(EXIT_KEY);
        client   = vm.addr(CLIENT_KEY);

        // Derive nodeIds.
        bytes32 entryPub = keccak256("entry-pub");
        bytes32 relayPub = keccak256("relay-pub");
        bytes32 exitPub  = keccak256("exit-pub");
        entryId = keccak256(abi.encode(entryOp, entryPub));
        relayId = keccak256(abi.encode(relayOp, relayPub));
        exitId  = keccak256(abi.encode(exitOp, exitPub));

        vm.deal(deployer, 100 ether);
        vm.deal(entryOp, 10 ether);
        vm.deal(relayOp, 10 ether);
        vm.deal(exitOp, 10 ether);
        vm.deal(client, 10 ether);

        // Deploy contracts.
        vm.startPrank(deployer);

        treasury = new Treasury(deployer);
        verifier = new AlwaysVerifier();
        zk = new ZKSettlement(address(verifier));

        uint64 nonce = vm.getNonce(deployer);
        address predictedOracle = vm.computeCreateAddress(deployer, nonce + 2);

        registry   = new NodeRegistry(predictedOracle);
        settlement = new SessionSettlement(address(registry), deployer);
        oracle     = new SlashingOracle(
            address(registry), address(treasury), address(settlement), deployer
        );
        require(address(oracle) == predictedOracle, "oracle mismatch");

        vm.stopPrank();

        // Register 3 nodes with secp256k1 keys.
        vm.prank(entryOp);
        registry.register{value: 0.1 ether}(entryId, entryPub, "1.1.1.1:51820", TestKeys.entry_key());
        vm.prank(relayOp);
        registry.register{value: 0.1 ether}(relayId, relayPub, "2.2.2.2:51820", TestKeys.relay_key());
        vm.prank(exitOp);
        registry.register{value: 1 ether}(exitId, exitPub, "3.3.3.3:51820", TestKeys.exit_key());

        // Set prices on all nodes.
        vm.prank(entryOp);
        registry.updatePricePerByte(entryId, 1);
        vm.prank(relayOp);
        registry.updatePricePerByte(relayId, 1);
        vm.prank(exitOp);
        registry.updatePricePerByte(exitId, 1);
    }

    /// @notice Full pipeline: open session → ZK deposit → compute commitments → settle.
    function test_full_zk_pipeline() public {
        // 1. Open a session.
        bytes32[3] memory ids = [entryId, relayId, exitId];
        vm.prank(client);
        settlement.openSession{value: 1 ether}(ids, type(uint256).max);

        // 2. Make a ZK deposit.
        vm.prank(client);
        bytes32 depositId = zk.deposit{value: 1 ether}();
        assertEq(zk.deposits(depositId), 1 ether);

        // 3. Set registry root (mock: just use a nonzero value).
        uint256 mockRoot = 12345;
        vm.prank(deployer);
        zk.proposeRegistryRoot(mockRoot);
        vm.warp(block.timestamp + zk.ROOT_TIMELOCK() + 1);
        vm.prank(deployer);
        zk.executeRegistryRoot(0);

        // 4. Compute Poseidon commitments.
        uint256 totalPayment = 1000;
        uint256 entryPay = (totalPayment * 25) / 100;   // 250
        uint256 relayPay = (totalPayment * 25) / 100;   // 250
        uint256 exitPay  = totalPayment - entryPay - relayPay;  // 500
        uint256 refund   = 1 ether - totalPayment;

        uint256 entryCommit = PoseidonT3.hash([uint256(uint160(entryOp)), entryPay]);
        uint256 relayCommit = PoseidonT3.hash([uint256(uint160(relayOp)), relayPay]);
        uint256 exitCommit  = PoseidonT3.hash([uint256(uint160(exitOp)), exitPay]);
        uint256 refundCommit = PoseidonT3.hash([uint256(uint160(client)), refund]);

        bytes32 nullifier = keccak256("test-nullifier");

        // 5. Build public signals.
        uint256[13] memory pubSignals = [
            uint256(zk.DOMAIN_SEPARATOR()),
            totalPayment,
            entryCommit,
            relayCommit,
            exitCommit,
            refundCommit,
            mockRoot,
            uint256(nullifier),
            uint256(depositId),
            entryPay,
            relayPay,
            exitPay,
            refund
        ];

        // 6. Settle with (mock) proof.
        _settleZk(pubSignals, nullifier, depositId);

        // 7. Verify settlement.
        assertEq(zk.deposits(depositId), 0, "deposit not consumed");
        assertTrue(zk.nullifiers(nullifier), "nullifier not marked");
        assertEq(zk.pendingWithdrawals(entryOp), entryPay, "entry payment wrong");
        assertEq(zk.pendingWithdrawals(relayOp), relayPay, "relay payment wrong");
        assertEq(zk.pendingWithdrawals(exitOp), exitPay, "exit payment wrong");
        assertEq(zk.pendingWithdrawals(client), refund, "refund wrong");

        // 8. Verify withdrawals work.
        uint256 entryBefore = entryOp.balance;
        vm.prank(entryOp);
        zk.withdraw();
        assertEq(entryOp.balance - entryBefore, entryPay);
    }

    function _settleZk(
        uint256[13] memory pubSignals,
        bytes32 nullifier,
        bytes32 depositId
    ) internal {
        uint256[2] memory pa = [uint256(0), uint256(0)];
        uint256[2][2] memory pb = [[uint256(0), uint256(0)], [uint256(0), uint256(0)]];
        uint256[2] memory pc = [uint256(0), uint256(0)];

        vm.prank(client);
        zk.settleWithProof(
            pa, pb, pc, pubSignals,
            nullifier, depositId,
            payable(entryOp), payable(relayOp), payable(exitOp), payable(client)
        );
    }

    /// @notice Verify secp256k1 keys are stored correctly on registration.
    function test_secp256k1_keys_stored() public {
        NodeRegistry.NodeInfo memory info = NodeRegistry(address(registry)).getNode(entryId);
        assertTrue(info.secp256k1X != bytes32(0), "secp256k1X should be nonzero");
        assertTrue(info.secp256k1Y != bytes32(0), "secp256k1Y should be nonzero");

        // Verify address derivation: keccak256(x || y) → last 20 bytes == operator.
        bytes memory key = abi.encodePacked(info.secp256k1X, info.secp256k1Y);
        address derived = address(uint160(uint256(keccak256(key))));
        assertEq(derived, entryOp, "secp256k1 key does not match operator address");
    }
}
