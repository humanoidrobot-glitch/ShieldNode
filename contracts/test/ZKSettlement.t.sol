// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {ZKSettlement, IGroth16Verifier} from "../src/ZKSettlement.sol";

contract MockVerifier is IGroth16Verifier {
    bool public shouldPass = true;

    function setResult(bool _pass) external {
        shouldPass = _pass;
    }

    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[13] calldata
    ) external view override returns (bool) {
        return shouldPass;
    }
}

contract ZKSettlementTest is Test {
    ZKSettlement public zk;
    MockVerifier public mockVerifier;

    address public client   = makeAddr("client");
    address public entryOp  = makeAddr("entryOp");
    address public relayOp  = makeAddr("relayOp");
    address public exitOp   = makeAddr("exitOp");
    address public refundTo = makeAddr("refundTo");

    function setUp() public {
        mockVerifier = new MockVerifier();
        zk = new ZKSettlement(address(mockVerifier));
        vm.deal(client, 10 ether);
        zk.updateRegistryRoot(12345);
    }

    /// @dev Build 13 public signals with nullifier and depositId bound.
    function _pubSignals(
        uint256 totalPayment,
        bytes32 nullifier,
        bytes32 depositId
    ) internal view returns (uint256[13] memory) {
        uint256 entryPay = (totalPayment * 25) / 100;
        uint256 relayPay = (totalPayment * 25) / 100;
        uint256 exitPay  = totalPayment - entryPay - relayPay;
        uint256 refund   = totalPayment <= 1 ether ? 1 ether - totalPayment : 0;
        return [
            uint256(zk.DOMAIN_SEPARATOR()),  // [0] domainSeparator
            totalPayment,                     // [1] totalPayment
            uint256(1),                       // [2] entryCommitment (dummy)
            uint256(2),                       // [3] relayCommitment (dummy)
            uint256(3),                       // [4] exitCommitment (dummy)
            uint256(4),                       // [5] refundCommitment (dummy)
            uint256(12345),                   // [6] registryRoot
            uint256(nullifier),               // [7] nullifier
            uint256(depositId),               // [8] depositId
            entryPay,                         // [9] entryPayOut
            relayPay,                         // [10] relayPayOut
            exitPay,                          // [11] exitPayOut
            refund                            // [12] refundOut
        ];
    }

    function _dummyProof()
        internal pure
        returns (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c)
    {
        a = [uint256(0), uint256(0)];
        b = [[uint256(0), uint256(0)], [uint256(0), uint256(0)]];
        c = [uint256(0), uint256(0)];
    }

    // ── Deposit tests ────────────────────────────────────────────

    function test_deposit() public {
        bytes32 depositId = keccak256("deposit-1");
        vm.prank(client);
        zk.deposit{value: 0.01 ether}(depositId);
        assertEq(zk.deposits(depositId), 0.01 ether);
    }

    function test_deposit_too_low() public {
        vm.prank(client);
        vm.expectRevert("ZKSettlement: deposit too low");
        zk.deposit{value: 0.0001 ether}(keccak256("low"));
    }

    function test_deposit_duplicate() public {
        bytes32 depositId = keccak256("dup");
        vm.prank(client);
        zk.deposit{value: 0.01 ether}(depositId);
        vm.prank(client);
        vm.expectRevert("ZKSettlement: duplicate deposit");
        zk.deposit{value: 0.01 ether}(depositId);
    }

    // ── Settlement tests ─────────────────────────────────────────

    function test_settle_with_valid_proof() public {
        bytes32 depositId = keccak256("session-zk-1");
        bytes32 nullifier = keccak256("null-1");

        vm.prank(client);
        zk.deposit{value: 1 ether}(depositId);

        uint256 totalPayment = 1000;
        uint256[13] memory pub = _pubSignals(totalPayment, nullifier, depositId);
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _dummyProof();

        uint256 entryBefore = entryOp.balance;
        uint256 exitBefore  = exitOp.balance;

        zk.settleWithProof(
            a, b, c, pub,
            nullifier, depositId,
            payable(entryOp), payable(relayOp), payable(exitOp), payable(refundTo)
        );

        assertEq(entryOp.balance - entryBefore, 250);
        assertEq(exitOp.balance - exitBefore, 500);
        assertEq(zk.deposits(depositId), 0);
        assertTrue(zk.nullifiers(nullifier));
    }

    function test_double_settle_reverts() public {
        bytes32 depositId = keccak256("session-ds");
        bytes32 nullifier = keccak256("null-ds");

        vm.prank(client);
        zk.deposit{value: 1 ether}(depositId);

        uint256[13] memory pub = _pubSignals(100, nullifier, depositId);
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _dummyProof();

        zk.settleWithProof(a, b, c, pub, nullifier, depositId,
            payable(entryOp), payable(relayOp), payable(exitOp), payable(refundTo));

        vm.expectRevert("ZKSettlement: already settled");
        zk.settleWithProof(a, b, c, pub, nullifier, depositId,
            payable(entryOp), payable(relayOp), payable(exitOp), payable(refundTo));
    }

    function test_invalid_proof_reverts() public {
        bytes32 depositId = keccak256("session-inv");
        bytes32 nullifier = keccak256("null-inv");

        vm.prank(client);
        zk.deposit{value: 1 ether}(depositId);
        mockVerifier.setResult(false);

        uint256[13] memory pub = _pubSignals(100, nullifier, depositId);
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _dummyProof();

        vm.expectRevert("ZKSettlement: invalid proof");
        zk.settleWithProof(a, b, c, pub, nullifier, depositId,
            payable(entryOp), payable(relayOp), payable(exitOp), payable(refundTo));
    }

    function test_wrong_domain_reverts() public {
        bytes32 depositId = keccak256("session-wd");
        bytes32 nullifier = keccak256("null-wd");

        vm.prank(client);
        zk.deposit{value: 1 ether}(depositId);

        uint256[13] memory pub = _pubSignals(100, nullifier, depositId);
        pub[0] = 99999; // Wrong domain separator

        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _dummyProof();
        vm.expectRevert("ZKSettlement: wrong domain");
        zk.settleWithProof(a, b, c, pub, nullifier, depositId,
            payable(entryOp), payable(relayOp), payable(exitOp), payable(refundTo));
    }

    function test_stale_registry_root_reverts() public {
        bytes32 depositId = keccak256("session-sr");
        bytes32 nullifier = keccak256("null-sr");

        vm.prank(client);
        zk.deposit{value: 1 ether}(depositId);

        uint256[13] memory pub = _pubSignals(100, nullifier, depositId);
        pub[6] = 99999; // Wrong registry root

        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _dummyProof();
        vm.expectRevert("ZKSettlement: stale registry root");
        zk.settleWithProof(a, b, c, pub, nullifier, depositId,
            payable(entryOp), payable(relayOp), payable(exitOp), payable(refundTo));
    }

    function test_payment_exceeds_deposit_reverts() public {
        bytes32 depositId = keccak256("session-pe");
        bytes32 nullifier = keccak256("null-pe");

        vm.prank(client);
        zk.deposit{value: 0.001 ether}(depositId);

        uint256[13] memory pub = _pubSignals(2 ether, nullifier, depositId);
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _dummyProof();

        vm.expectRevert("ZKSettlement: payment exceeds deposit");
        zk.settleWithProof(a, b, c, pub, nullifier, depositId,
            payable(entryOp), payable(relayOp), payable(exitOp), payable(refundTo));
    }

    function test_nullifier_mismatch_reverts() public {
        bytes32 depositId = keccak256("session-nm");
        bytes32 nullifier = keccak256("null-nm");
        bytes32 wrongNull = keccak256("wrong-null");

        vm.prank(client);
        zk.deposit{value: 1 ether}(depositId);

        uint256[13] memory pub = _pubSignals(100, nullifier, depositId);
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _dummyProof();

        // Pass a different nullifier than what's in pubSignals.
        vm.expectRevert("ZKSettlement: nullifier mismatch");
        zk.settleWithProof(a, b, c, pub, wrongNull, depositId,
            payable(entryOp), payable(relayOp), payable(exitOp), payable(refundTo));
    }

    function test_deposit_id_mismatch_reverts() public {
        bytes32 depositId = keccak256("session-dm");
        bytes32 nullifier = keccak256("null-dm");
        bytes32 wrongDep  = keccak256("wrong-dep");

        vm.prank(client);
        zk.deposit{value: 1 ether}(depositId);

        // pubSignals bind to depositId, but we pass wrongDep.
        uint256[13] memory pub = _pubSignals(100, nullifier, depositId);
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _dummyProof();

        vm.expectRevert("ZKSettlement: deposit mismatch");
        zk.settleWithProof(a, b, c, pub, nullifier, wrongDep,
            payable(entryOp), payable(relayOp), payable(exitOp), payable(refundTo));
    }

    // ── Admin tests ──────────────────────────────────────────────

    function test_update_registry_root() public {
        zk.updateRegistryRoot(67890);
        assertEq(zk.registryRoot(), 67890);
    }

    function test_update_registry_root_unauthorized() public {
        vm.prank(client);
        vm.expectRevert("ZKSettlement: not owner");
        zk.updateRegistryRoot(99999);
    }
}
