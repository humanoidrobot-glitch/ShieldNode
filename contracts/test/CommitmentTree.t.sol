// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {CommitmentTree} from "../src/CommitmentTree.sol";

contract CommitmentTreeTest is Test {
    CommitmentTree public tree;
    bytes32 constant SALT = keccak256("test-salt");

    function setUp() public {
        tree = new CommitmentTree();
    }

    // ── initialization ──────────────────────────────────────────

    function test_initialize_fills_all_slots() public {
        tree.initialize(SALT);

        assertTrue(tree.initialized());
        assertEq(tree.dummyCount(), 512);
        assertEq(tree.realCount(), 0);

        // All leaves should be non-zero.
        for (uint256 i; i < 10; ++i) {
            assertTrue(tree.getLeaf(i) != bytes32(0));
        }

        // Root should be non-zero.
        assertTrue(tree.getRoot() != bytes32(0));
    }

    function test_initialize_twice_reverts() public {
        tree.initialize(SALT);

        vm.expectRevert(CommitmentTree.AlreadyInitialized.selector);
        tree.initialize(SALT);
    }

    function test_initialize_only_owner() public {
        vm.prank(makeAddr("random"));
        vm.expectRevert(CommitmentTree.NotOwner.selector);
        tree.initialize(SALT);
    }

    // ── insert real node ────────────────────────────────────────

    function test_insert_real_replaces_dummy() public {
        tree.initialize(SALT);

        bytes32 commitment = keccak256("real-node-1");
        tree.insertReal(commitment);

        assertEq(tree.realCount(), 1);
        assertEq(tree.dummyCount(), 511);
        assertTrue(tree.isReal(tree.commitmentIndex(commitment)));
    }

    function test_insert_multiple_real_nodes() public {
        tree.initialize(SALT);

        for (uint256 i; i < 10; ++i) {
            tree.insertReal(keccak256(abi.encode("node", i)));
        }

        assertEq(tree.realCount(), 10);
        assertEq(tree.dummyCount(), 502);
    }

    function test_insert_zero_commitment_reverts() public {
        tree.initialize(SALT);

        vm.expectRevert(CommitmentTree.ZeroCommitment.selector);
        tree.insertReal(bytes32(0));
    }

    function test_root_changes_on_insert() public {
        tree.initialize(SALT);
        bytes32 rootBefore = tree.getRoot();

        tree.insertReal(keccak256("new-node"));
        bytes32 rootAfter = tree.getRoot();

        assertFalse(rootBefore == rootAfter);
    }

    // ── remove real node ────────────────────────────────────────

    function test_remove_real_replaces_with_dummy() public {
        tree.initialize(SALT);

        bytes32 commitment = keccak256("node-to-remove");
        tree.insertReal(commitment);
        assertEq(tree.realCount(), 1);

        tree.removeReal(commitment, keccak256("remove-salt"));
        assertEq(tree.realCount(), 0);
        assertEq(tree.dummyCount(), 512);
    }

    function test_remove_nonexistent_reverts() public {
        tree.initialize(SALT);

        vm.expectRevert(CommitmentTree.CommitmentNotFound.selector);
        tree.removeReal(keccak256("nonexistent"), SALT);
    }

    // ── fork threshold ──────────────────────────────────────────

    function test_fork_threshold_emits_event() public {
        tree.initialize(SALT);

        // Insert 256 real nodes (the threshold).
        for (uint256 i; i < 256; ++i) {
            tree.insertReal(keccak256(abi.encode("fork-node", i)));
        }

        assertTrue(tree.forkReady());
        assertEq(tree.realCount(), 256);
    }

    function test_fork_not_ready_below_threshold() public {
        tree.initialize(SALT);

        for (uint256 i; i < 100; ++i) {
            tree.insertReal(keccak256(abi.encode("node", i)));
        }

        assertFalse(tree.forkReady());
    }

    // ── Merkle proof ────────────────────────────────────────────

    function test_merkle_proof_length() public {
        tree.initialize(SALT);

        bytes32[9] memory proof = tree.getMerkleProof(0);

        // Should have 9 siblings (depth of the tree).
        // All should be non-zero (tree is fully populated).
        for (uint256 i; i < 9; ++i) {
            assertTrue(proof[i] != bytes32(0));
        }
    }

    function test_merkle_proof_verifies() public {
        tree.initialize(SALT);

        bytes32 commitment = keccak256("prove-me");
        tree.insertReal(commitment);

        uint256 idx = tree.commitmentIndex(commitment);
        bytes32[9] memory proof = tree.getMerkleProof(idx);

        // Manually verify the proof.
        bytes32 current = commitment;
        uint256 index = idx;
        for (uint256 i; i < 9; ++i) {
            if (index % 2 == 0) {
                current = keccak256(abi.encodePacked(current, proof[i]));
            } else {
                current = keccak256(abi.encodePacked(proof[i], current));
            }
            index = index / 2;
        }

        assertEq(current, tree.getRoot());
    }

    // ── dummy indistinguishability ──────────────────────────────

    function test_dummies_are_unique() public {
        tree.initialize(SALT);

        // Check first 20 leaves are all different.
        for (uint256 i; i < 20; ++i) {
            for (uint256 j = i + 1; j < 20; ++j) {
                assertFalse(tree.getLeaf(i) == tree.getLeaf(j));
            }
        }
    }

    function test_different_salts_produce_different_trees() public {
        CommitmentTree tree2 = new CommitmentTree();

        tree.initialize(SALT);
        tree2.initialize(keccak256("different-salt"));

        // Same index, different salt → different dummy.
        assertFalse(tree.getLeaf(0) == tree2.getLeaf(0));
        assertFalse(tree.getRoot() == tree2.getRoot());
    }
}
