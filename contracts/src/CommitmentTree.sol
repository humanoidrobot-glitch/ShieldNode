// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title CommitmentTree
/// @notice Fixed-size Merkle tree of node commitments for bootstrapping
///         network size privacy. At launch with few real nodes, unused
///         slots contain dummy commitments indistinguishable from real ones.
///
///         An attacker can see total registration events and stake locked,
///         but the dummies hide the real node count within the fixed tree
///         size. At 512 slots with 20 real nodes, the attacker knows
///         "somewhere between 1 and 512 nodes" — far better than "exactly 20."
///
///         When real node count crosses FORK_THRESHOLD, the tree can be
///         migrated to a new contract without dummy logic.
///
///         Internal nodes are stored on-chain so insert/remove only update
///         the O(log n) path from the mutated leaf to the root, instead of
///         recomputing the entire tree.
contract CommitmentTree {
    // ──────────────────────────────────────────────────────────────
    //  Constants
    // ──────────────────────────────────────────────────────────────

    /// @notice Fixed tree size (must be a power of 2).
    uint256 public constant TREE_SIZE = 512;

    /// @notice Tree depth: log2(512) = 9.
    uint256 public constant TREE_DEPTH = 9;

    /// @notice When real nodes exceed this count, the tree is ready for
    ///         migration to a dummyless contract.
    uint256 public constant FORK_THRESHOLD = 256;

    // ──────────────────────────────────────────────────────────────
    //  State
    // ──────────────────────────────────────────────────────────────

    address public owner;

    /// @notice 1-indexed binary tree: nodes[1] = root, leaves at [512..1023].
    ///         Index 0 is unused. Total storage: 1023 slots.
    bytes32[1024] internal nodes;

    /// @notice Whether each leaf slot is a real node (true) or dummy (false).
    bool[512] public isReal;

    /// @notice Total real node commitments in the tree.
    uint256 public realCount;

    /// @notice Total dummy commitments in the tree.
    uint256 public dummyCount;

    /// @notice Current Merkle root.
    bytes32 public root;

    /// @notice Whether the tree has been initialized with dummies.
    bool public initialized;

    /// @notice Whether the fork threshold has been reached.
    bool public forkReady;

    /// @notice Mapping from commitment → leaf index (0-based, for external API).
    mapping(bytes32 => uint256) public commitmentIndex;

    // ──────────────────────────────────────────────────────────────
    //  Events
    // ──────────────────────────────────────────────────────────────

    event TreeInitialized(uint256 dummyCount, bytes32 root);
    event RealNodeInserted(bytes32 indexed commitment, uint256 index);
    event RealNodeRemoved(bytes32 indexed commitment, uint256 index);
    event ForkThresholdReached(uint256 realCount);

    // ──────────────────────────────────────────────────────────────
    //  Errors
    // ──────────────────────────────────────────────────────────────

    error NotOwner();
    error AlreadyInitialized();
    error TreeFull();
    error CommitmentNotFound();
    error ZeroCommitment();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    // ──────────────────────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────────────────────

    constructor() {
        owner = msg.sender;
    }

    /// @notice Transfer ownership (e.g., to NodeRegistry after deployment).
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "CommitmentTree: zero owner");
        owner = newOwner;
    }

    // ──────────────────────────────────────────────────────────────
    //  Initialize with dummies
    // ──────────────────────────────────────────────────────────────

    /// @notice Fill all empty slots with dummy commitments and build the
    ///         full internal node tree.
    ///         Dummy commitments are keccak256(abi.encode("dummy", index, salt))
    ///         where salt is provided by the deployer. In production, salt
    ///         should come from a VDF or commit-reveal scheme so even the
    ///         deployer can't later prove which were dummies.
    /// @param salt Random salt for dummy generation.
    function initialize(bytes32 salt) external onlyOwner {
        if (initialized) revert AlreadyInitialized();

        // Fill leaves (1-indexed at TREE_SIZE .. 2*TREE_SIZE-1).
        for (uint256 i; i < TREE_SIZE; ++i) {
            bytes32 leaf = keccak256(abi.encode("dummy", i, salt));
            nodes[TREE_SIZE + i] = leaf;
            dummyCount++;
        }

        // Build internal nodes bottom-up.
        for (uint256 idx = TREE_SIZE - 1; idx >= 1; --idx) {
            nodes[idx] = keccak256(abi.encodePacked(nodes[2 * idx], nodes[2 * idx + 1]));
        }

        initialized = true;
        root = nodes[1];

        emit TreeInitialized(dummyCount, root);
    }

    // ──────────────────────────────────────────────────────────────
    //  Insert real node
    // ──────────────────────────────────────────────────────────────

    /// @notice Replace a dummy slot with a real node commitment.
    /// @param commitment The node's Poseidon commitment (from NodeRegistry).
    function insertReal(bytes32 commitment) external onlyOwner {
        if (commitment == bytes32(0)) revert ZeroCommitment();

        // Find the next dummy slot.
        uint256 slot = _findDummySlot();
        if (slot >= TREE_SIZE) revert TreeFull();

        // Update the leaf and propagate to root.
        nodes[TREE_SIZE + slot] = commitment;
        isReal[slot] = true;
        commitmentIndex[commitment] = slot;
        realCount++;

        if (dummyCount > 0) {
            dummyCount--;
        }

        _updatePath(TREE_SIZE + slot);

        emit RealNodeInserted(commitment, slot);

        if (realCount >= FORK_THRESHOLD && !forkReady) {
            forkReady = true;
            emit ForkThresholdReached(realCount);
        }
    }

    // ──────────────────────────────────────────────────────────────
    //  Remove real node (replace with dummy)
    // ──────────────────────────────────────────────────────────────

    /// @notice Replace a real node's commitment with a fresh dummy.
    /// @param commitment The commitment to remove.
    /// @param salt Salt for the replacement dummy.
    function removeReal(bytes32 commitment, bytes32 salt) external onlyOwner {
        uint256 slot = commitmentIndex[commitment];
        if (!isReal[slot] || nodes[TREE_SIZE + slot] != commitment) revert CommitmentNotFound();

        // Replace with a new dummy and propagate to root.
        nodes[TREE_SIZE + slot] = keccak256(abi.encode("dummy-replace", slot, salt));
        isReal[slot] = false;
        delete commitmentIndex[commitment];
        realCount--;
        dummyCount++;

        _updatePath(TREE_SIZE + slot);

        emit RealNodeRemoved(commitment, slot);
    }

    // ──────────────────────────────────────────────────────────────
    //  Views
    // ──────────────────────────────────────────────────────────────

    /// @notice Read a leaf by its 0-based index.
    function getLeaf(uint256 index) external view returns (bytes32) {
        return nodes[TREE_SIZE + index];
    }

    /// @notice Backward-compatible alias kept as `leaves(index)`.
    function leaves(uint256 index) external view returns (bytes32) {
        return nodes[TREE_SIZE + index];
    }

    function getRoot() external view returns (bytes32) {
        return root;
    }

    /// @notice Get the Merkle proof for a leaf at the given 0-based index.
    ///         Reads siblings directly from stored internal nodes — O(log n).
    /// @return siblings The sibling hashes along the path from leaf to root.
    function getMerkleProof(uint256 index)
        external
        view
        returns (bytes32[9] memory siblings)
    {
        uint256 idx = TREE_SIZE + index;
        for (uint256 depth; depth < TREE_DEPTH; ++depth) {
            // Sibling is the node that shares the same parent.
            siblings[depth] = nodes[idx ^ 1];
            idx /= 2;
        }
    }

    // ──────────────────────────────────────────────────────────────
    //  Internal
    // ──────────────────────────────────────────────────────────────

    function _findDummySlot() internal view returns (uint256) {
        for (uint256 i; i < TREE_SIZE; ++i) {
            if (!isReal[i]) return i;
        }
        return TREE_SIZE; // full
    }

    /// @notice Recompute internal nodes along the path from a leaf to the root.
    ///         Only touches O(TREE_DEPTH) = 9 storage slots.
    /// @param leafIdx The 1-indexed position of the mutated leaf.
    function _updatePath(uint256 leafIdx) internal {
        uint256 idx = leafIdx / 2; // start at parent
        while (idx >= 1) {
            nodes[idx] = keccak256(abi.encodePacked(nodes[2 * idx], nodes[2 * idx + 1]));
            idx /= 2;
        }
        root = nodes[1];
    }
}
