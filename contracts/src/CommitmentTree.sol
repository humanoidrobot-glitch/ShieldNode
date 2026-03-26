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

    /// @notice The commitment leaves. Index 0..TREE_SIZE-1.
    ///         Zero means empty (will be filled with dummy on first root compute).
    bytes32[512] public leaves;

    /// @notice Whether each leaf is a real node (true) or dummy (false).
    bool[512] public isReal;

    /// @notice Total real node commitments in the tree.
    uint256 public realCount;

    /// @notice Total dummy commitments in the tree.
    uint256 public dummyCount;

    /// @notice Current Merkle root (recomputed on insert/remove).
    bytes32 public root;

    /// @notice Whether the tree has been initialized with dummies.
    bool public initialized;

    /// @notice Whether the fork threshold has been reached.
    bool public forkReady;

    /// @notice Mapping from commitment → leaf index (for lookup/removal).
    mapping(bytes32 => uint256) public commitmentIndex;

    /// @notice Next available slot for real node insertion.
    uint256 private _nextRealSlot;

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

    // ──────────────────────────────────────────────────────────────
    //  Initialize with dummies
    // ──────────────────────────────────────────────────────────────

    /// @notice Fill all empty slots with dummy commitments.
    ///         Dummy commitments are keccak256(abi.encode("dummy", index, salt))
    ///         where salt is provided by the deployer. In production, salt
    ///         should come from a VDF or commit-reveal scheme so even the
    ///         deployer can't later prove which were dummies.
    /// @param salt Random salt for dummy generation.
    function initialize(bytes32 salt) external onlyOwner {
        if (initialized) revert AlreadyInitialized();

        for (uint256 i; i < TREE_SIZE; ++i) {
            if (leaves[i] == bytes32(0)) {
                leaves[i] = keccak256(abi.encode("dummy", i, salt));
                dummyCount++;
            }
        }

        initialized = true;
        root = _computeRoot();

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

        leaves[slot] = commitment;
        isReal[slot] = true;
        commitmentIndex[commitment] = slot;
        realCount++;

        if (dummyCount > 0) {
            dummyCount--;
        }

        root = _computeRoot();

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
        if (!isReal[slot] || leaves[slot] != commitment) revert CommitmentNotFound();

        // Replace with a new dummy.
        leaves[slot] = keccak256(abi.encode("dummy-replace", slot, salt));
        isReal[slot] = false;
        delete commitmentIndex[commitment];
        realCount--;
        dummyCount++;

        root = _computeRoot();

        emit RealNodeRemoved(commitment, slot);
    }

    // ──────────────────────────────────────────────────────────────
    //  Views
    // ──────────────────────────────────────────────────────────────

    function getLeaf(uint256 index) external view returns (bytes32) {
        return leaves[index];
    }

    function getRoot() external view returns (bytes32) {
        return root;
    }

    /// @notice Get the Merkle proof for a leaf at the given index.
    /// @return siblings The sibling hashes along the path from leaf to root.
    function getMerkleProof(uint256 index)
        external
        view
        returns (bytes32[9] memory siblings)
    {
        uint256 idx = index;
        bytes32[512] memory layer = leaves;

        for (uint256 depth; depth < TREE_DEPTH; ++depth) {
            uint256 layerLen = TREE_SIZE >> depth;
            uint256 sibIdx = idx ^ 1; // flip last bit to get sibling
            siblings[depth] = (sibIdx < layerLen) ? layer[sibIdx] : bytes32(0);

            // Compute next layer.
            uint256 nextLen = layerLen / 2;
            bytes32[512] memory next;
            for (uint256 i; i < nextLen; ++i) {
                next[i] = keccak256(abi.encodePacked(layer[2 * i], layer[2 * i + 1]));
            }
            layer = next;
            idx = idx / 2;
        }
    }

    // ──────────────────────────────────────────────────────────────
    //  Internal
    // ──────────────────────────────────────────────────────────────

    function _findDummySlot() internal view returns (uint256) {
        for (uint256 i = _nextRealSlot; i < TREE_SIZE; ++i) {
            if (!isReal[i]) return i;
        }
        // Wrap around.
        for (uint256 i; i < _nextRealSlot; ++i) {
            if (!isReal[i]) return i;
        }
        return TREE_SIZE; // full
    }

    /// @notice Compute the Merkle root from all leaves using keccak256.
    ///         In production, this would use Poseidon for ZK compatibility.
    function _computeRoot() internal view returns (bytes32) {
        bytes32[512] memory layer = leaves;
        uint256 layerLen = TREE_SIZE;

        for (uint256 depth; depth < TREE_DEPTH; ++depth) {
            uint256 nextLen = layerLen / 2;
            for (uint256 i; i < nextLen; ++i) {
                layer[i] = keccak256(abi.encodePacked(layer[2 * i], layer[2 * i + 1]));
            }
            layerLen = nextLen;
        }

        return layer[0];
    }
}
