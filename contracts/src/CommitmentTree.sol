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

    /// @notice Timelock delay for insert/remove operations.
    uint256 public constant COMMITMENT_TIMELOCK = 48 hours;

    // ──────────────────────────────────────────────────────────────
    //  State
    // ──────────────────────────────────────────────────────────────

    address public owner;

    /// @notice Pending owner for two-step transfer.
    address public pendingOwner;

    /// @notice 1-indexed binary tree: nodes[1] = root, leaves at [512..1023].
    ///         Index 0 is unused. Total storage: 1023 slots.
    bytes32[1024] internal nodes;

    /// @notice Whether each leaf slot is a real node (true) or dummy (false).
    bool[512] internal isReal;

    /// @notice Total real node commitments in the tree.
    uint256 public realCount;

    /// @notice Total dummy commitments in the tree.
    uint256 public dummyCount;

    /// @notice Current Merkle root.
    bytes32 public root;

    /// @notice Whether the tree has been fully initialized with dummies.
    bool public initialized;

    /// @notice Number of leaf slots initialized so far (for batched init).
    uint256 public initProgress;

    /// @notice Whether the fork threshold has been reached.
    bool public forkReady;

    /// @notice Mapping from commitment → leaf index (0-based, for external API).
    mapping(bytes32 => uint256) public commitmentIndex;

    /// @dev Timelocked commitment proposals.
    struct CommitmentProposal {
        bytes32 commitment;
        bytes32 salt;      // only used for removal
        bool    isInsert;  // true = insert, false = remove
        uint256 readyAt;
        bool    executed;
    }
    mapping(uint256 => CommitmentProposal) public commitmentProposals;
    uint256 public nextProposalId;

    // ──────────────────────────────────────────────────────────────
    //  Events
    // ──────────────────────────────────────────────────────────────

    event TreeInitialized(uint256 dummyCount, bytes32 root);
    event RealNodeInserted(bytes32 indexed commitment, uint256 index);
    event RealNodeRemoved(bytes32 indexed commitment, uint256 index);
    event ForkThresholdReached(uint256 realCount);
    event InsertProposed(uint256 indexed proposalId, bytes32 indexed commitment, uint256 readyAt);
    event RemoveProposed(uint256 indexed proposalId, bytes32 indexed commitment, uint256 readyAt);
    event OwnershipTransferProposed(address indexed currentOwner, address indexed proposedOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // ──────────────────────────────────────────────────────────────
    //  Errors
    // ──────────────────────────────────────────────────────────────

    error NotOwner();
    error AlreadyInitialized();
    error TreeFull();
    error CommitmentNotFound();
    error ZeroCommitment();
    error DuplicateCommitment();

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

    /// @notice Propose a new owner. The new owner must call acceptOwnership().
    /// @param newOwner Address of the proposed new owner.
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "CommitmentTree: zero address");
        pendingOwner = newOwner;
        emit OwnershipTransferProposed(owner, newOwner);
    }

    /// @notice Accept a pending ownership transfer. Only callable by pendingOwner.
    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "CommitmentTree: not pending owner");
        emit OwnershipTransferred(owner, msg.sender);
        owner = msg.sender;
        pendingOwner = address(0);
    }

    // ──────────────────────────────────────────────────────────────
    //  Initialize with dummies
    // ──────────────────────────────────────────────────────────────

    /// @notice Fill leaf slots with dummy commitments in batches to avoid
    ///         exceeding the block gas limit. Call repeatedly until
    ///         `initialized` is true.
    ///
    ///         Dummy commitments are keccak256(abi.encode("dummy", index, salt)).
    ///         In production, salt should come from a VDF or commit-reveal
    ///         scheme so even the deployer can't later prove which were dummies.
    /// @param salt       Random salt for dummy generation.
    /// @param batchSize  Number of leaves to fill in this call.
    function initialize(bytes32 salt, uint256 batchSize) external onlyOwner {
        if (initialized) revert AlreadyInitialized();
        require(batchSize > 0, "CommitmentTree: zero batch");

        uint256 start = initProgress;
        uint256 end = start + batchSize;
        if (end > TREE_SIZE) end = TREE_SIZE;

        // Fill leaves (1-indexed at TREE_SIZE .. 2*TREE_SIZE-1).
        for (uint256 i = start; i < end; ++i) {
            bytes32 leaf = keccak256(abi.encode("dummy", i, salt));
            nodes[TREE_SIZE + i] = leaf;
            dummyCount++;
        }

        initProgress = end;

        // Once all leaves are written, build internal nodes and finalize.
        if (end == TREE_SIZE) {
            for (uint256 idx = TREE_SIZE - 1; idx >= 1; --idx) {
                nodes[idx] = keccak256(abi.encodePacked(nodes[2 * idx], nodes[2 * idx + 1]));
            }
            initialized = true;
            root = nodes[1];
            emit TreeInitialized(dummyCount, root);
        }
    }

    // ──────────────────────────────────────────────────────────────
    //  Timelocked insert / remove
    // ──────────────────────────────────────────────────────────────

    /// @notice Propose inserting a real node commitment (48h timelock).
    /// @param commitment The node's Poseidon commitment.
    /// @return proposalId The ID of the created proposal.
    function proposeInsert(bytes32 commitment) external onlyOwner returns (uint256 proposalId) {
        require(initialized, "CommitmentTree: not initialized");
        if (commitment == bytes32(0)) revert ZeroCommitment();
        proposalId = nextProposalId++;
        uint256 readyAt = block.timestamp + COMMITMENT_TIMELOCK;
        commitmentProposals[proposalId] = CommitmentProposal({
            commitment: commitment,
            salt:       bytes32(0),
            isInsert:   true,
            readyAt:    readyAt,
            executed:   false
        });
        emit InsertProposed(proposalId, commitment, readyAt);
    }

    /// @notice Propose removing a real node commitment (48h timelock).
    /// @param commitment The commitment to remove.
    /// @param salt Salt for the replacement dummy.
    /// @return proposalId The ID of the created proposal.
    function proposeRemove(bytes32 commitment, bytes32 salt) external onlyOwner returns (uint256 proposalId) {
        require(initialized, "CommitmentTree: not initialized");
        proposalId = nextProposalId++;
        uint256 readyAt = block.timestamp + COMMITMENT_TIMELOCK;
        commitmentProposals[proposalId] = CommitmentProposal({
            commitment: commitment,
            salt:       salt,
            isInsert:   false,
            readyAt:    readyAt,
            executed:   false
        });
        emit RemoveProposed(proposalId, commitment, readyAt);
    }

    /// @notice Execute a timelocked insert or remove proposal.
    /// @param proposalId The proposal to execute.
    function executeProposal(uint256 proposalId) external onlyOwner {
        CommitmentProposal storage cp = commitmentProposals[proposalId];
        require(cp.readyAt > 0, "CommitmentTree: unknown proposal");
        require(!cp.executed, "CommitmentTree: already executed");
        require(block.timestamp >= cp.readyAt, "CommitmentTree: timelock active");
        cp.executed = true;

        if (cp.isInsert) {
            _insertReal(cp.commitment);
        } else {
            _removeReal(cp.commitment, cp.salt);
        }
    }

    /// @dev Replace a dummy slot with a real node commitment.
    /// @param commitment The node's Poseidon commitment to insert.
    function _insertReal(bytes32 commitment) internal {
        if (commitmentIndex[commitment] != 0) revert DuplicateCommitment();

        // Find the next dummy slot.
        uint256 slot = _findDummySlot();
        if (slot >= TREE_SIZE) revert TreeFull();

        // Update the leaf and propagate to root.
        nodes[TREE_SIZE + slot] = commitment;
        isReal[slot] = true;
        commitmentIndex[commitment] = slot + 1; // +1 so 0 means "not found"
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

    /// @dev Replace a real node's commitment with a fresh dummy.
    /// @param commitment The commitment to remove from the tree.
    /// @param salt        Salt used to generate the replacement dummy.
    function _removeReal(bytes32 commitment, bytes32 salt) internal {
        uint256 raw = commitmentIndex[commitment];
        if (raw == 0) revert CommitmentNotFound();
        uint256 slot = raw - 1;
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

    /// @notice Read a leaf by its 0-based index. Restricted to owner to
    ///         prevent enumeration of real vs dummy slots.
    /// @param index The 0-based leaf index.
    /// @return The leaf commitment at the given index.
    function getLeaf(uint256 index) external view onlyOwner returns (bytes32) {
        return nodes[TREE_SIZE + index];
    }

    /// @notice Return the current Merkle root of the commitment tree.
    /// @return The current root hash.
    function getRoot() external view returns (bytes32) {
        return root;
    }

    /// @notice Get the Merkle proof for a leaf at the given 0-based index.
    ///         Restricted to owner to prevent enumeration.
    /// @return siblings The sibling hashes along the path from leaf to root.
    function getMerkleProof(uint256 index)
        external
        view
        onlyOwner
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
