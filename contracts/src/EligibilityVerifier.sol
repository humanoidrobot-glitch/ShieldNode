// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IEligibilityProofVerifier
/// @notice Interface for the auto-generated Groth16 verifier for node
///         eligibility proofs (produced by snarkjs from the circom circuit).
interface IEligibilityProofVerifier {
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[6] calldata _pubSignals
    ) external view returns (bool);
}

/// @title EligibilityVerifier
/// @notice Verifies ZK proofs that a node meets selection criteria without
///         revealing which node produced the proof.
///
///         A node proves: "I am in the registry, my stake >= X, my slashes
///         <= Y, my uptime >= Z" without revealing its identity, endpoint,
///         actual stake, or any other metadata.
///
///         Hardens against enumeration attacks: even observing all proofs
///         doesn't reveal which nodes are in the network.
contract EligibilityVerifier {
    // ──────────────────────────────────────────────────────────────
    //  Constants
    // ──────────────────────────────────────────────────────────────

    // Public signal indices (must match circuit's public input order).
    uint256 private constant SIG_REGISTRY_ROOT    = 0;
    uint256 private constant SIG_MIN_STAKE        = 1;
    uint256 private constant SIG_MAX_SLASH_COUNT  = 2;
    uint256 private constant SIG_MIN_UPTIME       = 3;
    uint256 private constant SIG_EPOCH            = 4;
    uint256 private constant SIG_NULLIFIER        = 5;

    /// @notice Default eligibility thresholds.
    uint256 public constant DEFAULT_MIN_STAKE = 0.1 ether;
    uint256 public constant DEFAULT_MAX_SLASHES = 1;
    uint256 public constant DEFAULT_MIN_UPTIME = 900; // 90% × 1000

    /// @notice Timelock delay for registry root updates.
    uint256 public constant ROOT_TIMELOCK = 48 hours;

    // ──────────────────────────────────────────────────────────────
    //  Immutables
    // ──────────────────────────────────────────────────────────────

    IEligibilityProofVerifier public immutable proofVerifier;

    // ──────────────────────────────────────────────────────────────
    //  State
    // ──────────────────────────────────────────────────────────────

    /// @notice Current registry Merkle root (updated by owner).
    uint256 public registryRoot;

    address public owner;

    /// @notice Pending owner for two-step transfer.
    address public pendingOwner;

    /// @notice Tracks used nullifiers to prevent double-proof.
    mapping(uint256 => bool) public usedNullifiers;

    /// @dev Timelocked registry root proposals.
    struct RootProposal {
        uint256 newRoot;
        uint256 readyAt;
        bool    executed;
    }
    mapping(uint256 => RootProposal) public rootProposals;
    uint256 public nextProposalId;

    // ──────────────────────────────────────────────────────────────
    //  Events
    // ──────────────────────────────────────────────────────────────

    event EligibilityProven(uint256 indexed nullifier);
    event RegistryRootUpdated(uint256 newRoot);
    event RegistryRootProposed(uint256 indexed proposalId, uint256 newRoot, uint256 readyAt);
    event OwnershipTransferProposed(address indexed currentOwner, address indexed proposedOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // ──────────────────────────────────────────────────────────────
    //  Errors
    // ──────────────────────────────────────────────────────────────

    error NotOwner();
    error InvalidProof();
    error NullifierAlreadyUsed();
    error RegistryRootMismatch();
    error ThresholdMismatch(string field);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    // ──────────────────────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────────────────────

    constructor(address _verifier) {
        require(_verifier != address(0), "EligibilityVerifier: zero verifier");
        proofVerifier = IEligibilityProofVerifier(_verifier);
        owner = msg.sender;
    }

    // ──────────────────────────────────────────────────────────────
    //  Admin (timelocked)
    // ──────────────────────────────────────────────────────────────

    /// @notice Propose a new registry root (48h timelock).
    /// @param newRoot The new Merkle root.
    /// @return proposalId The ID of the created proposal.
    function proposeRegistryRoot(uint256 newRoot) external onlyOwner returns (uint256 proposalId) {
        require(newRoot != 0, "EligibilityVerifier: zero root");
        proposalId = nextProposalId++;
        uint256 readyAt = block.timestamp + ROOT_TIMELOCK;
        rootProposals[proposalId] = RootProposal({
            newRoot:  newRoot,
            readyAt:  readyAt,
            executed: false
        });
        emit RegistryRootProposed(proposalId, newRoot, readyAt);
    }

    /// @notice Execute a timelocked registry root update.
    /// @param proposalId The proposal to execute.
    function executeRegistryRoot(uint256 proposalId) external onlyOwner {
        RootProposal storage rp = rootProposals[proposalId];
        require(rp.readyAt > 0, "EligibilityVerifier: unknown proposal");
        require(!rp.executed, "EligibilityVerifier: already executed");
        require(block.timestamp >= rp.readyAt, "EligibilityVerifier: timelock active");
        rp.executed = true;
        registryRoot = rp.newRoot;
        emit RegistryRootUpdated(rp.newRoot);
    }

    // ──────────────────────────────────────────────────────────────
    //  Ownership transfer (two-step)
    // ──────────────────────────────────────────────────────────────

    /// @notice Propose a new owner. The new owner must call acceptOwnership().
    /// @param newOwner Address of the proposed new owner.
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "EligibilityVerifier: zero address");
        pendingOwner = newOwner;
        emit OwnershipTransferProposed(owner, newOwner);
    }

    /// @notice Accept a pending ownership transfer. Only callable by pendingOwner.
    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "EligibilityVerifier: not pending owner");
        emit OwnershipTransferred(owner, msg.sender);
        owner = msg.sender;
        pendingOwner = address(0);
    }

    // ──────────────────────────────────────────────────────────────
    //  Verification
    // ──────────────────────────────────────────────────────────────

    /// @notice Verify that an anonymous node meets eligibility criteria.
    /// @param proof_a Groth16 proof point A.
    /// @param proof_b Groth16 proof point B.
    /// @param proof_c Groth16 proof point C.
    /// @param pubSignals The 6 public inputs: registryRoot, minStake,
    ///        maxSlashCount, minUptimeScaled, epoch, nullifier.
    function verifyEligibility(
        uint256[2] calldata proof_a,
        uint256[2][2] calldata proof_b,
        uint256[2] calldata proof_c,
        uint256[6] calldata pubSignals
    ) external {
        // Verify registry root matches.
        if (pubSignals[SIG_REGISTRY_ROOT] != registryRoot) {
            revert RegistryRootMismatch();
        }

        // Verify thresholds match expected values.
        if (pubSignals[SIG_MIN_STAKE] != DEFAULT_MIN_STAKE) {
            revert ThresholdMismatch("minStake");
        }
        if (pubSignals[SIG_MAX_SLASH_COUNT] != DEFAULT_MAX_SLASHES) {
            revert ThresholdMismatch("maxSlashCount");
        }
        if (pubSignals[SIG_MIN_UPTIME] != DEFAULT_MIN_UPTIME) {
            revert ThresholdMismatch("minUptime");
        }

        // Check nullifier not already used.
        uint256 nullifier = pubSignals[SIG_NULLIFIER];
        if (usedNullifiers[nullifier]) {
            revert NullifierAlreadyUsed();
        }

        // Verify the ZK proof.
        bool valid = proofVerifier.verifyProof(proof_a, proof_b, proof_c, pubSignals);
        if (!valid) {
            revert InvalidProof();
        }

        // Mark nullifier as used.
        usedNullifiers[nullifier] = true;

        emit EligibilityProven(nullifier);
    }
}
