// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {INodeRegistry}    from "./interfaces/INodeRegistry.sol";
import {NodeRegistry}     from "./NodeRegistry.sol";
import {SlashingOracle}   from "./SlashingOracle.sol";
import {EIP712Utils}      from "./lib/EIP712Utils.sol";

/// @title ChallengeManager
/// @notice Issues periodic challenges to relay nodes and tracks responses.
///         Nodes that fail to respond within the deadline get an automatic
///         slash proposal via the SlashingOracle.
///
///         v1: Trusted challenger set (same as SlashingOracle challengers).
///         v2 (Phase 6): Challenge bonds replace the trusted set.
contract ChallengeManager {
    // ──────────────────────────────────────────────────────────────
    //  Constants
    // ──────────────────────────────────────────────────────────────

    /// @notice Time a node has to respond to a challenge.
    uint256 public constant RESPONSE_DEADLINE = 1 hours;

    /// @notice Minimum time between challenges to the same node.
    uint256 public constant CHALLENGE_COOLDOWN = 6 hours;

    /// @notice EIP-712 typehash for challenge responses.
    bytes32 public constant RESPONSE_TYPEHASH = keccak256(
        "ChallengeResponse(uint256 challengeId,bytes32 nodeId,bytes32 responseHash)"
    );

    // ──────────────────────────────────────────────────────────────
    //  Types
    // ──────────────────────────────────────────────────────────────

    enum ChallengeType {
        BandwidthVerification,  // Prove you forwarded traffic correctly
        LivenessCheck,          // Prove you're online and responsive
        PacketIntegrity         // Prove a specific packet was forwarded
    }

    enum ChallengeStatus {
        Active,
        Responded,
        Expired,
        Slashed
    }

    struct Challenge {
        bytes32         nodeId;
        ChallengeType   challengeType;
        address         challenger;
        uint256         issuedAt;
        uint256         deadline;
        ChallengeStatus status;
        bytes32         challengeData;  // type-specific challenge payload hash
    }

    // ──────────────────────────────────────────────────────────────
    //  Immutables
    // ──────────────────────────────────────────────────────────────

    NodeRegistry    public immutable registry;
    SlashingOracle  public immutable oracle;
    bytes32         public immutable DOMAIN_SEPARATOR;

    // ──────────────────────────────────────────────────────────────
    //  State
    // ──────────────────────────────────────────────────────────────

    address public owner;

    mapping(uint256 => Challenge) public challenges;
    uint256 public nextChallengeId;

    /// @dev Last challenge timestamp per node (for cooldown enforcement).
    mapping(bytes32 => uint256) public lastChallenged;

    // ──────────────────────────────────────────────────────────────
    //  Events
    // ──────────────────────────────────────────────────────────────

    event ChallengeIssued(
        uint256 indexed challengeId,
        bytes32 indexed nodeId,
        ChallengeType challengeType,
        address challenger,
        uint256 deadline,
        bytes32 challengeData
    );

    event ChallengeResponded(
        uint256 indexed challengeId,
        bytes32 indexed nodeId,
        bytes32 responseHash
    );

    event ChallengeExpired(
        uint256 indexed challengeId,
        bytes32 indexed nodeId
    );

    // ──────────────────────────────────────────────────────────────
    //  Errors
    // ──────────────────────────────────────────────────────────────

    error NotOwner();
    error NotChallenger();
    error NodeNotActive();
    error CooldownNotElapsed();
    error ChallengeNotFound();
    error ChallengeNotActive();
    error DeadlineNotPassed();
    error InvalidResponse();

    // ──────────────────────────────────────────────────────────────
    //  Modifiers
    // ──────────────────────────────────────────────────────────────

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlyChallenger() {
        if (!oracle.challengers(msg.sender)) revert NotChallenger();
        _;
    }

    // ──────────────────────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────────────────────

    constructor(address _registry, address payable _oracle) {
        require(_registry != address(0) && _oracle != address(0), "ChallengeManager: zero address");
        registry = NodeRegistry(_registry);
        oracle = SlashingOracle(_oracle);
        owner = msg.sender;

        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256("ShieldNode"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
    }

    // ──────────────────────────────────────────────────────────────
    //  Issue challenge
    // ──────────────────────────────────────────────────────────────

    /// @notice Issue a challenge to a specific node.
    /// @param nodeId The node to challenge.
    /// @param challengeType The type of challenge.
    /// @param challengeData Hash of the challenge-specific payload
    ///        (e.g., hash of a packet the node should have forwarded).
    function issueChallenge(
        bytes32 nodeId,
        ChallengeType challengeType,
        bytes32 challengeData
    ) external onlyChallenger returns (uint256 challengeId) {
        if (!registry.isNodeActive(nodeId)) revert NodeNotActive();

        // Enforce cooldown between challenges to the same node.
        if (block.timestamp < lastChallenged[nodeId] + CHALLENGE_COOLDOWN) {
            revert CooldownNotElapsed();
        }

        challengeId = nextChallengeId++;
        uint256 deadline = block.timestamp + RESPONSE_DEADLINE;

        challenges[challengeId] = Challenge({
            nodeId: nodeId,
            challengeType: challengeType,
            challenger: msg.sender,
            issuedAt: block.timestamp,
            deadline: deadline,
            status: ChallengeStatus.Active,
            challengeData: challengeData
        });

        lastChallenged[nodeId] = block.timestamp;

        emit ChallengeIssued(
            challengeId,
            nodeId,
            challengeType,
            msg.sender,
            deadline,
            challengeData
        );
    }

    // ──────────────────────────────────────────────────────────────
    //  Respond to challenge
    // ──────────────────────────────────────────────────────────────

    /// @notice Node responds to a challenge with proof of correct behavior.
    /// @param challengeId The challenge to respond to.
    /// @param responseHash Hash of the response data (type-specific proof).
    /// @param sig Node operator's EIP-712 signature over the response.
    function respondToChallenge(
        uint256 challengeId,
        bytes32 responseHash,
        bytes calldata sig
    ) external {
        Challenge storage c = challenges[challengeId];
        if (c.issuedAt == 0) revert ChallengeNotFound();
        if (c.status != ChallengeStatus.Active) revert ChallengeNotActive();
        if (block.timestamp > c.deadline) revert ChallengeNotActive();

        // Verify the response is signed by the node operator.
        bytes32 structHash = keccak256(
            abi.encode(RESPONSE_TYPEHASH, challengeId, c.nodeId, responseHash)
        );
        bytes32 digest = EIP712Utils.hashTypedData(DOMAIN_SEPARATOR, structHash);
        address signer = EIP712Utils.recoverSigner(digest, sig);

        // Signer must be the node's registered owner.
        INodeRegistry.NodeInfo memory info = registry.getNode(c.nodeId);
        if (signer != info.owner) revert InvalidResponse();

        c.status = ChallengeStatus.Responded;

        emit ChallengeResponded(challengeId, c.nodeId, responseHash);
    }

    // ──────────────────────────────────────────────────────────────
    //  Expire challenge (auto-slash)
    // ──────────────────────────────────────────────────────────────

    /// @notice Mark an unanswered challenge as expired and propose a slash.
    ///         Anyone can call this after the deadline passes.
    /// @param challengeId The expired challenge.
    function expireChallenge(uint256 challengeId) external {
        Challenge storage c = challenges[challengeId];
        if (c.issuedAt == 0) revert ChallengeNotFound();
        if (c.status != ChallengeStatus.Active) revert ChallengeNotActive();
        if (block.timestamp <= c.deadline) revert DeadlineNotPassed();

        c.status = ChallengeStatus.Expired;

        emit ChallengeExpired(challengeId, c.nodeId);

        // The challenger can now use this expiration as evidence
        // for a slash proposal via the SlashingOracle.
        // The actual slash proposal is a separate transaction to keep
        // the challenge-response logic decoupled from slashing.
    }

    // ──────────────────────────────────────────────────────────────
    //  Views
    // ──────────────────────────────────────────────────────────────

    function getChallenge(uint256 challengeId) external view returns (Challenge memory) {
        return challenges[challengeId];
    }

    function isExpired(uint256 challengeId) external view returns (bool) {
        Challenge storage c = challenges[challengeId];
        return c.status == ChallengeStatus.Active && block.timestamp > c.deadline;
    }
}
