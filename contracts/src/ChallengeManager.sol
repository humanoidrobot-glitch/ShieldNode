// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {INodeRegistry}    from "./interfaces/INodeRegistry.sol";
import {ISlashingOracle}  from "./interfaces/ISlashingOracle.sol";
import {NodeRegistry}     from "./NodeRegistry.sol";
import {SlashingOracle}   from "./SlashingOracle.sol";
import {EIP712Utils}      from "./lib/EIP712Utils.sol";

/// @title ChallengeManager
/// @notice Decentralized challenge-response protocol with challenge bonds.
///
///         Anyone can challenge a node by posting a bond. The challenged
///         node has RESPONSE_DEADLINE to respond with a signed proof.
///
///         Outcomes:
///         - Node responds: bond returned to challenger (honest node proved).
///         - Node fails to respond: bond returned + challenger earns a reward
///           from the node's stake via the SlashingOracle.
///         - Frivolous spam: per-challenger-per-node cooldown limits griefing.
///
///         Replaces the trusted challenger multisig from v1.
contract ChallengeManager {
    // ──────────────────────────────────────────────────────────────
    //  Constants
    // ──────────────────────────────────────────────────────────────

    /// @notice Time a node has to respond to a challenge.
    uint256 public constant RESPONSE_DEADLINE = 1 hours;

    /// @notice Minimum time between challenges to the same node by the same challenger.
    uint256 public constant CHALLENGE_COOLDOWN = 6 hours;

    /// @notice Minimum bond required to issue a challenge (0.01 ETH).
    ///         High enough to deter spam, low enough to be accessible.
    uint256 public constant CHALLENGE_BOND = 0.01 ether;

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
        Slashed,
        SlashFailed
    }

    /// @dev Field order optimized for storage packing:
    ///      slot 0: nodeId (32B)
    ///      slot 1: challengeData (32B)
    ///      slot 2: issuedAt (32B)
    ///      slot 3: deadline (32B)
    ///      slot 4: bond (32B)
    ///      slot 5: challenger (20B) + status (1B) + challengeType (1B) = 22B packed
    struct Challenge {
        bytes32         nodeId;
        bytes32         challengeData;
        uint256         issuedAt;
        uint256         deadline;
        uint256         bond;
        address         challenger;
        ChallengeStatus status;
        ChallengeType   challengeType;
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

    mapping(uint256 => Challenge) public challenges;
    uint256 public nextChallengeId;

    /// @dev Last challenge timestamp per challenger per node.
    mapping(bytes32 => mapping(address => uint256)) public lastChallenged;

    /// @notice Pull-payment: credited bond amounts awaiting withdrawal.
    mapping(address => uint256) public pendingWithdrawals;

    /// @dev Reentrancy guard.
    bool private _locked;

    // ──────────────────────────────────────────────────────────────
    //  Events
    // ──────────────────────────────────────────────────────────────

    event ChallengeIssued(
        uint256 indexed challengeId,
        bytes32 indexed nodeId,
        ChallengeType challengeType,
        address challenger,
        uint256 deadline,
        bytes32 challengeData,
        uint256 bond
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

    event BondReturned(
        uint256 indexed challengeId,
        address indexed challenger,
        uint256 amount
    );

    event BondAndRewardPaid(
        uint256 indexed challengeId,
        address indexed challenger,
        uint256 bondReturned,
        uint256 reward
    );

    event SlashProposalFailed(
        uint256 indexed challengeId,
        bytes32 indexed nodeId
    );

    // ──────────────────────────────────────────────────────────────
    //  Errors
    // ──────────────────────────────────────────────────────────────

    error InsufficientBond();
    error NodeNotActive();
    error CooldownNotElapsed();
    error ChallengeNotFound();
    error ChallengeNotActive();
    error DeadlineNotPassed();
    error InvalidResponse();
    error TransferFailed();

    // ──────────────────────────────────────────────────────────────
    //  Modifiers
    // ──────────────────────────────────────────────────────────────

    modifier nonReentrant() {
        require(!_locked, "ChallengeManager: reentrant");
        _locked = true;
        _;
        _locked = false;
    }

    // ──────────────────────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────────────────────

    constructor(address _registry, address payable _oracle) {
        require(_registry != address(0) && _oracle != address(0), "ChallengeManager: zero address");
        registry = NodeRegistry(_registry);
        oracle = SlashingOracle(_oracle);

        DOMAIN_SEPARATOR = EIP712Utils.computeDomainSeparator(address(this));
    }

    // ──────────────────────────────────────────────────────────────
    //  Issue challenge (anyone, with bond)
    // ──────────────────────────────────────────────────────────────

    /// @notice Issue a challenge to a node by posting a bond.
    /// @param nodeId The node to challenge.
    /// @param challengeType The type of challenge.
    /// @param challengeData Hash of the challenge-specific payload.
    function issueChallenge(
        bytes32 nodeId,
        ChallengeType challengeType,
        bytes32 challengeData
    ) external payable returns (uint256 challengeId) {
        if (msg.value < CHALLENGE_BOND) revert InsufficientBond();
        if (!registry.isNodeActive(nodeId)) revert NodeNotActive();

        if (block.timestamp < lastChallenged[nodeId][msg.sender] + CHALLENGE_COOLDOWN) {
            revert CooldownNotElapsed();
        }

        challengeId = nextChallengeId++;
        uint256 deadline = block.timestamp + RESPONSE_DEADLINE;

        challenges[challengeId] = Challenge({
            nodeId: nodeId,
            challengeData: challengeData,
            issuedAt: block.timestamp,
            deadline: deadline,
            bond: msg.value,
            challenger: msg.sender,
            status: ChallengeStatus.Active,
            challengeType: challengeType
        });

        lastChallenged[nodeId][msg.sender] = block.timestamp;

        emit ChallengeIssued(
            challengeId,
            nodeId,
            challengeType,
            msg.sender,
            deadline,
            challengeData,
            msg.value
        );
    }

    // ──────────────────────────────────────────────────────────────
    //  Respond to challenge (returns bond to challenger)
    // ──────────────────────────────────────────────────────────────

    /// @notice Node responds to a challenge. Bond is returned to the
    ///         challenger since the node proved it is honest.
    /// @param challengeId The challenge to respond to.
    /// @param responseHash Hash of the response data.
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

        INodeRegistry.NodeInfo memory info = registry.getNode(c.nodeId);
        if (signer != info.owner) revert InvalidResponse();

        c.status = ChallengeStatus.Responded;

        // Credit bond to challenger via pull-payment — prevents DoS
        // if challenger is a contract that reverts on ETH receive.
        uint256 bondAmount = c.bond;
        c.bond = 0;
        pendingWithdrawals[c.challenger] += bondAmount;

        emit ChallengeResponded(challengeId, c.nodeId, responseHash);
        emit BondReturned(challengeId, c.challenger, bondAmount);
    }

    // ──────────────────────────────────────────────────────────────
    //  Expire challenge (auto-slash, reward challenger)
    // ──────────────────────────────────────────────────────────────

    /// @notice Mark an unanswered challenge as expired. The challenger's
    ///         bond is returned and they earn a reward (paid from this
    ///         contract's balance — funded by future slash integrations).
    ///
    ///         Anyone can call this after the deadline passes.
    /// @param challengeId The expired challenge.
    function expireChallenge(uint256 challengeId) external {
        Challenge storage c = challenges[challengeId];
        if (c.issuedAt == 0) revert ChallengeNotFound();
        if (c.status != ChallengeStatus.Active) revert ChallengeNotActive();
        if (block.timestamp <= c.deadline) revert DeadlineNotPassed();

        uint256 bondAmount = c.bond;
        c.bond = 0;
        pendingWithdrawals[c.challenger] += bondAmount;

        emit ChallengeExpired(challengeId, c.nodeId);
        emit BondAndRewardPaid(challengeId, c.challenger, bondAmount, 0);

        // Propose slash via the oracle. Status depends on success.
        bytes memory evidence = abi.encode(challengeId);
        try oracle.proposeSlash(c.nodeId, uint8(ISlashingOracle.SlashReason.ChallengeFailure), evidence) {
            c.status = ChallengeStatus.Slashed;
        } catch {
            c.status = ChallengeStatus.SlashFailed;
            emit SlashProposalFailed(challengeId, c.nodeId);
        }
    }

    /// @notice Retry a failed slash proposal. Only callable on challenges
    ///         in SlashFailed status (oracle was unavailable at expire time).
    function retrySlash(uint256 challengeId) external {
        Challenge storage c = challenges[challengeId];
        if (c.issuedAt == 0) revert ChallengeNotFound();
        require(c.status == ChallengeStatus.SlashFailed, "ChallengeManager: not SlashFailed");

        bytes memory evidence = abi.encode(challengeId);
        try oracle.proposeSlash(c.nodeId, uint8(ISlashingOracle.SlashReason.ChallengeFailure), evidence) {
            c.status = ChallengeStatus.Slashed;
        } catch {
            emit SlashProposalFailed(challengeId, c.nodeId);
        }
    }

    // ──────────────────────────────────────────────────────────────
    //  Pull-payment withdrawal
    // ──────────────────────────────────────────────────────────────

    /// @notice Withdraw credited bond payments.
    function withdraw() external nonReentrant {
        uint256 amount = pendingWithdrawals[msg.sender];
        require(amount > 0, "ChallengeManager: nothing to withdraw");
        pendingWithdrawals[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        if (!ok) revert TransferFailed();
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

    /// @notice Check if a challenger can issue a new challenge to a node.
    function canChallenge(bytes32 nodeId, address _challenger) external view returns (bool) {
        if (!registry.isNodeActive(nodeId)) return false;
        return block.timestamp >= lastChallenged[nodeId][_challenger] + CHALLENGE_COOLDOWN;
    }

    receive() external payable {}
}
