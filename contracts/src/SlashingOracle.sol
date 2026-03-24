// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISlashingOracle} from "./interfaces/ISlashingOracle.sol";
import {INodeRegistry}   from "./interfaces/INodeRegistry.sol";
import {NodeRegistry}    from "./NodeRegistry.sol";

/// @title SlashingOracle
/// @notice Manages slash proposals, grace periods, progressive penalties, and
///         distributes slashed stake between the challenger and the treasury.
contract SlashingOracle is ISlashingOracle {
    // ──────────────────────────────────────────────────────────────
    //  Constants
    // ──────────────────────────────────────────────────────────────

    /// @notice Grace period before a proposal can be executed.
    uint256 public constant GRACE_PERIOD = 24 hours;

    /// @notice Slash percentages by offence count.
    ///         First = 10 %, second = 25 %, third+ = 100 %.
    uint256 private constant SLASH_PCT_FIRST  = 10;
    uint256 private constant SLASH_PCT_SECOND = 25;
    uint256 private constant SLASH_PCT_THIRD  = 100;

    /// @notice Reward split: 50 % to challenger, 50 % to treasury.
    uint256 private constant CHALLENGER_SHARE = 50;

    // ──────────────────────────────────────────────────────────────
    //  Immutables
    // ──────────────────────────────────────────────────────────────

    /// @notice The NodeRegistry this oracle operates on.
    NodeRegistry public immutable registry;

    /// @notice Treasury that receives its share of slashed funds.
    address public immutable treasury;

    // ──────────────────────────────────────────────────────────────
    //  State
    // ──────────────────────────────────────────────────────────────

    /// @notice Contract owner.
    address public owner;

    /// @notice Authorised challengers.
    mapping(address => bool) public challengers;

    /// @dev Proposal storage.
    struct Proposal {
        bytes32     nodeId;
        SlashReason reason;
        bytes       evidence;
        address     challenger;
        uint256     createdAt;
        bool        executed;
    }

    mapping(uint256 => Proposal) public proposals;
    uint256 public nextProposalId;

    // ──────────────────────────────────────────────────────────────
    //  Events (supplementary -- interface events are inherited)
    // ──────────────────────────────────────────────────────────────

    event ChallengerUpdated(address indexed challenger, bool authorised);

    // ──────────────────────────────────────────────────────────────
    //  Modifiers
    // ──────────────────────────────────────────────────────────────

    modifier onlyOwner() {
        require(msg.sender == owner, "SlashingOracle: not owner");
        _;
    }

    modifier onlyChallenger() {
        require(challengers[msg.sender], "SlashingOracle: not challenger");
        _;
    }

    // ──────────────────────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────────────────────

    /// @param _registry Address of the NodeRegistry.
    /// @param _treasury Address of the Treasury.
    constructor(address _registry, address _treasury) {
        require(_registry != address(0), "SlashingOracle: zero registry");
        require(_treasury != address(0), "SlashingOracle: zero treasury");
        registry = NodeRegistry(_registry);
        treasury = _treasury;
        owner = msg.sender;
    }

    // ──────────────────────────────────────────────────────────────
    //  Admin
    // ──────────────────────────────────────────────────────────────

    /// @notice Add or remove an authorised challenger.
    /// @param challenger The address to update.
    /// @param authorised Whether the address is authorised.
    function setChallenger(address challenger, bool authorised) external onlyOwner {
        challengers[challenger] = authorised;
        emit ChallengerUpdated(challenger, authorised);
    }

    // ──────────────────────────────────────────────────────────────
    //  Proposal lifecycle
    // ──────────────────────────────────────────────────────────────

    /// @inheritdoc ISlashingOracle
    function proposeSlash(
        bytes32 nodeId,
        uint8 reason,
        bytes calldata evidence
    ) external override onlyChallenger {
        require(reason <= uint8(SlashReason.BandwidthFraud), "SlashingOracle: bad reason");

        uint256 proposalId = nextProposalId++;

        proposals[proposalId] = Proposal({
            nodeId:     nodeId,
            reason:     SlashReason(reason),
            evidence:   evidence,
            challenger: msg.sender,
            createdAt:  block.timestamp,
            executed:   false
        });

        emit SlashProposed(proposalId, nodeId, msg.sender, SlashReason(reason));
    }

    /// @inheritdoc ISlashingOracle
    function executeSlash(uint256 proposalId) external override {
        Proposal storage p = proposals[proposalId];
        require(p.createdAt != 0, "SlashingOracle: unknown proposal");
        require(!p.executed, "SlashingOracle: already executed");
        require(
            block.timestamp >= p.createdAt + GRACE_PERIOD,
            "SlashingOracle: grace period"
        );

        p.executed = true;

        // Determine slash percentage based on the node's current slash count.
        INodeRegistry.NodeInfo memory info = registry.getNode(p.nodeId);
        uint256 pct;
        if (info.slashCount == 0) {
            pct = SLASH_PCT_FIRST;
        } else if (info.slashCount == 1) {
            pct = SLASH_PCT_SECOND;
        } else {
            pct = SLASH_PCT_THIRD;
        }

        uint256 slashAmount = (info.stake * pct) / 100;

        // Call the registry to slash (funds are sent back to this contract).
        registry.slash(p.nodeId, slashAmount);

        // If third offence (slashCount was 2 before this slash), permanently ban.
        if (info.slashCount >= 2) {
            registry.ban(p.nodeId);
        }

        // Distribute: 50 % challenger, 50 % treasury.
        uint256 challengerReward = (slashAmount * CHALLENGER_SHARE) / 100;
        uint256 treasuryReward   = slashAmount - challengerReward;

        if (challengerReward > 0) {
            (bool ok1, ) = p.challenger.call{value: challengerReward}("");
            require(ok1, "SlashingOracle: challenger transfer failed");
        }
        if (treasuryReward > 0) {
            (bool ok2, ) = treasury.call{value: treasuryReward}("");
            require(ok2, "SlashingOracle: treasury transfer failed");
        }

        emit SlashExecuted(proposalId, p.nodeId, slashAmount);
    }

    /// @notice Accept ETH from the registry during slashing.
    receive() external payable {}
}
