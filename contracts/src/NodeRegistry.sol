// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {INodeRegistry} from "./interfaces/INodeRegistry.sol";

/// @title NodeRegistry
/// @notice On-chain registry of ShieldNode VPN operators.  Handles staking,
///         heartbeats, endpoint management, and stake slashing.
contract NodeRegistry is INodeRegistry {
    // ──────────────────────────────────────────────────────────────
    //  Constants
    // ──────────────────────────────────────────────────────────────

    /// @notice Minimum ETH that must be staked to register a node.
    uint256 public constant MINIMUM_STAKE = 0.1 ether;

    /// @notice Maximum interval between heartbeats before a node is stale.
    uint256 public constant HEARTBEAT_INTERVAL = 6 hours;

    /// @notice Number of consecutive missed heartbeat windows that mark a node
    ///         as inactive.
    uint256 public constant MAX_MISSED_HEARTBEATS = 3;

    /// @notice Cooldown between deregistration and stake withdrawal.
    uint256 public constant UNSTAKE_COOLDOWN = 7 days;

    // ──────────────────────────────────────────────────────────────
    //  Immutables
    // ──────────────────────────────────────────────────────────────

    /// @notice Address of the SlashingOracle authorised to slash nodes.
    address public immutable slashingOracle;

    // ──────────────────────────────────────────────────────────────
    //  Storage
    // ──────────────────────────────────────────────────────────────

    /// @dev nodeId -> NodeInfo
    mapping(bytes32 => NodeInfo) private _nodes;

    /// @dev nodeId -> timestamp when deregistration was requested (0 = not requested)
    mapping(bytes32 => uint256) public deregisteredAt;

    /// @dev nodeId -> permanently banned flag
    mapping(bytes32 => bool) public banned;

    /// @dev Ordered list of every node ID that has been registered (including
    ///      deregistered ones; filtering is done at read time).
    bytes32[] private _allNodeIds;

    // ──────────────────────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────────────────────

    /// @param _slashingOracle Address of the deployed SlashingOracle contract.
    constructor(address _slashingOracle) {
        require(_slashingOracle != address(0), "NodeRegistry: zero oracle");
        slashingOracle = _slashingOracle;
    }

    // ──────────────────────────────────────────────────────────────
    //  Modifiers
    // ──────────────────────────────────────────────────────────────

    /// @dev Restrict a call to the node's owner.
    modifier onlyNodeOwner(bytes32 nodeId) {
        require(_nodes[nodeId].owner == msg.sender, "NodeRegistry: not node owner");
        _;
    }

    /// @dev Restrict a call to the SlashingOracle.
    modifier onlyOracle() {
        require(msg.sender == slashingOracle, "NodeRegistry: not oracle");
        _;
    }

    // ──────────────────────────────────────────────────────────────
    //  Registration
    // ──────────────────────────────────────────────────────────────

    /// @inheritdoc INodeRegistry
    function register(
        bytes32 nodeId,
        bytes32 publicKey,
        string calldata endpoint
    ) external payable override {
        require(_nodes[nodeId].owner == address(0), "NodeRegistry: already registered");
        require(msg.value >= MINIMUM_STAKE, "NodeRegistry: insufficient stake");
        require(nodeId != bytes32(0), "NodeRegistry: zero nodeId");
        require(publicKey != bytes32(0), "NodeRegistry: zero publicKey");
        require(bytes(endpoint).length > 0, "NodeRegistry: empty endpoint");

        _nodes[nodeId] = NodeInfo({
            owner:         msg.sender,
            publicKey:     publicKey,
            endpoint:      endpoint,
            stake:         msg.value,
            registeredAt:  block.timestamp,
            lastHeartbeat: block.timestamp,
            slashCount:    0,
            isActive:      true,
            pricePerByte:  0,
            commitment:    bytes32(0)
        });

        _allNodeIds.push(nodeId);

        emit NodeRegistered(nodeId, msg.sender, publicKey, endpoint, msg.value);
    }

    // ──────────────────────────────────────────────────────────────
    //  Deregistration & Withdrawal
    // ──────────────────────────────────────────────────────────────

    /// @inheritdoc INodeRegistry
    function deregister(bytes32 nodeId) external override onlyNodeOwner(nodeId) {
        require(_nodes[nodeId].isActive, "NodeRegistry: not active");

        // Effects
        _nodes[nodeId].isActive = false;
        deregisteredAt[nodeId] = block.timestamp;

        emit NodeDeregistered(nodeId, msg.sender);
    }

    /// @notice Withdraw staked ETH after the unstake cooldown has elapsed.
    /// @param nodeId The deregistered node whose stake to withdraw.
    function withdrawStake(bytes32 nodeId) external onlyNodeOwner(nodeId) {
        uint256 deregTs = deregisteredAt[nodeId];
        require(deregTs != 0, "NodeRegistry: not deregistered");
        require(
            block.timestamp >= deregTs + UNSTAKE_COOLDOWN,
            "NodeRegistry: cooldown not passed"
        );

        uint256 amount = _nodes[nodeId].stake;
        require(amount > 0, "NodeRegistry: nothing to withdraw");

        // Effects — delete before transfer (checks-effects-interactions)
        delete _nodes[nodeId];
        delete deregisteredAt[nodeId];
        delete banned[nodeId];

        // Interaction
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "NodeRegistry: ETH transfer failed");
    }

    // ──────────────────────────────────────────────────────────────
    //  Heartbeat
    // ──────────────────────────────────────────────────────────────

    /// @inheritdoc INodeRegistry
    function heartbeat(bytes32 nodeId) external override onlyNodeOwner(nodeId) {
        require(_nodes[nodeId].isActive, "NodeRegistry: not active");

        _nodes[nodeId].lastHeartbeat = block.timestamp;

        emit HeartbeatReceived(nodeId, block.timestamp);
    }

    // ──────────────────────────────────────────────────────────────
    //  Endpoint & Pricing
    // ──────────────────────────────────────────────────────────────

    /// @inheritdoc INodeRegistry
    function updateEndpoint(
        bytes32 nodeId,
        string calldata newEndpoint
    ) external override onlyNodeOwner(nodeId) {
        require(bytes(newEndpoint).length > 0, "NodeRegistry: empty endpoint");

        _nodes[nodeId].endpoint = newEndpoint;

        emit EndpointUpdated(nodeId, newEndpoint);
    }

    /// @notice Let a node operator set a custom per-byte price.
    /// @param nodeId       The node to update.
    /// @param newPrice     New price in wei per byte.
    function updatePricePerByte(
        bytes32 nodeId,
        uint256 newPrice
    ) external onlyNodeOwner(nodeId) {
        _nodes[nodeId].pricePerByte = newPrice;
    }

    /// @notice Add more stake to an active node without deregistering.
    function topUpStake(bytes32 nodeId) external payable onlyNodeOwner(nodeId) {
        require(_nodes[nodeId].isActive, "NodeRegistry: not active");
        require(msg.value > 0, "NodeRegistry: zero top-up");
        _nodes[nodeId].stake += msg.value;
        emit StakeUpdated(nodeId, _nodes[nodeId].stake);
    }

    // ──────────────────────────────────────────────────────────────
    //  Views
    // ──────────────────────────────────────────────────────────────

    /// @inheritdoc INodeRegistry
    function getNode(bytes32 nodeId) external view override returns (NodeInfo memory) {
        return _nodes[nodeId];
    }

    /// @inheritdoc INodeRegistry
    function getActiveNodes(
        uint256 offset,
        uint256 limit
    ) external view override returns (bytes32[] memory nodeIds) {
        // First pass: count actives to size the output array.
        uint256 total = _allNodeIds.length;
        uint256 activeCount;
        for (uint256 i; i < total; ++i) {
            if (_isActive(_allNodeIds[i])) {
                ++activeCount;
            }
        }

        if (offset >= activeCount) {
            return new bytes32[](0);
        }

        uint256 remaining = activeCount - offset;
        uint256 size = limit < remaining ? limit : remaining;
        nodeIds = new bytes32[](size);

        // Second pass: fill the page.
        uint256 seen;
        uint256 filled;
        for (uint256 i; i < total && filled < size; ++i) {
            if (_isActive(_allNodeIds[i])) {
                if (seen >= offset) {
                    nodeIds[filled] = _allNodeIds[i];
                    ++filled;
                }
                ++seen;
            }
        }
    }

    /// @inheritdoc INodeRegistry
    function isNodeActive(bytes32 nodeId) external view override returns (bool) {
        return _isActive(nodeId);
    }

    // ──────────────────────────────────────────────────────────────
    //  Slashing (callable only by SlashingOracle)
    // ──────────────────────────────────────────────────────────────

    /// @notice Slash a node's stake.  Only the SlashingOracle may call this.
    /// @param nodeId The node to slash.
    /// @param amount The amount of ETH to slash from the node's stake.
    function slash(bytes32 nodeId, uint256 amount) external onlyOracle {
        NodeInfo storage node = _nodes[nodeId];
        require(node.owner != address(0), "NodeRegistry: node not found");

        uint256 actual = amount > node.stake ? node.stake : amount;

        // Effects
        node.stake -= actual;
        node.slashCount += 1;

        emit StakeUpdated(nodeId, node.stake);

        // Interaction — send slashed ETH to the oracle (it handles distribution)
        (bool ok, ) = msg.sender.call{value: actual}("");
        require(ok, "NodeRegistry: slash transfer failed");
    }

    /// @notice Permanently ban a node (called by SlashingOracle on third offence).
    /// @param nodeId The node to ban.
    function ban(bytes32 nodeId) external onlyOracle {
        _nodes[nodeId].isActive = false;
        banned[nodeId] = true;
    }

    // ──────────────────────────────────────────────────────────────
    //  Internal helpers
    // ──────────────────────────────────────────────────────────────

    /// @dev Returns true when a node's heartbeat is fresh enough.
    function _isHeartbeatFresh(bytes32 nodeId) internal view returns (bool) {
        uint256 deadline = _nodes[nodeId].lastHeartbeat +
            (HEARTBEAT_INTERVAL * MAX_MISSED_HEARTBEATS);
        return block.timestamp <= deadline;
    }

    /// @dev Consolidated active check: registered, flagged active, heartbeat
    ///      fresh, and not banned.
    function _isActive(bytes32 nodeId) internal view returns (bool) {
        NodeInfo storage n = _nodes[nodeId];
        return n.isActive && n.owner != address(0) && _isHeartbeatFresh(nodeId) && !banned[nodeId];
    }
}
