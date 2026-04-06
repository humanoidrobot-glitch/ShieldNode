// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title INodeRegistry
/// @notice Interface for the ShieldNode decentralized VPN node registry.
interface INodeRegistry {
    // ──────────────────────────────────────────────────────────────
    //  Structs
    // ──────────────────────────────────────────────────────────────

    /// @notice Full on-chain metadata for a registered node.
    struct NodeInfo {
        address owner;
        bytes32 publicKey;
        string  endpoint;
        uint256 stake;
        uint256 registeredAt;
        uint256 lastHeartbeat;
        uint256 slashCount;
        bool    isActive;
        uint256 pricePerByte;
        bytes32 commitment;       // reserved for Phase-6 ZK eligibility
    }

    // ──────────────────────────────────────────────────────────────
    //  Events
    // ──────────────────────────────────────────────────────────────

    /// @notice Emitted when a new node is registered.
    event NodeRegistered(
        bytes32 indexed nodeId,
        address indexed owner,
        bytes32 indexed publicKey,
        string  endpoint,
        uint256 stake
    );

    /// @notice Emitted when a node is deregistered (begins unstake cooldown).
    event NodeDeregistered(bytes32 indexed nodeId, address indexed owner);

    /// @notice Emitted on a successful heartbeat.
    event HeartbeatReceived(bytes32 indexed nodeId, uint256 timestamp);

    /// @notice Emitted when a node's endpoint changes.
    event EndpointUpdated(bytes32 indexed nodeId, string newEndpoint);

    /// @notice Emitted when stake changes (slash or top-up).
    event StakeUpdated(bytes32 indexed nodeId, uint256 newStake);

    // ──────────────────────────────────────────────────────────────
    //  External / Public functions
    // ──────────────────────────────────────────────────────────────

    /// @notice Register a new VPN node with the given id and public key.
    /// @param nodeId     Unique identifier for the node.
    /// @param publicKey  Curve25519 public key used by clients.
    /// @param endpoint   WireGuard endpoint (host:port).
    function register(
        bytes32 nodeId,
        bytes32 publicKey,
        string calldata endpoint
    ) external payable;

    /// @notice Deregister a node and begin the unstake cooldown.
    /// @param nodeId The node to deregister.
    function deregister(bytes32 nodeId) external;

    /// @notice Send a heartbeat to prove liveness.
    /// @param nodeId The node sending the heartbeat.
    function heartbeat(bytes32 nodeId) external;

    /// @notice Update the WireGuard endpoint of a node.
    /// @param nodeId      The node to update.
    /// @param newEndpoint The new endpoint string.
    function updateEndpoint(bytes32 nodeId, string calldata newEndpoint) external;

    /// @notice Retrieve full metadata for a node.
    /// @param nodeId The node to query.
    /// @return info The NodeInfo struct.
    function getNode(bytes32 nodeId) external view returns (NodeInfo memory info);

    /// @notice Paginated list of currently-active node IDs.
    /// @param offset Start index.
    /// @param limit  Maximum number of IDs to return.
    /// @return nodeIds Array of active node IDs.
    function getActiveNodes(uint256 offset, uint256 limit)
        external
        view
        returns (bytes32[] memory nodeIds);

    /// @notice Check whether a node qualifies as active (fresh heartbeat, not slashed out).
    /// @param nodeId The node to check.
    /// @return active True if the node is currently active.
    function isNodeActive(bytes32 nodeId) external view returns (bool active);

    /// @notice Deactivate a node due to repeated liveness failures.
    ///         Not a permanent ban — the operator can withdraw after cooldown
    ///         and re-register.
    /// @param nodeId The node to deactivate.
    function deactivateForLiveness(bytes32 nodeId) external;
}
