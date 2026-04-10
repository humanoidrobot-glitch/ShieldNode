// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {INodeRegistry} from "./interfaces/INodeRegistry.sol";
import {SlashingOracle} from "./SlashingOracle.sol";
import {SessionSettlement} from "./SessionSettlement.sol";

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

    /// @notice Maximum allowed price per byte (prevents overflow in settlement).
    uint256 public constant MAX_PRICE_PER_BYTE = 1e12;

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

    /// @dev Permanent slash count — survives withdrawStake/re-registration.
    mapping(bytes32 => uint256) public permanentSlashCount;

    /// @dev Permanent ban — survives withdrawStake.
    mapping(bytes32 => bool) public permanentBan;

    /// @dev Owner-level slash count — prevents re-registering with new nodeId
    ///      to reset progressive penalties.
    mapping(address => uint256) public permanentSlashCountByOwner;

    /// @dev Ordered list of every node ID that has been registered (including
    ///      deregistered ones; filtering is done at read time).
    bytes32[] private _allNodeIds;

    /// @dev Tracks whether a nodeId has ever been added to _allNodeIds,
    ///      preventing duplicate entries on re-registration.
    mapping(bytes32 => bool) private _everRegistered;

    /// @dev Separate array of currently-active node IDs for O(n) pagination
    ///      where n = active count (not total ever-registered).
    bytes32[] private _activeNodeIds;

    /// @dev Index of a nodeId within _activeNodeIds (1-indexed; 0 = not in array).
    mapping(bytes32 => uint256) private _activeIndex;

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

    /// @dev Reentrancy guard.
    bool private _locked;

    modifier nonReentrant() {
        require(!_locked, "NodeRegistry: reentrant");
        _locked = true;
        _;
        _locked = false;
    }

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
        string calldata endpoint,
        bytes calldata secp256k1Key
    ) external payable override {
        require(_nodes[nodeId].owner == address(0), "NodeRegistry: already registered");
        require(!permanentBan[nodeId], "NodeRegistry: permanently banned");
        require(permanentSlashCountByOwner[msg.sender] < 3, "NodeRegistry: owner permanently banned");
        require(msg.value >= MINIMUM_STAKE, "NodeRegistry: insufficient stake");
        require(nodeId != bytes32(0), "NodeRegistry: zero nodeId");
        require(publicKey != bytes32(0), "NodeRegistry: zero publicKey");
        require(bytes(endpoint).length > 0, "NodeRegistry: empty endpoint");
        // Bind nodeId to registrant to prevent namespace squatting.
        require(
            nodeId == keccak256(abi.encode(msg.sender, publicKey)),
            "NodeRegistry: nodeId not derived from sender+pubkey"
        );
        // Verify secp256k1 key belongs to the sender.
        require(secp256k1Key.length == 64, "NodeRegistry: secp256k1 key must be 64 bytes");
        require(
            address(uint160(uint256(keccak256(secp256k1Key)))) == msg.sender,
            "NodeRegistry: secp256k1 key does not match sender"
        );

        _nodes[nodeId] = NodeInfo({
            owner:         msg.sender,
            publicKey:     publicKey,
            endpoint:      endpoint,
            stake:         msg.value,
            registeredAt:  block.timestamp,
            lastHeartbeat: block.timestamp,
            slashCount:    permanentSlashCountByOwner[msg.sender],
            isActive:      true,
            pricePerByte:  0,
            commitment:    bytes32(0),
            secp256k1X:    bytes32(secp256k1Key[:32]),
            secp256k1Y:    bytes32(secp256k1Key[32:64])
        });

        if (!_everRegistered[nodeId]) {
            _everRegistered[nodeId] = true;
            _allNodeIds.push(nodeId);
        }
        _addActive(nodeId);

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
        _removeActive(nodeId);

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
        // Block withdrawal if slash proposals are pending against this node.
        require(
            SlashingOracle(payable(slashingOracle)).pendingSlashCount(nodeId) == 0,
            "NodeRegistry: pending slash"
        );
        // Block withdrawal if node has open (unsettled) sessions.
        address _settlement = SlashingOracle(payable(slashingOracle)).settlement();
        require(
            SessionSettlement(payable(_settlement)).openSessionCount(nodeId) == 0,
            "NodeRegistry: open sessions"
        );

        uint256 amount = _nodes[nodeId].stake;
        require(amount > 0, "NodeRegistry: nothing to withdraw");

        // Effects — delete before transfer (checks-effects-interactions).
        // permanentSlashCount and permanentBan are NOT deleted — they persist.
        _removeActive(nodeId);
        delete _nodes[nodeId];
        delete deregisteredAt[nodeId];
        delete banned[nodeId]; // session-scoped flag; permanentBan survives

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
        require(newPrice <= MAX_PRICE_PER_BYTE, "NodeRegistry: price too high");
        _nodes[nodeId].pricePerByte = newPrice;
    }

    /// @notice Add more stake to an active node without deregistering.
    /// @param nodeId The node to top up.
    function topUpStake(bytes32 nodeId) external payable onlyNodeOwner(nodeId) {
        require(_nodes[nodeId].isActive, "NodeRegistry: not active");
        require(msg.value > 0, "NodeRegistry: zero top-up");
        _nodes[nodeId].stake += msg.value;
        emit StakeUpdated(nodeId, _nodes[nodeId].stake);
    }

    /// @notice Set or update the ZK eligibility commitment for a node.
    ///         Prepares the node for Phase 6 commitment-based proofs.
    /// @param nodeId     The node to update.
    /// @param commitment The Poseidon commitment hash (or bytes32(0) to clear).
    function setCommitment(bytes32 nodeId, bytes32 commitment) external onlyNodeOwner(nodeId) {
        require(_nodes[nodeId].isActive, "NodeRegistry: not active");
        _nodes[nodeId].commitment = commitment;
        emit CommitmentUpdated(nodeId, commitment);
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
        // Iterate _activeNodeIds (much smaller than _allNodeIds for mature
        // registries), filtering only for heartbeat freshness.
        uint256 total = _activeNodeIds.length;
        uint256 activeCount;
        for (uint256 i; i < total; ++i) {
            if (_isHeartbeatFresh(_activeNodeIds[i])) {
                ++activeCount;
            }
        }

        if (offset >= activeCount) {
            return new bytes32[](0);
        }

        uint256 remaining = activeCount - offset;
        uint256 size = limit < remaining ? limit : remaining;
        nodeIds = new bytes32[](size);

        uint256 seen;
        uint256 filled;
        for (uint256 i; i < total && filled < size; ++i) {
            if (_isHeartbeatFresh(_activeNodeIds[i])) {
                if (seen >= offset) {
                    nodeIds[filled] = _activeNodeIds[i];
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
    /// @param nodeId  The node to slash.
    /// @param amount  The amount of ETH to slash from the node's stake.
    /// @param isFraud True for fraud slashes; false for liveness. Only fraud
    ///                increments the owner-level counter toward permanent ban.
    function slash(bytes32 nodeId, uint256 amount, bool isFraud) external onlyOracle nonReentrant {
        NodeInfo storage node = _nodes[nodeId];
        require(node.owner != address(0), "NodeRegistry: node not found");
        require(amount > 0, "NodeRegistry: zero slash");

        uint256 actual = amount > node.stake ? node.stake : amount;

        // Effects
        node.stake -= actual;
        node.slashCount += 1;
        permanentSlashCount[nodeId] = node.slashCount;
        if (isFraud) {
            permanentSlashCountByOwner[node.owner] += 1;
        }

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
        permanentBan[nodeId] = true;
        _removeActive(nodeId);
    }

    /// @notice Deactivate a node due to repeated liveness failures.
    ///         Starts the unstake cooldown so the operator can withdraw and
    ///         re-register. Not a permanent ban.
    /// @param nodeId The node to deactivate.
    function deactivateForLiveness(bytes32 nodeId) external onlyOracle {
        address nodeOwner = _nodes[nodeId].owner;
        require(nodeOwner != address(0), "NodeRegistry: node not found");
        _nodes[nodeId].isActive = false;
        deregisteredAt[nodeId] = block.timestamp;
        _removeActive(nodeId);

        emit NodeDeregistered(nodeId, nodeOwner);
    }

    // ──────────────────────────────────────────────────────────────
    //  Internal helpers
    // ──────────────────────────────────────────────────────────────

    /// @dev Add a nodeId to the _activeNodeIds set.
    function _addActive(bytes32 nodeId) internal {
        if (_activeIndex[nodeId] == 0) {
            _activeNodeIds.push(nodeId);
            _activeIndex[nodeId] = _activeNodeIds.length; // 1-indexed
        }
    }

    /// @dev Remove a nodeId from the _activeNodeIds set (swap-and-pop).
    function _removeActive(bytes32 nodeId) internal {
        uint256 idx = _activeIndex[nodeId];
        if (idx == 0) return; // not in array
        uint256 lastIdx = _activeNodeIds.length;
        if (idx != lastIdx) {
            bytes32 lastId = _activeNodeIds[lastIdx - 1];
            _activeNodeIds[idx - 1] = lastId;
            _activeIndex[lastId] = idx;
        }
        _activeNodeIds.pop();
        delete _activeIndex[nodeId];
    }

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
