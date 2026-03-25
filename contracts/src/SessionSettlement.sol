// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISessionSettlement} from "./interfaces/ISessionSettlement.sol";
import {INodeRegistry}      from "./interfaces/INodeRegistry.sol";
import {NodeRegistry}       from "./NodeRegistry.sol";
import {EIP712Utils}        from "./lib/EIP712Utils.sol";

/// @title SessionSettlement
/// @notice Opens, cooperatively settles, and force-settles 3-hop VPN sessions.
///         Payment is split across entry (25 %), relay (25 %), and exit (50 %)
///         nodes.  Uses EIP-712 typed signatures for bandwidth receipts.
contract SessionSettlement is ISessionSettlement {
    // ──────────────────────────────────────────────────────────────
    //  Constants
    // ──────────────────────────────────────────────────────────────

    /// @notice Minimum ETH deposit to open a session.
    uint256 public constant MINIMUM_DEPOSIT = 0.001 ether;

    /// @notice Time after session start before a node may force-settle.
    uint256 public constant FORCE_SETTLE_TIMEOUT = 1 hours;

    /// @notice Payment split (basis points out of 100).
    uint256 public constant ENTRY_SHARE = 25;
    uint256 public constant RELAY_SHARE = 25;
    uint256 public constant EXIT_SHARE  = 50;

    // ──────────────────────────────────────────────────────────────
    //  EIP-712
    // ──────────────────────────────────────────────────────────────

    bytes32 public constant RECEIPT_TYPEHASH = EIP712Utils.RECEIPT_TYPEHASH;

    bytes32 public immutable DOMAIN_SEPARATOR;

    // ──────────────────────────────────────────────────────────────
    //  Immutables
    // ──────────────────────────────────────────────────────────────

    /// @notice Reference to the NodeRegistry for node-activity checks.
    NodeRegistry public immutable nodeRegistry;

    // ──────────────────────────────────────────────────────────────
    //  State
    // ──────────────────────────────────────────────────────────────

    /// @notice Auto-incrementing session counter.
    uint256 public nextSessionId;

    /// @dev sessionId -> SessionInfo
    mapping(uint256 => SessionInfo) private _sessions;

    // ──────────────────────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────────────────────

    /// @param _nodeRegistry Address of the deployed NodeRegistry.
    constructor(address _nodeRegistry) {
        require(_nodeRegistry != address(0), "Session: zero registry");
        nodeRegistry = NodeRegistry(_nodeRegistry);

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
    //  Open session
    // ──────────────────────────────────────────────────────────────

    /// @inheritdoc ISessionSettlement
    function openSession(bytes32[3] calldata nodeIds) external payable override {
        require(msg.value >= MINIMUM_DEPOSIT, "Session: deposit too low");

        // All three nodes must be active.
        for (uint256 i; i < 3; ++i) {
            require(
                nodeRegistry.isNodeActive(nodeIds[i]),
                "Session: node not active"
            );
        }

        uint256 sessionId = nextSessionId++;

        _sessions[sessionId] = SessionInfo({
            client:          msg.sender,
            nodeIds:         nodeIds,
            deposit:         msg.value,
            startBlock:      block.number,
            settled:         false,
            cumulativeBytes: 0
        });

        emit SessionOpened(sessionId, msg.sender, nodeIds, msg.value);
    }

    // ──────────────────────────────────────────────────────────────
    //  Cooperative settle
    // ──────────────────────────────────────────────────────────────

    /// @inheritdoc ISessionSettlement
    function settleSession(
        uint256 sessionId,
        bytes calldata signedReceipt
    ) external override {
        SessionInfo storage s = _sessions[sessionId];
        require(s.client != address(0), "Session: unknown");
        require(!s.settled, "Session: already settled");

        // Decode receipt: (sessionId, cumulativeBytes, timestamp, clientSig, nodeSig)
        (
            uint256 rSessionId,
            uint256 cumulativeBytes,
            uint256 timestamp,
            bytes memory clientSig,
            bytes memory nodeSig
        ) = abi.decode(signedReceipt, (uint256, uint256, uint256, bytes, bytes));

        require(rSessionId == sessionId, "Session: id mismatch");

        bytes32 structHash = EIP712Utils.receiptStructHash(rSessionId, cumulativeBytes, timestamp);
        bytes32 digest = EIP712Utils.hashTypedData(DOMAIN_SEPARATOR, structHash);

        // Verify client signature.
        address clientSigner = EIP712Utils.recoverSigner(digest, clientSig);
        require(clientSigner == s.client, "Session: bad client sig");

        // Verify node signature (exit node signs on behalf of the circuit).
        INodeRegistry.NodeInfo memory exitNode = nodeRegistry.getNode(s.nodeIds[2]);
        address nodeSigner = EIP712Utils.recoverSigner(digest, nodeSig);
        require(nodeSigner == exitNode.owner, "Session: bad node sig");

        _settle(sessionId, s, cumulativeBytes);
    }

    // ──────────────────────────────────────────────────────────────
    //  Force settle (node-initiated after timeout)
    // ──────────────────────────────────────────────────────────────

    /// @inheritdoc ISessionSettlement
    function forceSettle(
        uint256 sessionId,
        bytes calldata signedReceipt
    ) external override {
        SessionInfo storage s = _sessions[sessionId];
        require(s.client != address(0), "Session: unknown");
        require(!s.settled, "Session: already settled");
        require(
            block.timestamp >= s.startBlock + FORCE_SETTLE_TIMEOUT,
            "Session: too early"
        );

        // Caller must be the owner of one of the three session nodes.
        bool isNode;
        for (uint256 i; i < 3; ++i) {
            INodeRegistry.NodeInfo memory info = nodeRegistry.getNode(s.nodeIds[i]);
            if (info.owner == msg.sender) {
                isNode = true;
                break;
            }
        }
        require(isNode, "Session: not session node");

        // Decode receipt: only the node signature is required.
        (
            uint256 rSessionId,
            uint256 cumulativeBytes,
            uint256 timestamp,
            bytes memory nodeSig
        ) = abi.decode(signedReceipt, (uint256, uint256, uint256, bytes));

        require(rSessionId == sessionId, "Session: id mismatch");

        bytes32 structHash = EIP712Utils.receiptStructHash(rSessionId, cumulativeBytes, timestamp);
        bytes32 digest = EIP712Utils.hashTypedData(DOMAIN_SEPARATOR, structHash);

        // Verify the signer is an owner of one of the session nodes.
        address signer = EIP712Utils.recoverSigner(digest, nodeSig);
        bool validSigner;
        for (uint256 i; i < 3; ++i) {
            INodeRegistry.NodeInfo memory info = nodeRegistry.getNode(s.nodeIds[i]);
            if (info.owner == signer) {
                validSigner = true;
                break;
            }
        }
        require(validSigner, "Session: bad node sig");

        _settle(sessionId, s, cumulativeBytes);

        emit SessionForceSettled(
            sessionId,
            msg.sender,
            cumulativeBytes,
            _computeTotalPaid(s, cumulativeBytes)
        );
    }

    // ──────────────────────────────────────────────────────────────
    //  View
    // ──────────────────────────────────────────────────────────────

    /// @inheritdoc ISessionSettlement
    function getSession(uint256 sessionId)
        external
        view
        override
        returns (SessionInfo memory)
    {
        return _sessions[sessionId];
    }

    // ──────────────────────────────────────────────────────────────
    //  Internal helpers
    // ──────────────────────────────────────────────────────────────

    /// @dev Settle a session: pay the three nodes, refund the client.
    function _settle(
        uint256 sessionId,
        SessionInfo storage s,
        uint256 cumulativeBytes
    ) internal {
        // Use exit node's pricePerByte as the authoritative rate.
        INodeRegistry.NodeInfo memory exitNode = nodeRegistry.getNode(s.nodeIds[2]);
        uint256 totalPaid = cumulativeBytes * exitNode.pricePerByte;
        if (totalPaid > s.deposit) {
            totalPaid = s.deposit;
        }

        // Effects
        s.settled = true;
        s.cumulativeBytes = cumulativeBytes;

        // Split payments.
        uint256 entryPay = (totalPaid * ENTRY_SHARE) / 100;
        uint256 relayPay = (totalPaid * RELAY_SHARE) / 100;
        uint256 exitPay  = totalPaid - entryPay - relayPay; // remainder to exit

        uint256 refund = s.deposit - totalPaid;

        // Interactions -- pay nodes.
        _payNode(s.nodeIds[0], entryPay);
        _payNode(s.nodeIds[1], relayPay);
        _payNode(s.nodeIds[2], exitPay);

        // Refund client.
        if (refund > 0) {
            (bool ok, ) = s.client.call{value: refund}("");
            require(ok, "Session: refund failed");
        }

        emit SessionSettled(sessionId, s.client, cumulativeBytes, totalPaid);
    }

    /// @dev Send ETH to a node's owner.
    function _payNode(bytes32 nodeId, uint256 amount) internal {
        if (amount == 0) return;
        INodeRegistry.NodeInfo memory info = nodeRegistry.getNode(nodeId);
        (bool ok, ) = info.owner.call{value: amount}("");
        require(ok, "Session: node payment failed");
    }

    /// @dev Compute total paid (capped at deposit).
    function _computeTotalPaid(
        SessionInfo storage s,
        uint256 cumulativeBytes
    ) internal view returns (uint256) {
        INodeRegistry.NodeInfo memory exitNode = nodeRegistry.getNode(s.nodeIds[2]);
        uint256 total = cumulativeBytes * exitNode.pricePerByte;
        return total > s.deposit ? s.deposit : total;
    }

}
