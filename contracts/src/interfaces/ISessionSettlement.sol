// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ISessionSettlement
/// @notice Interface for opening, settling, and force-settling VPN sessions.
interface ISessionSettlement {
    // ──────────────────────────────────────────────────────────────
    //  Structs
    // ──────────────────────────────────────────────────────────────

    /// @notice On-chain state for a VPN session.
    struct SessionInfo {
        address    client;
        bytes32[3] nodeIds;
        address[3] nodeOwners;
        uint256    deposit;
        uint256    startTime;
        bool       settled;
        uint256    cumulativeBytes;
        uint256    pricePerByte;
    }

    // ──────────────────────────────────────────────────────────────
    //  Events
    // ──────────────────────────────────────────────────────────────

    /// @notice Emitted when a new session is opened.
    event SessionOpened(
        uint256 indexed sessionId,
        address indexed client,
        bytes32[3] nodeIds,
        uint256 deposit
    );

    /// @notice Emitted when a session is cooperatively settled.
    event SessionSettled(
        uint256 indexed sessionId,
        address indexed client,
        uint256 cumulativeBytes,
        uint256 totalPaid
    );

    /// @notice Emitted when a session is force-settled by a node.
    event SessionForceSettled(
        uint256 indexed sessionId,
        address indexed settler,
        uint256 cumulativeBytes,
        uint256 totalPaid
    );

    // ──────────────────────────────────────────────────────────────
    //  External functions
    // ──────────────────────────────────────────────────────────────

    /// @notice Open a 3-hop VPN session.
    /// @param nodeIds         Entry, relay, and exit node IDs (in order).
    /// @param maxPricePerByte Maximum acceptable price per byte (prevents front-running).
    function openSession(bytes32[3] calldata nodeIds, uint256 maxPricePerByte) external payable;

    /// @notice Cooperatively settle a session with a co-signed bandwidth receipt.
    /// @param sessionId     The session to settle.
    /// @param signedReceipt ABI-encoded receipt with client + node EIP-712 signatures.
    function settleSession(uint256 sessionId, bytes calldata signedReceipt) external;

    /// @notice Force-settle a session after the timeout when the client disappears.
    /// @param sessionId     The session to settle.
    /// @param signedReceipt ABI-encoded receipt with at least the node's EIP-712 signature.
    function forceSettle(uint256 sessionId, bytes calldata signedReceipt) external;

    /// @notice Retrieve full session metadata.
    /// @param sessionId The session to query.
    /// @return info The SessionInfo struct.
    function getSession(uint256 sessionId) external view returns (SessionInfo memory info);
}
