// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ISlashingOracle
/// @notice Interface for the ShieldNode slashing oracle that penalises misbehaving nodes.
interface ISlashingOracle {
    // ──────────────────────────────────────────────────────────────
    //  Enums
    // ──────────────────────────────────────────────────────────────

    /// @notice Categories of slashable offences.
    enum SlashReason {
        ProvableLogging,
        SelectiveDenial,
        BandwidthFraud,
        ChallengeFailure
    }

    // ──────────────────────────────────────────────────────────────
    //  Events
    // ──────────────────────────────────────────────────────────────

    /// @notice Emitted when a new slash proposal is created.
    event SlashProposed(
        uint256 indexed proposalId,
        bytes32 indexed nodeId,
        address indexed challenger,
        SlashReason reason
    );

    /// @notice Emitted when a slash proposal is executed.
    event SlashExecuted(
        uint256 indexed proposalId,
        bytes32 indexed nodeId,
        uint256 slashedAmount
    );

    // ──────────────────────────────────────────────────────────────
    //  External functions
    // ──────────────────────────────────────────────────────────────

    /// @notice Propose slashing a node for misbehaviour.
    /// @param nodeId   The offending node.
    /// @param reason   Category of offence.
    /// @param evidence Arbitrary evidence payload (e.g. Merkle proof).
    function proposeSlash(
        bytes32 nodeId,
        uint8 reason,
        bytes calldata evidence
    ) external;

    /// @notice Execute a slash proposal after the grace period has elapsed.
    /// @param proposalId The proposal to execute.
    function executeSlash(uint256 proposalId) external;
}
