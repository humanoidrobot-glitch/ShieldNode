// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISlashingOracle}  from "./interfaces/ISlashingOracle.sol";
import {INodeRegistry}    from "./interfaces/INodeRegistry.sol";
import {NodeRegistry}     from "./NodeRegistry.sol";
import {SessionSettlement} from "./SessionSettlement.sol";
import {EIP712Utils}       from "./lib/EIP712Utils.sol";

/// @title SlashingOracle
/// @notice Manages slash proposals with on-chain evidence verification,
///         grace periods, progressive penalties, and distributes slashed
///         stake between the challenger and the treasury.
///
///  Evidence verification by slash reason:
///
///  - **BandwidthFraud**: Two EIP-712 dual-signed receipts for the same
///    session with different cumulative byte counts.  The contract verifies
///    both sets of signatures (client + node) and confirms the byte counts
///    diverge.
///
///  - **ProvableLogging / SelectiveDenial**: A challenger-signed attestation
///    containing the target nodeId and a description hash.  The contract
///    verifies the challenger's ECDSA signature.  This is a "trusted
///    challenger" model — decentralised challenge bonds come in Phase 6.
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

    // ── EIP-712 (mirrors SessionSettlement) ──────────────────────

    bytes32 public constant RECEIPT_TYPEHASH = EIP712Utils.RECEIPT_TYPEHASH;

    /// @notice EIP-712 domain separator (computed in constructor to match
    ///         the SessionSettlement contract on the same chain).
    bytes32 public immutable DOMAIN_SEPARATOR;

    // ── Attestation EIP-712 ──────────────────────────────────────

    bytes32 public constant ATTESTATION_TYPEHASH = keccak256(
        "SlashAttestation(bytes32 nodeId,uint256 timestamp,bytes32 descriptionHash)"
    );

    // ──────────────────────────────────────────────────────────────
    //  Immutables
    // ──────────────────────────────────────────────────────────────

    /// @notice The NodeRegistry this oracle operates on.
    NodeRegistry public immutable registry;

    /// @notice Treasury that receives its share of slashed funds.
    address public immutable treasury;

    /// @notice SessionSettlement contract whose EIP-712 domain this oracle
    ///         shares for receipt signature verification.
    address public immutable settlement;

    // ──────────────────────────────────────────────────────────────
    //  State
    // ──────────────────────────────────────────────────────────────

    /// @notice Contract owner.
    address public owner;

    /// @notice Authorised challengers.
    mapping(address => bool) public challengers;

    /// @dev Proposal storage.  Evidence is not stored — it is verified
    ///      at proposal time and emitted in the SlashProposed event.
    struct Proposal {
        bytes32     nodeId;
        SlashReason reason;
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
    //  Errors
    // ──────────────────────────────────────────────────────────────

    error ZeroAddress();
    error NotOwner();
    error NotChallenger();
    error BadReason();
    error InvalidEvidence(string detail);
    error UnknownProposal();
    error AlreadyExecuted();
    error GracePeriodActive();
    error TransferFailed(string recipient);

    // ──────────────────────────────────────────────────────────────
    //  Modifiers
    // ──────────────────────────────────────────────────────────────

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlyChallenger() {
        if (!challengers[msg.sender]) revert NotChallenger();
        _;
    }

    // ──────────────────────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────────────────────

    /// @param _registry   Address of the NodeRegistry.
    /// @param _treasury   Address of the Treasury.
    /// @param _settlement Address of the SessionSettlement contract (for
    ///                    BandwidthFraud EIP-712 domain matching).
    constructor(address _registry, address _treasury, address _settlement) {
        if (_registry == address(0)) revert ZeroAddress();
        if (_treasury == address(0)) revert ZeroAddress();
        if (_settlement == address(0)) revert ZeroAddress();
        registry   = NodeRegistry(_registry);
        treasury   = _treasury;
        settlement = _settlement;
        owner      = msg.sender;

        // Read the EIP-712 domain directly from SessionSettlement so receipt
        // signatures produced for settlement are also valid here.
        DOMAIN_SEPARATOR = SessionSettlement(_settlement).DOMAIN_SEPARATOR();
    }

    // ──────────────────────────────────────────────────────────────
    //  Admin
    // ──────────────────────────────────────────────────────────────

    /// @notice Add or remove an authorised challenger.
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
        if (reason > uint8(SlashReason.BandwidthFraud)) revert BadReason();

        SlashReason sr = SlashReason(reason);

        // ── On-chain evidence verification ───────────────────────
        if (sr == SlashReason.BandwidthFraud) {
            _verifyBandwidthFraud(nodeId, evidence);
        } else {
            // ProvableLogging or SelectiveDenial — trusted challenger attestation.
            _verifyChallengerAttestation(nodeId, evidence, msg.sender);
        }

        uint256 proposalId = nextProposalId++;

        proposals[proposalId] = Proposal({
            nodeId:     nodeId,
            reason:     sr,
            challenger: msg.sender,
            createdAt:  block.timestamp,
            executed:   false
        });

        emit SlashProposed(proposalId, nodeId, msg.sender, sr);
    }

    /// @inheritdoc ISlashingOracle
    function executeSlash(uint256 proposalId) external override {
        Proposal storage p = proposals[proposalId];
        if (p.createdAt == 0) revert UnknownProposal();
        if (p.executed) revert AlreadyExecuted();
        if (block.timestamp < p.createdAt + GRACE_PERIOD) revert GracePeriodActive();

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
            if (!ok1) revert TransferFailed("challenger");
        }
        if (treasuryReward > 0) {
            (bool ok2, ) = treasury.call{value: treasuryReward}("");
            if (!ok2) revert TransferFailed("treasury");
        }

        emit SlashExecuted(proposalId, p.nodeId, slashAmount);
    }

    /// @notice Accept ETH from the registry during slashing.
    receive() external payable {}

    // ──────────────────────────────────────────────────────────────
    //  Evidence verification — internal
    // ──────────────────────────────────────────────────────────────

    /// @dev Verify BandwidthFraud evidence: two conflicting dual-signed
    ///      receipts for the same session.
    ///
    ///  Evidence layout:
    ///  ```
    ///  abi.encode(
    ///      uint256 sessionId,
    ///      uint256 bytes1,  uint256 ts1,  bytes clientSig1, bytes nodeSig1,
    ///      uint256 bytes2,  uint256 ts2,  bytes clientSig2, bytes nodeSig2
    ///  )
    ///  ```
    function _verifyBandwidthFraud(
        bytes32 nodeId,
        bytes calldata evidence
    ) internal view {
        (
            uint256 sessionId,
            uint256 cumBytes1, uint256 ts1, bytes memory cSig1, bytes memory nSig1,
            uint256 cumBytes2, uint256 ts2, bytes memory cSig2, bytes memory nSig2
        ) = abi.decode(evidence, (uint256, uint256, uint256, bytes, bytes, uint256, uint256, bytes, bytes));

        // The two receipts must report different byte counts.
        if (cumBytes1 == cumBytes2) {
            revert InvalidEvidence("byte counts match");
        }

        // Verify both receipts and check signers match + belong to accused node.
        _verifyFraudSigners(
            nodeId, sessionId,
            cumBytes1, ts1, cSig1, nSig1,
            cumBytes2, ts2, cSig2, nSig2
        );
    }

    /// @dev Second half of fraud verification — separated to avoid stack-too-deep.
    function _verifyFraudSigners(
        bytes32 nodeId,
        uint256 sessionId,
        uint256 cumBytes1, uint256 ts1, bytes memory cSig1, bytes memory nSig1,
        uint256 cumBytes2, uint256 ts2, bytes memory cSig2, bytes memory nSig2
    ) internal view {
        bytes32 digest1 = _receiptDigest(sessionId, cumBytes1, ts1);
        address client1 = EIP712Utils.recoverSigner(digest1, cSig1);
        address node1   = EIP712Utils.recoverSigner(digest1, nSig1);

        bytes32 digest2 = _receiptDigest(sessionId, cumBytes2, ts2);
        address client2 = EIP712Utils.recoverSigner(digest2, cSig2);
        address node2   = EIP712Utils.recoverSigner(digest2, nSig2);

        if (client1 != client2) revert InvalidEvidence("client signers differ");
        if (node1 != node2)     revert InvalidEvidence("node signers differ");

        INodeRegistry.NodeInfo memory info = registry.getNode(nodeId);
        if (node1 != info.owner) revert InvalidEvidence("node signer is not accused node owner");
    }

    /// @dev Verify a challenger-signed attestation for ProvableLogging or
    ///      SelectiveDenial.
    ///
    ///  Evidence layout:
    ///  ```
    ///  abi.encode(
    ///      bytes32 nodeId,
    ///      uint256 timestamp,
    ///      bytes32 descriptionHash,
    ///      bytes   challengerSig
    ///  )
    ///  ```
    function _verifyChallengerAttestation(
        bytes32 nodeId,
        bytes calldata evidence,
        address expectedChallenger
    ) internal view {
        (
            bytes32 attestedNodeId,
            uint256 timestamp,
            bytes32 descriptionHash,
            bytes memory challengerSig
        ) = abi.decode(evidence, (bytes32, uint256, bytes32, bytes));

        // The attestation must target the same node as the proposal.
        if (attestedNodeId != nodeId) {
            revert InvalidEvidence("attestation nodeId mismatch");
        }

        // Attestation must not be from the future.
        if (timestamp > block.timestamp) {
            revert InvalidEvidence("attestation timestamp in the future");
        }

        // Verify the challenger's signature over the attestation.
        bytes32 structHash = keccak256(
            abi.encode(ATTESTATION_TYPEHASH, attestedNodeId, timestamp, descriptionHash)
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
        );

        address signer = EIP712Utils.recoverSigner(digest, challengerSig);
        if (signer != expectedChallenger) {
            revert InvalidEvidence("attestation signer mismatch");
        }
    }

    // ──────────────────────────────────────────────────────────────
    //  EIP-712 helpers
    // ──────────────────────────────────────────────────────────────

    /// @dev Compute the EIP-712 digest for a BandwidthReceipt.
    function _receiptDigest(
        uint256 sessionId,
        uint256 cumulativeBytes,
        uint256 timestamp
    ) internal view returns (bytes32) {
        bytes32 structHash = EIP712Utils.receiptStructHash(sessionId, cumulativeBytes, timestamp);
        return EIP712Utils.hashTypedData(DOMAIN_SEPARATOR, structHash);
    }

}
