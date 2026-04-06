// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISlashingOracle}    from "./interfaces/ISlashingOracle.sol";
import {INodeRegistry}     from "./interfaces/INodeRegistry.sol";
import {ISessionSettlement} from "./interfaces/ISessionSettlement.sol";
import {NodeRegistry}      from "./NodeRegistry.sol";
import {SessionSettlement}  from "./SessionSettlement.sol";
import {EIP712Utils}        from "./lib/EIP712Utils.sol";

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

    /// @notice Maximum lifetime of a proposal. After this, it can be expired
    ///         to free the node's pendingSlashCount and unblock withdrawals.
    uint256 public constant PROPOSAL_EXPIRY = 14 days;

    /// @notice Slash percentages by offence count (fraud track).
    ///         First = 10 %, second = 25 %, third+ = 100 %.
    uint256 private constant SLASH_PCT_FIRST  = 10;
    uint256 private constant SLASH_PCT_SECOND = 25;
    uint256 private constant SLASH_PCT_THIRD  = 100;

    /// @notice Reduced penalty for liveness failures (ChallengeFailure).
    ///         Separate from the fraud track — a network outage should not
    ///         escalate toward permanent ban at the same rate as proven fraud.
    uint256 private constant SLASH_PCT_LIVENESS = 5;

    /// @notice Number of liveness failures before a node is auto-deactivated.
    uint256 public constant LIVENESS_BAN_THRESHOLD = 5;

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

    /// @notice Separate EIP-712 domain for attestations.
    ///         Uses address(this) as verifyingContract instead of the
    ///         settlement address, so wallets display the correct context.
    bytes32 public immutable ATTESTATION_DOMAIN_SEPARATOR;

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

    /// @dev A single dual-signed receipt used as fraud evidence.
    struct FraudReceipt {
        uint256 cumBytes;
        uint256 ts;
        bytes   clientSig;
        bytes   nodeSig;
    }

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

    /// @dev Evidence hash dedup — prevents the same evidence from creating multiple proposals.
    mapping(bytes32 => bool) public usedEvidence;

    /// @dev Count of pending (unexecuted) slash proposals per node.
    ///      NodeRegistry can check this to block withdrawals while slashes are pending.
    mapping(bytes32 => uint256) public pendingSlashCount;

    /// @dev Timestamp of last slash execution per node — enforces cooldown
    ///      between sequential slash executions to prevent batch bypass.
    mapping(bytes32 => uint256) public lastSlashExecuted;

    /// @notice Pull-payment: credited amounts awaiting withdrawal.
    mapping(address => uint256) public pendingWithdrawals;

    /// @notice Cumulative liveness failure count per node. Resets when the
    ///         node is deactivated at threshold.
    mapping(bytes32 => uint256) public livenessFailureCount;

    /// @dev Timelocked challenger proposals.
    struct ChallengerProposal {
        address challenger;
        bool    authorised;
        uint256 readyAt;
        bool    executed;
    }
    mapping(uint256 => ChallengerProposal) public challengerProposals;
    uint256 public nextChallengerProposalId;

    uint256 public constant CHALLENGER_TIMELOCK = 48 hours;

    /// @notice Emergency pause state.
    bool public paused;

    /// @notice Dedicated pauser address for emergency pause/unpause.
    address public pauser;

    /// @dev Reentrancy guard.
    bool private _locked;

    // ──────────────────────────────────────────────────────────────
    //  Events (supplementary -- interface events are inherited)
    // ──────────────────────────────────────────────────────────────

    event ChallengerUpdated(address indexed challenger, bool authorised);
    event ChallengerProposed(uint256 indexed proposalId, address indexed challenger, bool authorised, uint256 readyAt);
    event SlashProposalExpired(uint256 indexed proposalId, bytes32 indexed nodeId);
    event LivenessDeactivation(bytes32 indexed nodeId, uint256 failureCount);
    event Paused(address account);
    event Unpaused(address account);

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
    error NotExpired();
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

    modifier whenNotPaused() {
        require(!paused, "SlashingOracle: paused");
        _;
    }

    modifier nonReentrant() {
        require(!_locked, "SlashingOracle: reentrant");
        _locked = true;
        _;
        _locked = false;
    }

    // ──────────────────────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────────────────────

    /// @param _registry   Address of the NodeRegistry.
    /// @param _treasury   Address of the Treasury.
    /// @param _settlement Address of the SessionSettlement contract (for
    ///                    BandwidthFraud EIP-712 domain matching).
    /// @param _pauser     Address authorised to pause/unpause.
    constructor(address _registry, address _treasury, address _settlement, address _pauser) {
        if (_registry == address(0)) revert ZeroAddress();
        if (_treasury == address(0)) revert ZeroAddress();
        if (_settlement == address(0)) revert ZeroAddress();
        require(_pauser != address(0), "SlashingOracle: zero pauser");
        registry   = NodeRegistry(_registry);
        treasury   = _treasury;
        settlement = _settlement;
        owner      = msg.sender;
        pauser     = _pauser;

        // Read the EIP-712 domain directly from SessionSettlement so receipt
        // signatures produced for settlement are also valid here.
        DOMAIN_SEPARATOR = SessionSettlement(_settlement).DOMAIN_SEPARATOR();

        // Attestations use this contract's own domain so wallets display
        // the correct verifyingContract when challengers sign attestations.
        ATTESTATION_DOMAIN_SEPARATOR = EIP712Utils.computeDomainSeparator(address(this));
    }

    // ──────────────────────────────────────────────────────────────
    //  Admin
    // ──────────────────────────────────────────────────────────────

    /// @notice Propose adding or removing an authorised challenger (48h timelock).
    function proposeChallenger(address challenger, bool authorised) external onlyOwner returns (uint256 proposalId) {
        proposalId = nextChallengerProposalId++;
        uint256 readyAt = block.timestamp + CHALLENGER_TIMELOCK;
        challengerProposals[proposalId] = ChallengerProposal({
            challenger: challenger,
            authorised: authorised,
            readyAt:    readyAt,
            executed:   false
        });
        emit ChallengerProposed(proposalId, challenger, authorised, readyAt);
    }

    /// @notice Execute a timelocked challenger proposal.
    function executeChallenger(uint256 proposalId) external onlyOwner {
        ChallengerProposal storage cp = challengerProposals[proposalId];
        require(cp.readyAt > 0, "SlashingOracle: unknown proposal");
        require(!cp.executed, "SlashingOracle: already executed");
        require(block.timestamp >= cp.readyAt, "SlashingOracle: timelock active");
        cp.executed = true;
        challengers[cp.challenger] = cp.authorised;
        emit ChallengerUpdated(cp.challenger, cp.authorised);
    }

    /// @notice Emergency revocation — instant, safe direction only (remove, not add).
    function emergencyRevokeChallenger(address challenger) external onlyOwner {
        require(challengers[challenger], "SlashingOracle: not a challenger");
        challengers[challenger] = false;
        emit ChallengerUpdated(challenger, false);
    }

    /// @notice Emergency pause — blocks proposeSlash and executeSlash.
    function pause() external {
        require(msg.sender == pauser, "SlashingOracle: not pauser");
        paused = true;
        emit Paused(msg.sender);
    }

    /// @notice Resume operations.
    function unpause() external {
        require(msg.sender == pauser, "SlashingOracle: not pauser");
        paused = false;
        emit Unpaused(msg.sender);
    }

    // ──────────────────────────────────────────────────────────────
    //  Proposal lifecycle
    // ──────────────────────────────────────────────────────────────

    /// @inheritdoc ISlashingOracle
    function proposeSlash(
        bytes32 nodeId,
        uint8 reason,
        bytes calldata evidence
    ) external override onlyChallenger whenNotPaused {
        if (reason > uint8(SlashReason.ChallengeFailure)) revert BadReason();

        // Prevent duplicate proposals from the same evidence.
        bytes32 evidenceHash = keccak256(abi.encode(nodeId, reason, evidence));
        require(!usedEvidence[evidenceHash], "SlashingOracle: duplicate evidence");
        usedEvidence[evidenceHash] = true;

        SlashReason sr = SlashReason(reason);

        // ── On-chain evidence verification ───────────────────────
        if (sr == SlashReason.BandwidthFraud) {
            _verifyBandwidthFraud(nodeId, evidence);
        } else if (sr == SlashReason.ChallengeFailure) {
            // ChallengeManager submits expired challenge ID as evidence.
            // The caller must be an authorized challenger (ChallengeManager).
            // Evidence is abi-encoded (uint256 challengeId).
            // Verification is implicit: only ChallengeManager (an authorized
            // challenger) can call this with this reason, and it only does so
            // after verifying the challenge expired.
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

        pendingSlashCount[nodeId]++;

        emit SlashProposed(proposalId, nodeId, msg.sender, sr);
    }

    /// @inheritdoc ISlashingOracle
    function executeSlash(uint256 proposalId) external override whenNotPaused {
        Proposal storage p = proposals[proposalId];
        if (p.createdAt == 0) revert UnknownProposal();
        if (p.executed) revert AlreadyExecuted();
        if (block.timestamp < p.createdAt + GRACE_PERIOD) revert GracePeriodActive();
        require(
            block.timestamp >= lastSlashExecuted[p.nodeId] + GRACE_PERIOD,
            "SlashingOracle: slash cooldown"
        );

        p.executed = true;
        lastSlashExecuted[p.nodeId] = block.timestamp;
        if (pendingSlashCount[p.nodeId] > 0) {
            pendingSlashCount[p.nodeId]--;
        }

        // Determine slash percentage. Liveness failures use a reduced
        // penalty separate from the fraud escalation track.
        INodeRegistry.NodeInfo memory info = registry.getNode(p.nodeId);
        uint256 pct;
        if (p.reason == SlashReason.ChallengeFailure) {
            pct = SLASH_PCT_LIVENESS;
        } else if (info.slashCount == 0) {
            pct = SLASH_PCT_FIRST;
        } else if (info.slashCount == 1) {
            pct = SLASH_PCT_SECOND;
        } else {
            pct = SLASH_PCT_THIRD;
        }

        uint256 slashAmount = (info.stake * pct) / 100;

        // Call the registry to slash (funds are sent back to this contract).
        registry.slash(p.nodeId, slashAmount);

        // If third fraud offence (slashCount was 2 before this slash),
        // permanently ban. Liveness failures don't escalate toward permanent
        // ban — they are handled separately via LIVENESS_BAN_THRESHOLD.
        if (p.reason != SlashReason.ChallengeFailure && info.slashCount >= 2) {
            registry.ban(p.nodeId);
        }

        // Track liveness failures separately; deactivate at threshold.
        if (p.reason == SlashReason.ChallengeFailure) {
            livenessFailureCount[p.nodeId]++;
            if (livenessFailureCount[p.nodeId] >= LIVENESS_BAN_THRESHOLD) {
                emit LivenessDeactivation(p.nodeId, livenessFailureCount[p.nodeId]);
                livenessFailureCount[p.nodeId] = 0;
                registry.deactivateForLiveness(p.nodeId);
            }
        }

        // Distribute: 50 % challenger, 50 % treasury (pull-payment).
        uint256 challengerReward = (slashAmount * CHALLENGER_SHARE) / 100;
        uint256 treasuryReward   = slashAmount - challengerReward;

        if (challengerReward > 0) pendingWithdrawals[p.challenger] += challengerReward;
        if (treasuryReward > 0)   pendingWithdrawals[treasury]     += treasuryReward;

        emit SlashExecuted(proposalId, p.nodeId, slashAmount);
    }

    /// @notice Expire a stale proposal that was never executed within
    ///         PROPOSAL_EXPIRY. Decrements pendingSlashCount so the node
    ///         can withdraw its stake. Anyone can call.
    function expireProposal(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        if (p.createdAt == 0) revert UnknownProposal();
        if (p.executed) revert AlreadyExecuted();
        if (block.timestamp < p.createdAt + PROPOSAL_EXPIRY) revert NotExpired();

        p.executed = true;
        if (pendingSlashCount[p.nodeId] > 0) {
            pendingSlashCount[p.nodeId]--;
        }

        emit SlashProposalExpired(proposalId, p.nodeId);
    }

    // ──────────────────────────────────────────────────────────────
    //  Pull-payment withdrawal
    // ──────────────────────────────────────────────────────────────

    /// @notice Withdraw credited slash rewards.
    function withdraw() external nonReentrant {
        uint256 amount = pendingWithdrawals[msg.sender];
        require(amount > 0, "SlashingOracle: nothing to withdraw");
        pendingWithdrawals[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "SlashingOracle: transfer failed");
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
            FraudReceipt memory r1,
            FraudReceipt memory r2
        ) = abi.decode(evidence, (uint256, FraudReceipt, FraudReceipt));

        // The two receipts must report different byte counts.
        if (r1.cumBytes == r2.cumBytes) {
            revert InvalidEvidence("byte counts match");
        }

        // Verify both receipts and check signers match + belong to accused node.
        _verifyFraudSigners(nodeId, sessionId, r1, r2);
    }

    /// @dev Verify both fraud receipts: recover signers, check they match,
    ///      and confirm the node signer was a session participant.
    ///      Uses session-snapshotted owners (not current registry owner) so
    ///      evidence remains valid even after the node deregisters/re-registers.
    function _verifyFraudSigners(
        bytes32 nodeId,
        uint256 sessionId,
        FraudReceipt memory r1,
        FraudReceipt memory r2
    ) internal view {
        bytes32 digest1 = _receiptDigest(sessionId, r1.cumBytes, r1.ts);
        address client1 = EIP712Utils.recoverSigner(digest1, r1.clientSig);
        address node1   = EIP712Utils.recoverSigner(digest1, r1.nodeSig);

        bytes32 digest2 = _receiptDigest(sessionId, r2.cumBytes, r2.ts);
        address client2 = EIP712Utils.recoverSigner(digest2, r2.clientSig);
        address node2   = EIP712Utils.recoverSigner(digest2, r2.nodeSig);

        if (client1 != client2) revert InvalidEvidence("client signers differ");
        if (node1 != node2)     revert InvalidEvidence("node signers differ");

        // Verify against session-snapshotted owners instead of current
        // registry owner. This prevents evidence escape via deregister + re-register.
        ISessionSettlement.SessionInfo memory session = SessionSettlement(payable(settlement)).getSession(sessionId);
        require(session.client != address(0), "SlashingOracle: unknown session");

        bool isSessionNode = false;
        for (uint256 i; i < 3; ++i) {
            if (node1 == session.nodeOwners[i]) {
                isSessionNode = true;
                break;
            }
        }
        if (!isSessionNode) revert InvalidEvidence("node signer not in session");
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
        // Uses ATTESTATION_DOMAIN_SEPARATOR (this contract's own domain)
        // rather than the receipt DOMAIN_SEPARATOR (SessionSettlement's domain).
        bytes32 structHash = keccak256(
            abi.encode(ATTESTATION_TYPEHASH, attestedNodeId, timestamp, descriptionHash)
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", ATTESTATION_DOMAIN_SEPARATOR, structHash)
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
