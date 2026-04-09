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
///         Pull-payment pattern: recipients withdraw credited amounts.
contract SessionSettlement is ISessionSettlement {
    // ──────────────────────────────────────────────────────────────
    //  Constants
    // ──────────────────────────────────────────────────────────────

    uint256 public constant MINIMUM_DEPOSIT = 0.001 ether;
    uint256 public constant FORCE_SETTLE_TIMEOUT = 1 hours;
    uint256 public constant FORCE_SETTLE_CAP_BPS = 5000; // 50%
    uint256 public constant SESSION_CLEANUP_TIMEOUT = 30 days;

    uint256 public constant ENTRY_SHARE = 25;
    uint256 public constant RELAY_SHARE = 25;
    uint256 public constant EXIT_SHARE  = 50;

    /// @notice Maximum cumulative bytes per session (prevents overflow in settlement).
    uint256 public constant MAX_CUMULATIVE_BYTES = 1e30;

    // ──────────────────────────────────────────────────────────────
    //  EIP-712
    // ──────────────────────────────────────────────────────────────

    bytes32 public constant RECEIPT_TYPEHASH = EIP712Utils.RECEIPT_TYPEHASH;
    bytes32 public immutable DOMAIN_SEPARATOR;

    // ──────────────────────────────────────────────────────────────
    //  Immutables
    // ──────────────────────────────────────────────────────────────

    NodeRegistry public immutable nodeRegistry;

    // ──────────────────────────────────────────────────────────────
    //  State
    // ──────────────────────────────────────────────────────────────

    uint256 public nextSessionId;
    mapping(uint256 => SessionInfo) private _sessions;

    /// @notice Pull-payment: credited amounts awaiting withdrawal.
    mapping(address => uint256) public pendingWithdrawals;

    /// @notice Open (unsettled) session count per nodeId.
    mapping(bytes32 => uint256) public openSessionCount;

    /// @dev Reentrancy guard.
    bool private _locked;

    /// @notice Emergency pause state.
    bool public paused;

    /// @notice Address authorized to pause/unpause.
    address public pauser;

    // ──────────────────────────────────────────────────────────────
    //  Events
    // ──────────────────────────────────────────────────────────────

    event Paused(address account);
    event Unpaused(address account);
    event SessionCleanedUp(uint256 indexed sessionId, address indexed client, uint256 refund);

    // ──────────────────────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────────────────────

    constructor(address _nodeRegistry, address _pauser) {
        require(_nodeRegistry != address(0), "Session: zero registry");
        require(_pauser != address(0), "Session: zero pauser");
        nodeRegistry = NodeRegistry(_nodeRegistry);
        DOMAIN_SEPARATOR = EIP712Utils.computeDomainSeparator(address(this));
        pauser = _pauser;
    }

    // ──────────────────────────────────────────────────────────────
    //  Modifiers
    // ──────────────────────────────────────────────────────────────

    modifier nonReentrant() {
        require(!_locked, "Session: reentrant");
        _locked = true;
        _;
        _locked = false;
    }

    modifier whenNotPaused() {
        require(!paused, "Session: paused");
        _;
    }

    // ──────────────────────────────────────────────────────────────
    //  Emergency pause
    // ──────────────────────────────────────────────────────────────

    function pause() external {
        require(msg.sender == pauser, "Session: not pauser");
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external {
        require(msg.sender == pauser, "Session: not pauser");
        paused = false;
        emit Unpaused(msg.sender);
    }

    // ──────────────────────────────────────────────────────────────
    //  Open session
    // ──────────────────────────────────────────────────────────────

    /// @inheritdoc ISessionSettlement
    function openSession(bytes32[3] calldata nodeIds, uint256 maxPricePerByte) external payable override whenNotPaused {
        require(msg.value >= MINIMUM_DEPOSIT, "Session: deposit too low");

        require(
            nodeIds[0] != nodeIds[1] &&
            nodeIds[1] != nodeIds[2] &&
            nodeIds[0] != nodeIds[2],
            "Session: duplicate nodes"
        );

        // Snapshot node owners and per-node prices at open time.
        address[3] memory owners;
        uint256[3] memory prices;
        for (uint256 i; i < 3; ++i) {
            require(nodeRegistry.isNodeActive(nodeIds[i]), "Session: node not active");
            INodeRegistry.NodeInfo memory info = nodeRegistry.getNode(nodeIds[i]);
            owners[i] = info.owner;
            prices[i] = info.pricePerByte;
            require(prices[i] > 0, "Session: zero price");
            require(prices[i] <= maxPricePerByte, "Session: price exceeds max");
        }

        // Prevent quorum bypass: node owners must be distinct and client
        // must not own any of the session nodes.
        require(
            owners[0] != owners[1] && owners[1] != owners[2] && owners[0] != owners[2],
            "Session: duplicate owners"
        );
        require(
            msg.sender != owners[0] && msg.sender != owners[1] && msg.sender != owners[2],
            "Session: client is node owner"
        );

        uint256 sessionId = nextSessionId++;

        _sessions[sessionId] = SessionInfo({
            client:          msg.sender,
            nodeIds:         nodeIds,
            nodeOwners:      owners,
            deposit:         msg.value,
            startTime:       block.timestamp,
            settled:         false,
            cumulativeBytes: 0,
            nodePrices:      prices
        });

        // Track open sessions per node.
        for (uint256 i; i < 3; ++i) {
            openSessionCount[nodeIds[i]]++;
        }

        emit SessionOpened(sessionId, msg.sender, nodeIds, msg.value);
    }

    // ──────────────────────────────────────────────────────────────
    //  Cooperative settle
    // ──────────────────────────────────────────────────────────────

    /// @inheritdoc ISessionSettlement
    function settleSession(
        uint256 sessionId,
        bytes calldata signedReceipt
    ) external override nonReentrant whenNotPaused {
        SessionInfo storage s = _sessions[sessionId];
        require(s.client != address(0), "Session: unknown");
        require(!s.settled, "Session: already settled");
        require(
            msg.sender == s.client || _isSessionOwner(s, msg.sender),
            "Session: not participant"
        );

        (
            uint256 rSessionId,
            uint256 cumulativeBytes,
            uint256 timestamp,
            bytes memory clientSig,
            bytes memory nodeSig0,
            bytes memory nodeSig1,
            bytes memory nodeSig2
        ) = abi.decode(signedReceipt, (uint256, uint256, uint256, bytes, bytes, bytes, bytes));

        require(rSessionId == sessionId, "Session: id mismatch");

        bytes32 digest = _verifyReceiptAndNodeSigs(
            s, rSessionId, cumulativeBytes, timestamp, nodeSig0, nodeSig1, nodeSig2
        );

        // Verify client signature against snapshotted client.
        address clientSigner = EIP712Utils.recoverSigner(digest, clientSig);
        require(clientSigner == s.client, "Session: bad client sig");

        _settle(sessionId, s, cumulativeBytes, s.deposit);
    }

    // ──────────────────────────────────────────────────────────────
    //  Force settle (node-initiated after timeout, 2-of-3 sigs)
    // ──────────────────────────────────────────────────────────────

    /// @inheritdoc ISessionSettlement
    function forceSettle(
        uint256 sessionId,
        bytes calldata signedReceipt
    ) external override nonReentrant whenNotPaused {
        SessionInfo storage s = _sessions[sessionId];
        require(s.client != address(0), "Session: unknown");
        require(!s.settled, "Session: already settled");
        require(block.timestamp >= s.startTime + FORCE_SETTLE_TIMEOUT, "Session: too early");
        require(_isSessionOwner(s, msg.sender), "Session: not session node");

        (uint256 cumBytes, uint256 actualPaid) = _verifyAndSettleForce(sessionId, s, signedReceipt);
        emit SessionForceSettled(sessionId, msg.sender, cumBytes, actualPaid);
    }

    /// @dev Decode, verify all 3 node sigs, and settle with force cap.
    ///      Requires all 3 node signatures.
    /// @param sessionId The session to force-settle.
    /// @param s Storage reference to the session info.
    /// @param signedReceipt ABI-encoded receipt with three node signatures.
    /// @return cumBytes Cumulative bytes from the receipt.
    /// @return actualPaid Actual ETH distributed to nodes.
    function _verifyAndSettleForce(
        uint256 sessionId,
        SessionInfo storage s,
        bytes calldata signedReceipt
    ) internal returns (uint256 cumBytes, uint256 actualPaid) {
        uint256 rSessionId;
        uint256 timestamp;
        bytes memory nodeSig0;
        bytes memory nodeSig1;
        bytes memory nodeSig2;
        (rSessionId, cumBytes, timestamp, nodeSig0, nodeSig1, nodeSig2) =
            abi.decode(signedReceipt, (uint256, uint256, uint256, bytes, bytes, bytes));

        require(rSessionId == sessionId, "Session: id mismatch");

        _verifyReceiptAndNodeSigs(
            s, rSessionId, cumBytes, timestamp, nodeSig0, nodeSig1, nodeSig2
        );

        uint256 cap = (s.deposit * FORCE_SETTLE_CAP_BPS) / 10000;
        actualPaid = _settle(sessionId, s, cumBytes, cap);
    }

    // ──────────────────────────────────────────────────────────────
    //  Idle session cleanup
    // ──────────────────────────────────────────────────────────────

    /// @notice Clean up an abandoned session after SESSION_CLEANUP_TIMEOUT.
    ///         Callable by anyone.  Refunds the full deposit to the client
    ///         and decrements openSessionCount so nodes can unstake.
    /// @param sessionId The abandoned session to clean up.
    function cleanupSession(uint256 sessionId) external nonReentrant whenNotPaused {
        SessionInfo storage s = _sessions[sessionId];
        require(s.client != address(0), "Session: unknown");
        require(!s.settled, "Session: already settled");
        require(
            block.timestamp >= s.startTime + SESSION_CLEANUP_TIMEOUT,
            "Session: cleanup too early"
        );

        s.settled = true;
        s.cumulativeBytes = 0;
        _decrementOpenSessions(s.nodeIds);

        pendingWithdrawals[s.client] += s.deposit;

        emit SessionCleanedUp(sessionId, s.client, s.deposit);
    }

    // ──────────────────────────────────────────────────────────────
    //  Pull-payment withdrawal
    // ──────────────────────────────────────────────────────────────

    /// @notice Withdraw credited settlement payments.
    function withdraw() external nonReentrant {
        uint256 amount = pendingWithdrawals[msg.sender];
        require(amount > 0, "Session: nothing to withdraw");
        pendingWithdrawals[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Session: transfer failed");
    }

    // ──────────────────────────────────────────────────────────────
    //  View
    // ──────────────────────────────────────────────────────────────

    /// @inheritdoc ISessionSettlement
    function getSession(uint256 sessionId)
        external view override returns (SessionInfo memory)
    {
        return _sessions[sessionId];
    }

    // ──────────────────────────────────────────────────────────────
    //  Internal helpers
    // ──────────────────────────────────────────────────────────────

    /// @dev Validate receipt timestamps and verify all 3 node EIP-712 sigs.
    function _verifyReceiptAndNodeSigs(
        SessionInfo storage s,
        uint256 sessionId,
        uint256 cumulativeBytes,
        uint256 timestamp,
        bytes memory nodeSig0,
        bytes memory nodeSig1,
        bytes memory nodeSig2
    ) internal view returns (bytes32 digest) {
        require(timestamp >= s.startTime, "Session: receipt before start");
        require(timestamp <= block.timestamp, "Session: future receipt");

        digest = EIP712Utils.hashTypedData(
            DOMAIN_SEPARATOR,
            EIP712Utils.receiptStructHash(sessionId, cumulativeBytes, timestamp)
        );

        require(EIP712Utils.recoverSigner(digest, nodeSig0) == s.nodeOwners[0], "Session: bad entry sig");
        require(EIP712Utils.recoverSigner(digest, nodeSig1) == s.nodeOwners[1], "Session: bad relay sig");
        require(EIP712Utils.recoverSigner(digest, nodeSig2) == s.nodeOwners[2], "Session: bad exit sig");
    }

    /// @dev Settle a session: credit node payments and client refund.
    ///      Each node is paid at its own price * share.
    /// @param sessionId The session to settle.
    /// @param s Storage reference to the session info.
    /// @param cumulativeBytes Total bytes consumed in the session.
    /// @param cap Maximum ETH that may be distributed to nodes.
    /// @return totalPaid The actual amount distributed to nodes.
    function _settle(
        uint256 sessionId,
        SessionInfo storage s,
        uint256 cumulativeBytes,
        uint256 cap
    ) internal returns (uint256 totalPaid) {
        require(cumulativeBytes <= MAX_CUMULATIVE_BYTES, "Session: bytes overflow");

        // Compute per-node payments using individual prices and share weights.
        uint256 entryPay = (cumulativeBytes * s.nodePrices[0] * ENTRY_SHARE) / 100;
        uint256 relayPay = (cumulativeBytes * s.nodePrices[1] * RELAY_SHARE) / 100;
        uint256 exitPay  = (cumulativeBytes * s.nodePrices[2] * EXIT_SHARE) / 100;
        totalPaid = entryPay + relayPay + exitPay;

        if (totalPaid > cap && totalPaid > 0) {
            // Scale proportionally to stay within cap.
            entryPay = (entryPay * cap) / totalPaid;
            relayPay = (relayPay * cap) / totalPaid;
            exitPay  = cap - entryPay - relayPay;
            totalPaid = cap;
        }

        // Effects
        s.settled = true;
        s.cumulativeBytes = cumulativeBytes;

        _decrementOpenSessions(s.nodeIds);

        // Credit payments (pull-payment pattern).
        if (entryPay > 0) pendingWithdrawals[s.nodeOwners[0]] += entryPay;
        if (relayPay > 0) pendingWithdrawals[s.nodeOwners[1]] += relayPay;
        if (exitPay > 0)  pendingWithdrawals[s.nodeOwners[2]] += exitPay;

        uint256 refund = s.deposit - totalPaid;
        if (refund > 0) pendingWithdrawals[s.client] += refund;

        emit SessionSettled(sessionId, s.client, cumulativeBytes, totalPaid);
    }

    /// @dev Decrement open session count for each node in the circuit.
    function _decrementOpenSessions(bytes32[3] storage nodeIds) internal {
        for (uint256 i; i < 3; ++i) {
            bytes32 nid = nodeIds[i];
            uint256 count = openSessionCount[nid];
            if (count > 0) {
                openSessionCount[nid] = count - 1;
            }
        }
    }

    /// @dev Check if an address is one of the snapshotted session node owners.
    /// @param s Storage reference to the session info.
    /// @param addr The address to check.
    /// @return True if addr matches any of the three node owners.
    function _isSessionOwner(SessionInfo storage s, address addr) internal view returns (bool) {
        return addr == s.nodeOwners[0] || addr == s.nodeOwners[1] || addr == s.nodeOwners[2];
    }
}
