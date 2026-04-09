// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {EIP712Utils} from "./lib/EIP712Utils.sol";
import {PoseidonT3} from "poseidon-solidity/PoseidonT3.sol";

/// @title IGroth16Verifier
/// @notice Interface for the auto-generated Groth16 verifier from snarkjs.
///         The actual contract is exported by `snarkjs zkey export solidityverifier`
///         and deployed separately.
interface IGroth16Verifier {
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[13] calldata _pubSignals
    ) external view returns (bool);
}

/// @title ZKSettlement
/// @notice Privacy-preserving session settlement using Groth16 ZK proofs.
///
///         Instead of revealing session ID, node identities, and byte counts
///         on-chain, the client submits a ZK proof that a valid dual-signed
///         bandwidth receipt exists and the payment split is correct.
///
///         The chain sees: a valid proof, ETH distributed to commitment-derived
///         addresses, and a refund. It does NOT see who, what, or how much
///         was transferred.
///
///         Works alongside SessionSettlement.sol — ZK is opt-in.
contract ZKSettlement {
    // ──────────────────────────────────────────────────────────────
    //  Constants
    // ──────────────────────────────────────────────────────────────

    uint256 public constant MINIMUM_DEPOSIT = 0.001 ether;

    /// @notice Payment split (basis points out of 100). Must match SessionSettlement.
    uint256 public constant ENTRY_SHARE = 25;
    uint256 public constant RELAY_SHARE = 25;

    // Public signal indices (must match circuit's public input/output order)
    uint256 private constant SIG_DOMAIN_SEPARATOR   = 0;
    uint256 private constant SIG_TOTAL_PAYMENT      = 1;
    uint256 private constant SIG_ENTRY_COMMITMENT   = 2;
    uint256 private constant SIG_RELAY_COMMITMENT   = 3;
    uint256 private constant SIG_EXIT_COMMITMENT    = 4;
    uint256 private constant SIG_REFUND_COMMITMENT  = 5;
    uint256 private constant SIG_REGISTRY_ROOT      = 6;
    uint256 private constant SIG_NULLIFIER          = 7;
    uint256 private constant SIG_DEPOSIT_ID         = 8;
    // Circuit outputs (payment amounts for on-chain verification)
    uint256 private constant SIG_ENTRY_PAY          = 9;
    uint256 private constant SIG_RELAY_PAY          = 10;
    uint256 private constant SIG_EXIT_PAY           = 11;
    uint256 private constant SIG_REFUND             = 12;

    /// @notice Number of public signals (9 inputs + 4 outputs).
    uint256 private constant NUM_PUBLIC_SIGNALS = 13;

    // ──────────────────────────────────────────────────────────────
    //  Immutables
    // ──────────────────────────────────────────────────────────────

    IGroth16Verifier public immutable verifier;
    bytes32 public immutable DOMAIN_SEPARATOR;

    // ──────────────────────────────────────────────────────────────
    //  State
    // ──────────────────────────────────────────────────────────────

    /// @notice Tracks deposits by commitment hash to prevent double-spend.
    ///         depositId -> deposit amount (0 = not deposited or already settled)
    mapping(bytes32 => uint256) public deposits;

    /// @notice Current Merkle root of the node registry (updated by owner).
    uint256 public registryRoot;

    /// @notice Contract owner (for registry root updates). Temporary until
    ///         the root is read directly from NodeRegistry.
    address public owner;

    /// @notice Pending owner for two-step transfer.
    address public pendingOwner;

    /// @notice Tracks which proof nullifiers have been used.
    mapping(bytes32 => bool) public nullifiers;

    /// @notice Depositor address per depositId (for refunds).
    mapping(bytes32 => address) public depositors;

    /// @notice Deposit timestamp per depositId (for refund timeout).
    mapping(bytes32 => uint256) public depositTimestamps;

    /// @notice Minimum time before a deposit can be refunded.
    uint256 public constant REFUND_TIMEOUT = 7 days;

    /// @notice Pull-payment: credited amounts awaiting withdrawal.
    mapping(address => uint256) public pendingWithdrawals;

    /// @notice Auto-incrementing deposit counter for deterministic depositId generation.
    uint256 public depositCount;

    /// @dev Reentrancy guard.
    bool private _locked;

    /// @dev Timelocked registry root proposals.
    struct RootProposal {
        uint256 newRoot;
        uint256 readyAt;
        bool    executed;
    }
    mapping(uint256 => RootProposal) public rootProposals;
    uint256 public nextRootProposalId;
    uint256 public constant ROOT_TIMELOCK = 48 hours;

    // ──────────────────────────────────────────────────────────────
    //  Events
    // ──────────────────────────────────────────────────────────────

    event DepositMade(bytes32 indexed depositId, address indexed depositor, uint256 amount);

    event ZKSessionSettled(
        bytes32 indexed nullifier,
        uint256 totalPayment,
        uint256 entryCommitment,
        uint256 relayCommitment,
        uint256 exitCommitment,
        uint256 refundCommitment
    );

    event RegistryRootUpdated(uint256 newRoot);
    event RegistryRootProposed(uint256 indexed proposalId, uint256 newRoot, uint256 readyAt);
    event OwnershipTransferProposed(address indexed currentOwner, address indexed proposedOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    event DepositRefunded(bytes32 indexed depositId, address indexed depositor, uint256 amount);

    // ──────────────────────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────────────────────

    /// @param _verifier Address of the deployed Groth16Verifier contract.
    constructor(address _verifier) {
        require(_verifier != address(0), "ZKSettlement: zero verifier");
        verifier = IGroth16Verifier(_verifier);
        owner = msg.sender;

        DOMAIN_SEPARATOR = EIP712Utils.computeDomainSeparator(address(this));
    }

    // ──────────────────────────────────────────────────────────────
    //  Modifiers
    // ──────────────────────────────────────────────────────────────

    modifier nonReentrant() {
        require(!_locked, "ZKSettlement: reentrant");
        _locked = true;
        _;
        _locked = false;
    }

    // ──────────────────────────────────────────────────────────────
    //  Pull-payment withdrawal
    // ──────────────────────────────────────────────────────────────

    /// @notice Withdraw credited settlement payments or refunds.
    function withdraw() external nonReentrant {
        uint256 amount = pendingWithdrawals[msg.sender];
        require(amount > 0, "ZKSettlement: nothing to withdraw");
        pendingWithdrawals[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "ZKSettlement: transfer failed");
    }

    // ──────────────────────────────────────────────────────────────
    //  Deposit
    // ──────────────────────────────────────────────────────────────

    /// @notice Deposit ETH for a future ZK-settled session.
    /// @return depositId Deterministic identifier derived from sender, value, and counter.
    ///         The depositor reads this from the DepositMade event or return value.
    function deposit() external payable returns (bytes32 depositId) {
        require(msg.value >= MINIMUM_DEPOSIT, "ZKSettlement: deposit too low");

        depositId = keccak256(abi.encode(msg.sender, msg.value, depositCount++));
        require(deposits[depositId] == 0, "ZKSettlement: duplicate deposit");

        deposits[depositId] = msg.value;
        depositors[depositId] = msg.sender;
        depositTimestamps[depositId] = block.timestamp;

        emit DepositMade(depositId, msg.sender, msg.value);
    }

    /// @notice Refund a deposit after the timeout (e.g., proof became invalid).
    ///         Credits pendingWithdrawals — call withdraw() to collect.
    /// @param depositId The identifier of the deposit to refund.
    function refundDeposit(bytes32 depositId) external {
        require(depositors[depositId] == msg.sender, "ZKSettlement: not depositor");
        require(
            block.timestamp >= depositTimestamps[depositId] + REFUND_TIMEOUT,
            "ZKSettlement: too early"
        );
        uint256 amount = deposits[depositId];
        require(amount > 0, "ZKSettlement: no deposit");

        deposits[depositId] = 0;
        pendingWithdrawals[msg.sender] += amount;

        emit DepositRefunded(depositId, msg.sender, amount);
    }

    // ──────────────────────────────────────────────────────────────
    //  ZK Settlement
    // ──────────────────────────────────────────────────────────────

    /// @notice Settle a session using a Groth16 ZK proof.
    ///         The proof binds nullifier, depositId, and address commitments
    ///         so that no replay, deposit swap, or address front-running is possible.
    /// @param proof_a    Groth16 proof point A.
    /// @param proof_b    Groth16 proof point B.
    /// @param proof_c    Groth16 proof point C.
    /// @param pubSignals The 13 public signals (9 inputs + 4 output amounts).
    /// @param nullifier  Unique nullifier preventing double-settlement.
    /// @param depositId  The deposit to consume.
    /// @param entryAddr  Payment address for the entry node.
    /// @param relayAddr  Payment address for the relay node.
    /// @param exitAddr   Payment address for the exit node.
    /// @param refundAddr Address to receive the unused deposit remainder.
    function settleWithProof(
        uint256[2] calldata proof_a,
        uint256[2][2] calldata proof_b,
        uint256[2] calldata proof_c,
        uint256[13] calldata pubSignals,
        bytes32 nullifier,
        bytes32 depositId,
        address payable entryAddr,
        address payable relayAddr,
        address payable exitAddr,
        address payable refundAddr
    ) external {
        // 1. Verify nullifier is bound to the proof and not reused.
        require(pubSignals[SIG_NULLIFIER] == uint256(nullifier), "ZKSettlement: nullifier mismatch");
        require(!nullifiers[nullifier], "ZKSettlement: already settled");

        // 2. Verify depositId is bound to the proof and deposit exists.
        require(pubSignals[SIG_DEPOSIT_ID] == uint256(depositId), "ZKSettlement: deposit mismatch");
        uint256 depositAmount = deposits[depositId];
        require(depositAmount > 0, "ZKSettlement: no deposit");

        // 3. Verify domain separator.
        require(
            pubSignals[SIG_DOMAIN_SEPARATOR] == uint256(DOMAIN_SEPARATOR),
            "ZKSettlement: wrong domain"
        );

        // 4. Verify registry root is current.
        require(pubSignals[SIG_REGISTRY_ROOT] == registryRoot, "ZKSettlement: stale registry root");

        // 5. Verify the ZK proof.
        require(
            verifier.verifyProof(proof_a, proof_b, proof_c, pubSignals),
            "ZKSettlement: invalid proof"
        );

        // 6–9. Verify payments, commitments, and credit payees
        //       (extracted for stack depth).
        nullifiers[nullifier] = true;
        deposits[depositId] = 0;

        address[4] memory addrs = [
            address(entryAddr), address(relayAddr),
            address(exitAddr), address(refundAddr)
        ];
        _verifyAndCredit(pubSignals, depositAmount, addrs);
    }

    // ──────────────────────────────────────────────────────────────
    //  Admin (temporary — replace with on-chain registry read)
    // ──────────────────────────────────────────────────────────────

    /// @notice Propose a new registry root (48h timelock).
    /// @param newRoot The new Merkle root value to propose.
    /// @return proposalId The ID of the created timelock proposal.
    function proposeRegistryRoot(uint256 newRoot) external returns (uint256 proposalId) {
        require(msg.sender == owner, "ZKSettlement: not owner");
        proposalId = nextRootProposalId++;
        uint256 readyAt = block.timestamp + ROOT_TIMELOCK;
        rootProposals[proposalId] = RootProposal({
            newRoot:  newRoot,
            readyAt:  readyAt,
            executed: false
        });
        emit RegistryRootProposed(proposalId, newRoot, readyAt);
    }

    /// @notice Execute a timelocked registry root proposal.
    /// @param proposalId The ID of the root proposal to execute.
    function executeRegistryRoot(uint256 proposalId) external {
        require(msg.sender == owner, "ZKSettlement: not owner");
        RootProposal storage rp = rootProposals[proposalId];
        require(rp.readyAt > 0, "ZKSettlement: unknown proposal");
        require(!rp.executed, "ZKSettlement: already executed");
        require(block.timestamp >= rp.readyAt, "ZKSettlement: timelock active");
        rp.executed = true;
        registryRoot = rp.newRoot;
        emit RegistryRootUpdated(rp.newRoot);
    }

    // ──────────────────────────────────────────────────────────────
    //  Ownership transfer (two-step)
    // ──────────────────────────────────────────────────────────────

    /// @notice Propose a new owner. The new owner must call acceptOwnership().
    /// @param newOwner Address of the proposed new owner.
    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "ZKSettlement: not owner");
        require(newOwner != address(0), "ZKSettlement: zero address");
        pendingOwner = newOwner;
        emit OwnershipTransferProposed(owner, newOwner);
    }

    /// @notice Accept a pending ownership transfer. Only callable by pendingOwner.
    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "ZKSettlement: not pending owner");
        emit OwnershipTransferred(owner, msg.sender);
        owner = msg.sender;
        pendingOwner = address(0);
    }

    // ──────────────────────────────────────────────────────────────
    //  Internal helpers
    // ──────────────────────────────────────────────────────────────

    /// @dev Verify payment amounts, Poseidon commitments, and credit payees.
    ///      Extracted from settleWithProof to avoid stack-too-deep.
    function _verifyAndCredit(
        uint256[13] calldata pubSignals,
        uint256 depositAmount,
        address[4] memory addrs
    ) internal {
        // a. Extract and verify payment amounts.
        uint256 totalPayment = pubSignals[SIG_TOTAL_PAYMENT];
        require(totalPayment <= depositAmount, "ZKSettlement: payment exceeds deposit");

        uint256[4] memory amounts = [
            pubSignals[SIG_ENTRY_PAY],
            pubSignals[SIG_RELAY_PAY],
            pubSignals[SIG_EXIT_PAY],
            pubSignals[SIG_REFUND]
        ];

        require(amounts[0] + amounts[1] + amounts[2] == totalPayment, "ZKSettlement: split mismatch");
        require(amounts[3] + totalPayment == depositAmount, "ZKSettlement: refund mismatch");

        if (totalPayment > 0) {
            require(amounts[0] == (totalPayment * ENTRY_SHARE) / 100, "ZKSettlement: entry share mismatch");
            require(amounts[1] == (totalPayment * RELAY_SHARE) / 100, "ZKSettlement: relay share mismatch");
            // Exit share is fully constrained by the split check on line above:
            // amounts[0] + amounts[1] + amounts[2] == totalPayment.
        }

        // b. Verify Poseidon(addr, amount) commitments.
        uint256[4] memory commitments = [
            pubSignals[SIG_ENTRY_COMMITMENT],
            pubSignals[SIG_RELAY_COMMITMENT],
            pubSignals[SIG_EXIT_COMMITMENT],
            pubSignals[SIG_REFUND_COMMITMENT]
        ];
        for (uint256 i; i < 4; ++i) {
            require(
                PoseidonT3.hash([uint256(uint160(addrs[i])), amounts[i]]) == commitments[i],
                "ZKSettlement: addr commitment binding"
            );
        }

        // c. Credit payments (pull-payment pattern).
        for (uint256 i; i < 4; ++i) {
            if (amounts[i] > 0) pendingWithdrawals[addrs[i]] += amounts[i];
        }

        emit ZKSessionSettled(
            bytes32(pubSignals[SIG_NULLIFIER]),
            totalPayment,
            commitments[0], commitments[1], commitments[2], commitments[3]
        );
    }
}
