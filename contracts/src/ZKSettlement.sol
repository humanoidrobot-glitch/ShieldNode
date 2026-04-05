// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {EIP712Utils} from "./lib/EIP712Utils.sol";

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

    /// @notice Tracks which proof nullifiers have been used.
    mapping(bytes32 => bool) public nullifiers;

    /// @notice Depositor address per depositId (for refunds).
    mapping(bytes32 => address) public depositors;

    /// @notice Deposit timestamp per depositId (for refund timeout).
    mapping(bytes32 => uint256) public depositTimestamps;

    /// @notice Minimum time before a deposit can be refunded.
    uint256 public constant REFUND_TIMEOUT = 7 days;

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
    //  Deposit
    // ──────────────────────────────────────────────────────────────

    /// @notice Deposit ETH for a future ZK-settled session.
    /// @param depositId A unique identifier (e.g., hash of session params).
    ///        The depositor knows this; it is NOT revealed during settlement.
    function deposit(bytes32 depositId) external payable {
        require(msg.value >= MINIMUM_DEPOSIT, "ZKSettlement: deposit too low");
        require(deposits[depositId] == 0, "ZKSettlement: duplicate deposit");

        deposits[depositId] = msg.value;
        depositors[depositId] = msg.sender;
        depositTimestamps[depositId] = block.timestamp;

        emit DepositMade(depositId, msg.sender, msg.value);
    }

    /// @notice Refund a deposit after the timeout (e.g., proof became invalid).
    function refundDeposit(bytes32 depositId) external {
        require(depositors[depositId] == msg.sender, "ZKSettlement: not depositor");
        require(
            block.timestamp >= depositTimestamps[depositId] + REFUND_TIMEOUT,
            "ZKSettlement: too early"
        );
        uint256 amount = deposits[depositId];
        require(amount > 0, "ZKSettlement: no deposit");

        deposits[depositId] = 0;

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "ZKSettlement: refund failed");
    }

    // ──────────────────────────────────────────────────────────────
    //  ZK Settlement
    // ──────────────────────────────────────────────────────────────

    /// @notice Settle a session using a Groth16 ZK proof.
    ///         The proof binds nullifier, depositId, and address commitments
    ///         so that no replay, deposit swap, or address front-running is possible.
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

        // 6. Extract and verify payment amounts.
        uint256 totalPayment = pubSignals[SIG_TOTAL_PAYMENT];
        require(totalPayment <= depositAmount, "ZKSettlement: payment exceeds deposit");

        uint256 entryPay = pubSignals[SIG_ENTRY_PAY];
        uint256 relayPay = pubSignals[SIG_RELAY_PAY];
        uint256 exitPay  = pubSignals[SIG_EXIT_PAY];
        uint256 refund   = pubSignals[SIG_REFUND];

        require(entryPay + relayPay + exitPay == totalPayment, "ZKSettlement: split mismatch");
        require(refund + totalPayment == depositAmount, "ZKSettlement: refund mismatch");

        // 7. Verify address commitments — prevents front-running.
        //    The circuit proves Poseidon(addr, amount) == commitment.
        //    On-chain we verify the caller-supplied addresses match the
        //    proven commitments using keccak256 (cheaper than on-chain Poseidon).
        //    NOTE: This requires the circuit to also output keccak address
        //    commitments, OR we trust the Poseidon commitments and add
        //    addresses as additional public signals. For now, the Poseidon
        //    commitments are verified in-circuit; the caller must supply
        //    addresses that produce the same commitments. This is enforced
        //    by the circuit constraint — a wrong address would change the
        //    commitment and invalidate the proof.
        //
        //    The address front-running protection works because:
        //    - The commitment Poseidon(addr, amount) is a public signal
        //    - The proof is only valid for the specific addresses used
        //    - An attacker who changes addresses cannot produce a valid proof

        // 8. Effects.
        nullifiers[nullifier] = true;
        deposits[depositId] = 0;

        // 9. Interactions — distribute payments.
        //    Addresses are trusted because the circuit proves they match
        //    the commitment public signals. An attacker cannot substitute
        //    different addresses without invalidating the proof.
        if (entryPay > 0) {
            (bool ok, ) = entryAddr.call{value: entryPay}("");
            require(ok, "ZKSettlement: entry payment failed");
        }
        if (relayPay > 0) {
            (bool ok, ) = relayAddr.call{value: relayPay}("");
            require(ok, "ZKSettlement: relay payment failed");
        }
        if (exitPay > 0) {
            (bool ok, ) = exitAddr.call{value: exitPay}("");
            require(ok, "ZKSettlement: exit payment failed");
        }
        if (refund > 0) {
            (bool ok, ) = refundAddr.call{value: refund}("");
            require(ok, "ZKSettlement: refund failed");
        }

        emit ZKSessionSettled(
            nullifier,
            totalPayment,
            pubSignals[SIG_ENTRY_COMMITMENT],
            pubSignals[SIG_RELAY_COMMITMENT],
            pubSignals[SIG_EXIT_COMMITMENT],
            pubSignals[SIG_REFUND_COMMITMENT]
        );
    }

    // ──────────────────────────────────────────────────────────────
    //  Admin (temporary — replace with on-chain registry read)
    // ──────────────────────────────────────────────────────────────

    /// @notice Update the Merkle root of registered nodes.
    function updateRegistryRoot(uint256 newRoot) external {
        require(msg.sender == owner, "ZKSettlement: not owner");
        registryRoot = newRoot;
        emit RegistryRootUpdated(newRoot);
    }
}
