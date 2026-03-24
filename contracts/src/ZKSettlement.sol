// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IGroth16Verifier
/// @notice Interface for the auto-generated Groth16 verifier from snarkjs.
///         The actual contract is exported by `snarkjs zkey export solidityverifier`
///         and deployed separately.
interface IGroth16Verifier {
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[7] calldata _pubSignals
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

    // Public signal indices (must match circuit's public input order)
    uint256 private constant SIG_DOMAIN_SEPARATOR   = 0;
    uint256 private constant SIG_TOTAL_PAYMENT      = 1;
    uint256 private constant SIG_ENTRY_COMMITMENT   = 2;
    uint256 private constant SIG_RELAY_COMMITMENT   = 3;
    uint256 private constant SIG_EXIT_COMMITMENT    = 4;
    uint256 private constant SIG_REFUND_COMMITMENT  = 5;
    uint256 private constant SIG_REGISTRY_ROOT      = 6;

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
    //  Deposit
    // ──────────────────────────────────────────────────────────────

    /// @notice Deposit ETH for a future ZK-settled session.
    /// @param depositId A unique identifier (e.g., hash of session params).
    ///        The depositor knows this; it is NOT revealed during settlement.
    function deposit(bytes32 depositId) external payable {
        require(msg.value >= MINIMUM_DEPOSIT, "ZKSettlement: deposit too low");
        require(deposits[depositId] == 0, "ZKSettlement: duplicate deposit");

        deposits[depositId] = msg.value;

        emit DepositMade(depositId, msg.sender, msg.value);
    }

    // ──────────────────────────────────────────────────────────────
    //  ZK Settlement
    // ──────────────────────────────────────────────────────────────

    /// @notice Settle a session using a Groth16 ZK proof.
    function settleWithProof(
        uint256[2] calldata proof_a,
        uint256[2][2] calldata proof_b,
        uint256[2] calldata proof_c,
        uint256[7] calldata pubSignals,
        bytes32 nullifier,
        bytes32 depositId,
        address payable entryAddr,
        address payable relayAddr,
        address payable exitAddr,
        address payable refundAddr
    ) external {
        // 1. Check nullifier not used.
        require(!nullifiers[nullifier], "ZKSettlement: already settled");

        // 2. Check deposit exists.
        uint256 depositAmount = deposits[depositId];
        require(depositAmount > 0, "ZKSettlement: no deposit");

        // 3. Verify domain separator matches this contract.
        require(
            pubSignals[SIG_DOMAIN_SEPARATOR] == uint256(DOMAIN_SEPARATOR),
            "ZKSettlement: wrong domain"
        );

        // 4. Verify registry root is current.
        require(
            pubSignals[SIG_REGISTRY_ROOT] == registryRoot,
            "ZKSettlement: stale registry root"
        );

        // 5. Verify the ZK proof.
        require(
            verifier.verifyProof(proof_a, proof_b, proof_c, pubSignals),
            "ZKSettlement: invalid proof"
        );

        // 6. Extract payment amounts from public signals.
        uint256 totalPayment = pubSignals[SIG_TOTAL_PAYMENT];
        require(totalPayment <= depositAmount, "ZKSettlement: payment exceeds deposit");

        // 7. Compute the 25/25/50 split (must match SessionSettlement).
        uint256 entryPay = (totalPayment * ENTRY_SHARE) / 100;
        uint256 relayPay = (totalPayment * RELAY_SHARE) / 100;
        uint256 exitPay  = totalPayment - entryPay - relayPay;
        uint256 refund   = depositAmount - totalPayment;

        // 8. Effects — mark as settled before transfers.
        nullifiers[nullifier] = true;
        deposits[depositId] = 0;

        // 9. Interactions — distribute payments.
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
