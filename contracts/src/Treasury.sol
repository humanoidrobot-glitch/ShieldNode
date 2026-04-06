// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal interface for pull-payment withdrawal.
interface IWithdrawable {
    function withdraw() external;
}

/// @title Treasury
/// @notice Receives protocol revenue (e.g. slashing proceeds) and allows the
///         owner to withdraw after a timelock.
contract Treasury {
    // ──────────────────────────────────────────────────────────────
    //  Constants
    // ──────────────────────────────────────────────────────────────

    /// @notice Minimum delay between queuing and executing a withdrawal.
    uint256 public constant TIMELOCK_DURATION = 48 hours;

    // ──────────────────────────────────────────────────────────────
    //  State
    // ──────────────────────────────────────────────────────────────

    /// @notice Contract owner (deployer).
    address public owner;

    /// @notice Pending owner for two-step transfer.
    address public pendingOwner;

    /// @notice Guardian address that can veto queued withdrawals during timelock.
    address public guardian;

    /// @notice Running counter of deposit operations (for history).
    uint256 public depositCount;

    /// @notice Running counter of withdrawal operations.
    uint256 public withdrawalCount;

    /// @dev Pending withdrawal request.
    struct WithdrawalRequest {
        address to;
        uint256 amount;
        uint256 readyAt;
        bool    executed;
    }

    /// @notice Mapping of withdrawal-id to its request.
    mapping(uint256 => WithdrawalRequest) public withdrawals;

    /// @notice Next withdrawal-id.
    uint256 public nextWithdrawalId;

    /// @notice Sum of all queued-but-unresolved withdrawal amounts.
    uint256 public totalPending;

    /// @dev Timelocked guardian proposals.
    struct GuardianProposal {
        address newGuardian;
        uint256 readyAt;
        bool    executed;
    }
    mapping(uint256 => GuardianProposal) public guardianProposals;
    uint256 public nextGuardianProposalId;

    // ──────────────────────────────────────────────────────────────
    //  Events
    // ──────────────────────────────────────────────────────────────

    /// @notice Emitted when ETH is deposited.
    event Deposited(address indexed from, uint256 amount, uint256 indexed depositId);

    /// @notice Emitted when a withdrawal is queued.
    event WithdrawalQueued(
        uint256 indexed withdrawalId,
        address indexed to,
        uint256 amount,
        uint256 readyAt
    );

    /// @notice Emitted when a queued withdrawal is executed.
    event WithdrawalExecuted(uint256 indexed withdrawalId, address indexed to, uint256 amount);

    /// @notice Emitted when a queued withdrawal is cancelled.
    event WithdrawalCancelled(uint256 indexed withdrawalId);

    /// @notice Emitted when the guardian is updated.
    event GuardianUpdated(address indexed oldGuardian, address indexed newGuardian);

    /// @notice Emitted when a guardian change is proposed.
    event GuardianProposed(uint256 indexed proposalId, address indexed newGuardian, uint256 readyAt);

    event OwnershipTransferProposed(address indexed currentOwner, address indexed proposedOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // ──────────────────────────────────────────────────────────────
    //  Modifiers
    // ──────────────────────────────────────────────────────────────

    modifier onlyOwner() {
        require(msg.sender == owner, "Treasury: not owner");
        _;
    }

    modifier onlyGuardian() {
        require(msg.sender == guardian, "Treasury: not guardian");
        _;
    }

    // ──────────────────────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────────────────────

    /// @param _guardian Address that can veto queued withdrawals.
    constructor(address _guardian) {
        owner = msg.sender;
        guardian = _guardian;
    }

    // ──────────────────────────────────────────────────────────────
    //  Receive
    // ──────────────────────────────────────────────────────────────

    /// @notice Accept ETH deposits.
    receive() external payable {
        uint256 id = depositCount++;
        emit Deposited(msg.sender, msg.value, id);
    }

    // ──────────────────────────────────────────────────────────────
    //  Withdrawal (timelock)
    // ──────────────────────────────────────────────────────────────

    /// @notice Queue a withdrawal request. Executable after TIMELOCK_DURATION.
    /// @param to     Recipient address.
    /// @param amount Amount of ETH to withdraw.
    /// @return withdrawalId The ID of the queued withdrawal.
    function queueWithdrawal(address to, uint256 amount)
        external
        onlyOwner
        returns (uint256 withdrawalId)
    {
        require(to != address(0), "Treasury: zero address");
        require(amount > 0, "Treasury: zero amount");
        require(amount <= address(this).balance - totalPending, "Treasury: insufficient available balance");

        totalPending += amount;
        withdrawalId = nextWithdrawalId++;
        uint256 readyAt = block.timestamp + TIMELOCK_DURATION;

        withdrawals[withdrawalId] = WithdrawalRequest({
            to:       to,
            amount:   amount,
            readyAt:  readyAt,
            executed: false
        });

        emit WithdrawalQueued(withdrawalId, to, amount, readyAt);
    }

    /// @notice Execute a previously queued withdrawal after its timelock.
    /// @param withdrawalId The withdrawal to execute.
    function executeWithdrawal(uint256 withdrawalId) external onlyOwner {
        WithdrawalRequest storage req = withdrawals[withdrawalId];
        require(req.amount > 0, "Treasury: unknown withdrawal");
        require(!req.executed, "Treasury: already executed");
        require(block.timestamp >= req.readyAt, "Treasury: timelock not passed");
        require(req.amount <= address(this).balance, "Treasury: insufficient balance");

        // Effects
        totalPending -= req.amount;
        req.executed = true;

        // Interaction
        (bool ok, ) = req.to.call{value: req.amount}("");
        require(ok, "Treasury: transfer failed");

        withdrawalCount++;
        emit WithdrawalExecuted(withdrawalId, req.to, req.amount);
    }

    // ──────────────────────────────────────────────────────────────
    //  Cancel (guardian or owner)
    // ──────────────────────────────────────────────────────────────

    /// @notice Cancel a queued withdrawal during the timelock period.
    ///         Callable by either the owner or the guardian.
    /// @param withdrawalId The withdrawal to cancel.
    function cancelWithdrawal(uint256 withdrawalId) external {
        require(
            msg.sender == owner || msg.sender == guardian,
            "Treasury: not owner or guardian"
        );
        WithdrawalRequest storage req = withdrawals[withdrawalId];
        require(req.amount > 0, "Treasury: unknown withdrawal");
        require(!req.executed, "Treasury: already executed");

        totalPending -= req.amount;
        delete withdrawals[withdrawalId];

        emit WithdrawalCancelled(withdrawalId);
    }

    // ──────────────────────────────────────────────────────────────
    //  Claim from pull-payment contracts
    // ──────────────────────────────────────────────────────────────

    /// @notice Claim funds from a pull-payment contract (e.g. SlashingOracle).
    ///         The source contract sends ETH to this contract via its withdraw(),
    ///         which is received by receive() and emits a Deposited event.
    /// @param source Address of the pull-payment contract to withdraw from.
    function claimFromOracle(address source) external onlyOwner {
        IWithdrawable(source).withdraw();
    }

    // ──────────────────────────────────────────────────────────────
    //  Admin
    // ──────────────────────────────────────────────────────────────

    /// @notice Propose a new guardian (48h timelock).
    /// @param _guardian Address of the proposed new guardian.
    /// @return proposalId The ID of the created proposal.
    function proposeGuardian(address _guardian) external onlyOwner returns (uint256 proposalId) {
        proposalId = nextGuardianProposalId++;
        uint256 readyAt = block.timestamp + TIMELOCK_DURATION;
        guardianProposals[proposalId] = GuardianProposal({
            newGuardian: _guardian,
            readyAt:     readyAt,
            executed:    false
        });
        emit GuardianProposed(proposalId, _guardian, readyAt);
    }

    /// @notice Execute a timelocked guardian proposal.
    /// @param proposalId The guardian proposal to execute.
    function executeGuardian(uint256 proposalId) external onlyOwner {
        GuardianProposal storage gp = guardianProposals[proposalId];
        require(gp.readyAt > 0, "Treasury: unknown proposal");
        require(!gp.executed, "Treasury: already executed");
        require(block.timestamp >= gp.readyAt, "Treasury: timelock active");
        gp.executed = true;
        emit GuardianUpdated(guardian, gp.newGuardian);
        guardian = gp.newGuardian;
    }

    // ──────────────────────────────────────────────────────────────
    //  Ownership transfer (two-step)
    // ──────────────────────────────────────────────────────────────

    /// @notice Propose a new owner. The new owner must call acceptOwnership().
    /// @param newOwner Address of the proposed new owner.
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Treasury: zero address");
        pendingOwner = newOwner;
        emit OwnershipTransferProposed(owner, newOwner);
    }

    /// @notice Accept a pending ownership transfer. Only callable by pendingOwner.
    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "Treasury: not pending owner");
        emit OwnershipTransferred(owner, msg.sender);
        owner = msg.sender;
        pendingOwner = address(0);
    }

    // ──────────────────────────────────────────────────────────────
    //  Views
    // ──────────────────────────────────────────────────────────────

    /// @notice Current ETH balance held by the treasury.
    function balance() external view returns (uint256) {
        return address(this).balance;
    }
}
