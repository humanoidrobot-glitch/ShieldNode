// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

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

    // ──────────────────────────────────────────────────────────────
    //  Modifiers
    // ──────────────────────────────────────────────────────────────

    modifier onlyOwner() {
        require(msg.sender == owner, "Treasury: not owner");
        _;
    }

    // ──────────────────────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────────────────────

    constructor() {
        owner = msg.sender;
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
        require(amount <= address(this).balance, "Treasury: insufficient balance");

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
        req.executed = true;

        // Interaction
        (bool ok, ) = req.to.call{value: req.amount}("");
        require(ok, "Treasury: transfer failed");

        withdrawalCount++;
        emit WithdrawalExecuted(withdrawalId, req.to, req.amount);
    }

    // ──────────────────────────────────────────────────────────────
    //  Views
    // ──────────────────────────────────────────────────────────────

    /// @notice Current ETH balance held by the treasury.
    function balance() external view returns (uint256) {
        return address(this).balance;
    }
}
