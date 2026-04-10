// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {NodeRegistry}       from "../../src/NodeRegistry.sol";
import {SessionSettlement}  from "../../src/SessionSettlement.sol";
import {SlashingOracle}     from "../../src/SlashingOracle.sol";
import {ISlashingOracle}    from "../../src/interfaces/ISlashingOracle.sol";
import {INodeRegistry}      from "../../src/interfaces/INodeRegistry.sol";
import {ChallengeManager}   from "../../src/ChallengeManager.sol";
import {Treasury}           from "../../src/Treasury.sol";
import {EIP712Utils}        from "../../src/lib/EIP712Utils.sol";
import {TestKeys}           from "../helpers/TestKeys.sol";

/// @title CrossContractHandler
/// @notice Drives random sequences across NodeRegistry, SessionSettlement,
///         SlashingOracle, ChallengeManager, and Treasury for invariant testing.
///         Exercises the full slash → deactivation → withdrawal pipeline and
///         session → settle → payment pipeline.
contract CrossContractHandler is Test {
    NodeRegistry      public registry;
    SessionSettlement public settlement;
    SlashingOracle    public oracle;
    ChallengeManager  public cm;
    Treasury          public treasury;

    // ── Node operators (3 nodes for sessions) ──────────────────
    uint256 constant ENTRY_KEY  = 0xA001;
    uint256 constant RELAY_KEY  = 0xA002;
    uint256 constant EXIT_KEY   = 0xA003;
    uint256 constant CLIENT_KEY = 0xB001;

    address public entryOp;
    address public relayOp;
    address public exitOp;
    address public client;

    bytes32 public entryId;
    bytes32 public relayId;
    bytes32 public exitId;
    bytes32[3] public nodeIds;

    // ── Challenger for SlashingOracle ──────────────────────────
    uint256 internal challPk = 0xC0DE;
    address public challAddr;

    bytes32 public constant ATTESTATION_TYPEHASH = keccak256(
        "SlashAttestation(bytes32 nodeId,uint256 timestamp,bytes32 descriptionHash)"
    );

    // ── Ghost tracking ────────────────────────────────────────
    uint256 public ghostTotalDeposited;      // ETH deposited into all contracts
    uint256 public ghostTotalWithdrawn;      // ETH withdrawn from all contracts
    uint256 public openCount;
    uint256 public slashProposalCount;
    uint256 public ghostLivenessSlashCount;  // liveness slashes on exit node

    /// @dev Treasury owner — stored so treasuryClaim can use the correct address.
    address public treasuryOwner;

    constructor(
        NodeRegistry _registry,
        SessionSettlement _settlement,
        SlashingOracle _oracle,
        ChallengeManager _cm,
        Treasury _treasury,
        address _treasuryOwner
    ) {
        registry   = _registry;
        settlement = _settlement;
        oracle     = _oracle;
        cm         = _cm;
        treasury   = _treasury;
        treasuryOwner = _treasuryOwner;

        entryOp  = vm.addr(ENTRY_KEY);
        relayOp  = vm.addr(RELAY_KEY);
        exitOp   = vm.addr(EXIT_KEY);
        client   = vm.addr(CLIENT_KEY);
        challAddr = vm.addr(challPk);

        entryId = keccak256(abi.encode(entryOp, keccak256("entry-pub")));
        relayId = keccak256(abi.encode(relayOp, keccak256("relay-pub")));
        exitId  = keccak256(abi.encode(exitOp,  keccak256("exit-pub")));
        nodeIds = [entryId, relayId, exitId];
    }

    // ── EIP-712 helpers ────────────────────────────────────────

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("ShieldNode"),
                keccak256("1"),
                block.chainid,
                address(settlement)
            )
        );
    }

    function _digest(uint256 sid, uint256 cb, uint256 ts) internal view returns (bytes32) {
        bytes32 sh = keccak256(abi.encode(EIP712Utils.RECEIPT_TYPEHASH, sid, cb, ts));
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), sh));
    }

    function _sign(uint256 pk, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }

    function _signAttestation(bytes32 nodeId, uint256 ts, bytes32 descHash) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(ATTESTATION_TYPEHASH, nodeId, ts, descHash)
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", oracle.ATTESTATION_DOMAIN_SEPARATOR(), structHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(challPk, digest);
        return abi.encodePacked(r, s, v);
    }

    // ── Actions ────────────────────────────────────────────────

    /// @notice Open a session with a random deposit.
    function openSession(uint256 deposit) external {
        deposit = bound(deposit, 0.001 ether, 0.5 ether);
        vm.deal(client, client.balance + deposit);
        vm.prank(client);
        try settlement.openSession{value: deposit}(nodeIds, type(uint256).max) {
            ghostTotalDeposited += deposit;
            openCount++;
        } catch {}
    }

    /// @notice Settle a random open session cooperatively.
    function settleSession(uint256 sessionSeed, uint256 cumBytes) external {
        if (openCount == 0) return;
        uint256 sessionId = sessionSeed % openCount;
        cumBytes = bound(cumBytes, 0, 1e15);

        uint256 ts = block.timestamp;
        bytes32 d = _digest(sessionId, cumBytes, ts);
        bytes memory receipt = abi.encode(sessionId, cumBytes, ts, _sign(CLIENT_KEY, d), _sign(ENTRY_KEY, d), _sign(RELAY_KEY, d), _sign(EXIT_KEY, d));

        vm.prank(client);
        try settlement.settleSession(sessionId, receipt) {} catch {}
    }

    /// @notice Force-settle a session after timeout with 2-of-3 node sigs.
    function forceSettle(uint256 sessionSeed, uint256 cumBytes) external {
        if (openCount == 0) return;
        uint256 sessionId = sessionSeed % openCount;
        cumBytes = bound(cumBytes, 0, 1e15);

        vm.warp(block.timestamp + settlement.FORCE_SETTLE_TIMEOUT() + 1);

        uint256 ts = block.timestamp;
        bytes32 d = _digest(sessionId, cumBytes, ts);
        bytes memory receipt = abi.encode(sessionId, cumBytes, ts, _sign(ENTRY_KEY, d), _sign(RELAY_KEY, d), _sign(EXIT_KEY, d));

        vm.prank(exitOp);
        try settlement.forceSettle(sessionId, receipt) {} catch {}
    }

    /// @notice Withdraw from SessionSettlement for a random participant.
    function withdrawSettlement(uint256 addrSeed) external {
        address[4] memory addrs = [entryOp, relayOp, exitOp, client];
        address who = addrs[addrSeed % 4];
        uint256 pending = settlement.pendingWithdrawals(who);
        vm.prank(who);
        try settlement.withdraw() {
            ghostTotalWithdrawn += pending;
        } catch {}
    }

    /// @notice Propose a liveness (ChallengeFailure) slash on the exit node.
    function proposeLivenessSlash(uint256 seed) external {
        if (registry.getNode(exitId).owner == address(0)) return;

        bytes memory evidence = abi.encode(uint256(seed + slashProposalCount + 5000));
        vm.prank(challAddr);
        try oracle.proposeSlash(exitId, uint8(ISlashingOracle.SlashReason.ChallengeFailure), evidence) {
            slashProposalCount++;
        } catch {}
    }

    /// @notice Propose a fraud (ProvableLogging) slash on the exit node.
    function proposeFraudSlash(uint256 seed) external {
        if (registry.getNode(exitId).owner == address(0)) return;

        bytes32 descHash = keccak256(abi.encode("fraud", seed, slashProposalCount));
        uint256 ts = block.timestamp;
        bytes memory evidence = abi.encode(exitId, ts, descHash, _signAttestation(exitId, ts, descHash));

        vm.prank(challAddr);
        try oracle.proposeSlash(exitId, uint8(ISlashingOracle.SlashReason.ProvableLogging), evidence) {
            slashProposalCount++;
        } catch {}
    }

    /// @notice Execute a slash proposal after grace period.
    function executeSlash(uint256 proposalSeed) external {
        if (slashProposalCount == 0) return;
        uint256 proposalId = proposalSeed % slashProposalCount;

        // Check if this is a ChallengeFailure for ghost tracking.
        (,ISlashingOracle.SlashReason reason,,, bool executed) = oracle.proposals(proposalId);

        vm.warp(block.timestamp + oracle.GRACE_PERIOD() + 1);

        // Heartbeat to keep node active through time warps.
        if (registry.getNode(exitId).isActive) {
            vm.prank(exitOp);
            try registry.heartbeat(exitId) {} catch {}
        }

        try oracle.executeSlash(proposalId) {
            if (!executed && reason == ISlashingOracle.SlashReason.ChallengeFailure) {
                ghostLivenessSlashCount++;
            }
        } catch {}
    }

    /// @notice Withdraw slash rewards from SlashingOracle.
    function withdrawOracle(uint256 addrSeed) external {
        address[2] memory addrs = [challAddr, address(treasury)];
        address who = addrs[addrSeed % 2];
        uint256 pending = oracle.pendingWithdrawals(who);
        vm.prank(who);
        try oracle.withdraw() {
            ghostTotalWithdrawn += pending;
        } catch {}
    }

    /// @notice Heartbeat the exit node to keep it active.
    function heartbeatExit() external {
        if (registry.getNode(exitId).isActive) {
            vm.prank(exitOp);
            try registry.heartbeat(exitId) {} catch {}
        }
    }

    /// @notice Treasury claims slash proceeds from oracle.
    function treasuryClaim() external {
        uint256 pending = oracle.pendingWithdrawals(address(treasury));
        if (pending == 0) return;
        vm.prank(treasuryOwner);
        try treasury.claimFromOracle(address(oracle)) {} catch {}
    }
}

/// @title Cross-Contract Invariant Test
/// @notice Verifies invariants across the full contract system:
///         NodeRegistry ↔ SlashingOracle ↔ SessionSettlement ↔ Treasury.
contract CrossContractInvariantTest is Test {
    NodeRegistry       public registry;
    SessionSettlement  public settlement;
    SlashingOracle     public oracle;
    ChallengeManager   public cm;
    Treasury           public treasury;
    CrossContractHandler public handler;

    address public deployer = makeAddr("deployer");

    function setUp() public {
        vm.deal(deployer, 100 ether);

        vm.startPrank(deployer);
        treasury = new Treasury(deployer);

        // Predict oracle address for NodeRegistry constructor.
        uint64 nonce = vm.getNonce(deployer);
        address predictedOracle = vm.computeCreateAddress(deployer, nonce + 2);

        registry   = new NodeRegistry(predictedOracle);
        settlement = new SessionSettlement(address(registry), deployer);
        oracle     = new SlashingOracle(
            address(registry),
            address(treasury),
            address(settlement),
            deployer
        );
        require(address(oracle) == predictedOracle, "oracle mismatch");

        cm = new ChallengeManager(address(registry), payable(address(oracle)));

        handler = new CrossContractHandler(registry, settlement, oracle, cm, treasury, deployer);

        // Authorise the challenger (timelocked).
        oracle.proposeChallenger(handler.challAddr(), true);
        vm.warp(block.timestamp + oracle.CHALLENGER_TIMELOCK() + 1);
        oracle.executeChallenger(0);

        vm.stopPrank();

        // Register 3 nodes with meaningful stake.
        // Cache IDs before pranking (vm.prank is consumed by the next external call).
        address entryOp = handler.entryOp();
        address relayOp = handler.relayOp();
        address exitOp  = handler.exitOp();
        bytes32 eid = handler.entryId();
        bytes32 rid = handler.relayId();
        bytes32 xid = handler.exitId();

        vm.deal(entryOp, 10 ether);
        vm.deal(relayOp, 10 ether);
        vm.deal(exitOp, 10 ether);

        vm.prank(entryOp);
        registry.register{value: 1 ether}(eid, keccak256("entry-pub"), "1.1.1.1:51820", TestKeys.entry_key());
        vm.prank(relayOp);
        registry.register{value: 1 ether}(rid, keccak256("relay-pub"), "2.2.2.2:51820", TestKeys.relay_key());
        vm.prank(exitOp);
        registry.register{value: 1 ether}(xid, keccak256("exit-pub"), "3.3.3.3:51820", TestKeys.exit_key());

        vm.prank(entryOp);
        registry.updatePricePerByte(eid, 1);
        vm.prank(relayOp);
        registry.updatePricePerByte(rid, 1);
        vm.prank(exitOp);
        registry.updatePricePerByte(xid, 1);

        targetContract(address(handler));
    }

    /// @notice SlashingOracle solvency: balance >= total owed via pending withdrawals.
    function invariant_oracle_solvency() public view {
        uint256 owed = oracle.pendingWithdrawals(handler.challAddr())
                     + oracle.pendingWithdrawals(address(treasury));
        assertLe(owed, address(oracle).balance, "oracle insolvent");
    }

    /// @notice SessionSettlement solvency: balance >= total owed.
    function invariant_settlement_solvency() public view {
        uint256 owed = settlement.pendingWithdrawals(handler.entryOp())
                     + settlement.pendingWithdrawals(handler.relayOp())
                     + settlement.pendingWithdrawals(handler.exitOp())
                     + settlement.pendingWithdrawals(handler.client());
        assertLe(owed, address(settlement).balance, "settlement insolvent");
    }

    /// @notice Liveness failure count never exceeds the threshold — it resets
    ///         to 0 when the threshold is reached and deactivation fires.
    function invariant_liveness_count_bounded() public view {
        assertLt(
            oracle.livenessFailureCount(handler.exitId()),
            oracle.LIVENESS_BAN_THRESHOLD(),
            "liveness count should reset at threshold"
        );
    }

    /// @notice Slash penalty monotonicity: permanent slash counts only increase.
    function invariant_slash_count_monotonic() public view {
        INodeRegistry.NodeInfo memory info = registry.getNode(handler.exitId());
        assertLe(
            info.slashCount,
            registry.permanentSlashCount(handler.exitId()) + 1,
            "slash count exceeds permanent count"
        );
    }
}
