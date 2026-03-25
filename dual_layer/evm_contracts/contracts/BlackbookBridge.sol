// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title  BlackbookBridge
 * @notice Non-custodial USDC/USDT vault on BNB Chain that bridges to BlackBook L1.
 *
 * ── Deposit flow ──────────────────────────────────────────────────────────────
 *   1. User calls  deposit(token, amount, l1Wallet)
 *      • USDC or USDT is pulled from the user into this contract.
 *      • A UsdcDeposited event is emitted containing the user's L1 wallet address.
 *   2. BlackBook L1 watcher detects UsdcDeposited → mints BB to l1Wallet.
 *   3. L1 operator calls ackDeposit(depositIndex, l1MintSlot) to record
 *      the on-chain audit trail.
 *
 * ── Withdrawal flow ───────────────────────────────────────────────────────────
 *   1. User requests a withdrawal on L1 (burns BB).
 *   2. L1 operator calls releaseWithdrawal(to, token, amount, withdrawalId).
 *   3. USDC/USDT is transferred from the vault to the user's BSC address.
 *
 * ── Token notes ───────────────────────────────────────────────────────────────
 *   Both Binance-Peg USDC (0x8AC7…) and Binance-Peg BSC-USD USDT (0x55d3…)
 *   have 18 decimals on BSC mainnet. All amounts are in those 18-decimal units.
 */
contract BlackbookBridge is ReentrancyGuard {
    using SafeERC20 for IERC20;

    // ── Constants ─────────────────────────────────────────────────────────────

    /// Minimum deposit: 1 whole token (1e18 units).
    uint256 public constant MIN_DEPOSIT = 1e18;
    /// Maximum single deposit: 100,000 tokens.
    uint256 public constant MAX_DEPOSIT = 100_000 * 1e18;
    /// Valid BB wallet length range (base58-encoded Ed25519 pubkeys are 32–44 chars).
    uint256 public constant MIN_L1_WALLET_LEN = 32;
    uint256 public constant MAX_L1_WALLET_LEN = 44;

    // ── State ─────────────────────────────────────────────────────────────────

    /// Binance-Peg USD Coin (18 dec) — the only USDC token accepted.
    IERC20 public immutable usdc;
    /// Binance-Peg BSC-USD (18 dec) — the only USDT token accepted.
    IERC20 public immutable usdt;

    /// L1 relayer hot wallet — sole authority for ackDeposit / releaseWithdrawal.
    address public operator;

    /// Monotonic deposit counter.  Starts at 0.
    uint256 public depositCount;
    /// Cumulative token units ever deposited (across all tokens).
    uint256 public totalDeposited;
    /// Cumulative token units ever released in withdrawals.
    uint256 public totalWithdrawn;

    struct DepositInfo {
        address depositor;   // BSC address of the depositor
        string  l1Wallet;    // BlackBook L1 base58 wallet to receive BB
        address token;       // USDC or USDT
        uint256 amount;      // token units deposited
        uint256 createdAt;   // block.timestamp at deposit time
        bool    bbMinted;    // true after operator calls ackDeposit
        uint64  l1MintSlot;  // BlackBook L1 slot when BB was minted
    }

    /// Deposit index → deposit details.
    mapping(uint256 => DepositInfo) public deposits;

    /// withdrawalId → processed.  Prevents double-release.
    mapping(bytes32 => bool) public processedWithdrawals;

    // ── Events ────────────────────────────────────────────────────────────────

    /**
     * @notice Emitted when USDC/USDT lands in the vault.
     *         The BlackBook L1 watcher listens for this event and mints BB
     *         to `l1Wallet` automatically.
     */
    event UsdcDeposited(
        address indexed depositor,
        string          l1Wallet,
        address indexed token,
        uint256         amount,
        uint256         depositIndex
    );

    /// Emitted by the operator after BB has been minted on L1.
    event DepositAcknowledged(uint256 indexed depositIndex, uint64 l1MintSlot);

    /// Emitted when the operator sends USDC/USDT back to a user.
    event WithdrawalReleased(
        address indexed to,
        address indexed token,
        uint256         amount,
        bytes32 indexed withdrawalId
    );

    /// Emitted when the operator role is transferred.
    event OperatorUpdated(address indexed oldOperator, address indexed newOperator);

    // ── Modifiers ─────────────────────────────────────────────────────────────

    modifier onlyOperator() {
        require(msg.sender == operator, "BlackbookBridge: not operator");
        _;
    }

    // ── Constructor ───────────────────────────────────────────────────────────

    /**
     * @param _usdc     Binance-Peg USD Coin contract address.
     * @param _usdt     Binance-Peg BSC-USD contract address.
     * @param _operator Initial operator (BlackBook L1 relayer hot wallet).
     */
    constructor(address _usdc, address _usdt, address _operator) {
        require(_usdc     != address(0), "BlackbookBridge: zero usdc address");
        require(_usdt     != address(0), "BlackbookBridge: zero usdt address");
        require(_operator != address(0), "BlackbookBridge: zero operator address");
        usdc     = IERC20(_usdc);
        usdt     = IERC20(_usdt);
        operator = _operator;
    }

    // ── User-facing: deposit ──────────────────────────────────────────────────

    /**
     * @notice Deposit USDC or USDT into the BlackBook vault.
     *         The caller MUST first approve this contract to spend `amount`
     *         of `token` (standard ERC-20 approve).
     *
     * @param token     Address of USDC or USDT.
     * @param amount    Token units to deposit (1 USDC = 1e18).
     * @param l1Wallet  Your BlackBook L1 wallet in base58 format (32–44 chars).
     *                  BB tokens will be minted here on the L1 chain.
     */
    function deposit(
        address token,
        uint256 amount,
        string  calldata l1Wallet
    ) external nonReentrant {
        require(
            token == address(usdc) || token == address(usdt),
            "BlackbookBridge: token not supported"
        );
        require(amount >= MIN_DEPOSIT, "BlackbookBridge: amount too small (min 1 token)");
        require(amount <= MAX_DEPOSIT, "BlackbookBridge: amount too large (max 100k tokens)");

        uint256 wlen = bytes(l1Wallet).length;
        require(
            wlen >= MIN_L1_WALLET_LEN && wlen <= MAX_L1_WALLET_LEN,
            "BlackbookBridge: invalid l1Wallet length (must be 32-44 chars)"
        );

        // Pull tokens from caller
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);

        // Record
        uint256 index = depositCount++;
        deposits[index] = DepositInfo({
            depositor:  msg.sender,
            l1Wallet:   l1Wallet,
            token:      token,
            amount:     amount,
            createdAt:  block.timestamp,
            bbMinted:   false,
            l1MintSlot: 0
        });
        totalDeposited += amount;

        emit UsdcDeposited(msg.sender, l1Wallet, token, amount, index);
    }

    // ── Operator: acknowledge minting ─────────────────────────────────────────

    /**
     * @notice Record that BB has been successfully minted on BlackBook L1.
     *         Creates an auditable on-chain link between this BSC deposit and
     *         the L1 mint slot.
     *
     * @param depositIndex  Index of the deposit to acknowledge.
     * @param l1MintSlot    BlackBook L1 slot when BB was minted.
     */
    function ackDeposit(uint256 depositIndex, uint64 l1MintSlot) external onlyOperator {
        DepositInfo storage dep = deposits[depositIndex];
        require(dep.amount > 0, "BlackbookBridge: deposit not found");
        require(!dep.bbMinted,  "BlackbookBridge: already acknowledged");
        dep.bbMinted   = true;
        dep.l1MintSlot = l1MintSlot;
        emit DepositAcknowledged(depositIndex, l1MintSlot);
    }

    // ── Operator: release withdrawal ──────────────────────────────────────────

    /**
     * @notice Transfer USDC/USDT from the vault to a user's BSC address.
     *         Called by the L1 operator after the user burns BB on L1.
     *
     * @param to            Recipient BSC address.
     * @param token         USDC or USDT.
     * @param amount        Token units to release.
     * @param withdrawalId  Unique L1 withdrawal ID — prevents double release.
     */
    function releaseWithdrawal(
        address to,
        address token,
        uint256 amount,
        bytes32 withdrawalId
    ) external nonReentrant onlyOperator {
        require(
            token == address(usdc) || token == address(usdt),
            "BlackbookBridge: token not supported"
        );
        require(to     != address(0), "BlackbookBridge: zero recipient");
        require(amount >  0,          "BlackbookBridge: zero amount");
        require(!processedWithdrawals[withdrawalId], "BlackbookBridge: already processed");
        require(
            IERC20(token).balanceOf(address(this)) >= amount,
            "BlackbookBridge: insufficient vault balance"
        );

        processedWithdrawals[withdrawalId] = true;
        totalWithdrawn += amount;

        IERC20(token).safeTransfer(to, amount);
        emit WithdrawalReleased(to, token, amount, withdrawalId);
    }

    // ── Operator: governance ──────────────────────────────────────────────────

    /**
     * @notice Transfer the operator role to a new address.
     * @param newOperator The new operator. Must not be the zero address.
     */
    function setOperator(address newOperator) external onlyOperator {
        require(newOperator != address(0), "BlackbookBridge: zero address");
        emit OperatorUpdated(operator, newOperator);
        operator = newOperator;
    }

    // ── View helpers ──────────────────────────────────────────────────────────

    /// Vault USDC balance (18-decimal units).
    function usdcBalance() external view returns (uint256) {
        return usdc.balanceOf(address(this));
    }

    /// Vault USDT balance (18-decimal units).
    function usdtBalance() external view returns (uint256) {
        return usdt.balanceOf(address(this));
    }

    /// Full deposit record by index.
    function getDeposit(uint256 index) external view returns (DepositInfo memory) {
        return deposits[index];
    }
}
