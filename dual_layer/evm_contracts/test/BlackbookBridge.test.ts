/**
 * BlackbookBridge — Hardhat test suite
 *
 * Run:  cd evm_contracts && npm test
 */

import { expect } from "chai";
import { ethers } from "hardhat";
import { BlackbookBridge, MockERC20 } from "../typechain-types";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";

// A valid BlackBook base-58 ed25519 public key (44 chars)
const BB_WALLET = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";
// One token unit on BSC (18 decimals) — 1 USDC / 1 USDT
const ONE  = ethers.parseEther("1");
const TEN  = ethers.parseEther("10");
const HUGE = ethers.parseEther("200000"); // > MAX_DEPOSIT

describe("BlackbookBridge", () => {
  let bridge:   BlackbookBridge;
  let usdc:     MockERC20;
  let usdt:     MockERC20;
  let owner:    HardhatEthersSigner;
  let operator: HardhatEthersSigner;
  let user:     HardhatEthersSigner;
  let other:    HardhatEthersSigner;

  // Helper: deploy fresh instances before each test
  beforeEach(async () => {
    [owner, operator, user, other] = await ethers.getSigners();

    const MockERC20F = await ethers.getContractFactory("MockERC20");
    usdc = (await MockERC20F.deploy("USD Coin", "USDC")) as unknown as MockERC20;
    usdt = (await MockERC20F.deploy("Tether USD", "USDT")) as unknown as MockERC20;

    const BridgeF = await ethers.getContractFactory("BlackbookBridge");
    bridge = (await BridgeF.deploy(
      await usdc.getAddress(),
      await usdt.getAddress(),
      operator.address,
    )) as unknown as BlackbookBridge;

    // Fund user with stablecoins and approve the bridge
    await usdc.mint(user.address, ethers.parseEther("10000"));
    await usdt.mint(user.address, ethers.parseEther("10000"));
    await usdc.connect(user).approve(await bridge.getAddress(), ethers.MaxUint256);
    await usdt.connect(user).approve(await bridge.getAddress(), ethers.MaxUint256);
  });

  // ── Constructor ─────────────────────────────────────────────────────────────

  describe("constructor", () => {
    it("stores usdc, usdt, operator correctly", async () => {
      expect(await bridge.usdc()).to.equal(await usdc.getAddress());
      expect(await bridge.usdt()).to.equal(await usdt.getAddress());
      expect(await bridge.operator()).to.equal(operator.address);
    });

    it("reverts on zero token address", async () => {
      const BridgeF = await ethers.getContractFactory("BlackbookBridge");
      await expect(
        BridgeF.deploy(ethers.ZeroAddress, await usdt.getAddress(), operator.address),
      ).to.be.revertedWith("Zero token address");
    });

    it("reverts on zero operator address", async () => {
      const BridgeF = await ethers.getContractFactory("BlackbookBridge");
      await expect(
        BridgeF.deploy(await usdc.getAddress(), await usdt.getAddress(), ethers.ZeroAddress),
      ).to.be.revertedWith("Zero operator address");
    });
  });

  // ── deposit() ───────────────────────────────────────────────────────────────

  describe("deposit", () => {
    it("accepts USDC and emits UsdcDeposited", async () => {
      await expect(bridge.connect(user).deposit(await usdc.getAddress(), TEN, BB_WALLET))
        .to.emit(bridge, "UsdcDeposited")
        .withArgs(user.address, BB_WALLET, await usdc.getAddress(), TEN, 0n);

      expect(await usdc.balanceOf(await bridge.getAddress())).to.equal(TEN);
      expect(await bridge.depositCount()).to.equal(1n);
    });

    it("accepts USDT", async () => {
      await expect(bridge.connect(user).deposit(await usdt.getAddress(), TEN, BB_WALLET))
        .to.emit(bridge, "UsdcDeposited");
    });

    it("stores deposit record correctly", async () => {
      await bridge.connect(user).deposit(await usdc.getAddress(), TEN, BB_WALLET);
      const dep = await bridge.getDeposit(0n);
      expect(dep.depositor).to.equal(user.address);
      expect(dep.l1Wallet).to.equal(BB_WALLET);
      expect(dep.token).to.equal(await usdc.getAddress());
      expect(dep.amount).to.equal(TEN);
      expect(dep.bbMinted).to.be.false;
      expect(dep.l1MintSlot).to.equal(0n);
    });

    it("increments depositCount for multiple deposits", async () => {
      await bridge.connect(user).deposit(await usdc.getAddress(), TEN, BB_WALLET);
      await bridge.connect(user).deposit(await usdt.getAddress(), ONE, BB_WALLET);
      expect(await bridge.depositCount()).to.equal(2n);
    });

    it("accumulates totalDeposited", async () => {
      await bridge.connect(user).deposit(await usdc.getAddress(), TEN, BB_WALLET);
      await bridge.connect(user).deposit(await usdt.getAddress(), ONE, BB_WALLET);
      expect(await bridge.totalDeposited()).to.equal(TEN + ONE);
    });

    it("reverts on unsupported token", async () => {
      const FakeF = await ethers.getContractFactory("MockERC20");
      const fake = await FakeF.deploy("FAKE", "FAKE");
      await fake.mint(user.address, TEN);
      await fake.connect(user).approve(await bridge.getAddress(), TEN);

      await expect(
        bridge.connect(user).deposit(await fake.getAddress(), TEN, BB_WALLET),
      ).to.be.revertedWith("BlackbookBridge: token not supported");
    });

    it("reverts when amount below MIN_DEPOSIT", async () => {
      await expect(
        bridge.connect(user).deposit(await usdc.getAddress(), ethers.parseEther("0.5"), BB_WALLET),
      ).to.be.revertedWith("BlackbookBridge: amount too small (min 1 token)");
    });

    it("reverts when amount above MAX_DEPOSIT", async () => {
      await usdc.mint(user.address, HUGE);
      await expect(
        bridge.connect(user).deposit(await usdc.getAddress(), HUGE, BB_WALLET),
      ).to.be.revertedWith("BlackbookBridge: amount too large (max 100k tokens)");
    });

    it("reverts when l1Wallet too short", async () => {
      await expect(
        bridge.connect(user).deposit(await usdc.getAddress(), TEN, "short"),
      ).to.be.revertedWith("BlackbookBridge: invalid l1Wallet length");
    });

    it("reverts when l1Wallet too long (>44 chars)", async () => {
      const longWallet = "A".repeat(45);
      await expect(
        bridge.connect(user).deposit(await usdc.getAddress(), TEN, longWallet),
      ).to.be.revertedWith("BlackbookBridge: invalid l1Wallet length");
    });

    it("reverts when allowance is not set", async () => {
      // 'other' has no approval
      await usdc.mint(other.address, TEN);
      await expect(
        bridge.connect(other).deposit(await usdc.getAddress(), TEN, BB_WALLET),
      ).to.be.reverted;
    });
  });

  // ── ackDeposit() ────────────────────────────────────────────────────────────

  describe("ackDeposit", () => {
    beforeEach(async () => {
      await bridge.connect(user).deposit(await usdc.getAddress(), TEN, BB_WALLET);
    });

    it("operator acknowledges deposit, emits DepositAcknowledged", async () => {
      await expect(bridge.connect(operator).ackDeposit(0n, 12345n))
        .to.emit(bridge, "DepositAcknowledged")
        .withArgs(0n, 12345n);

      const dep = await bridge.getDeposit(0n);
      expect(dep.bbMinted).to.be.true;
      expect(dep.l1MintSlot).to.equal(12345n);
    });

    it("reverts on double-ack", async () => {
      await bridge.connect(operator).ackDeposit(0n, 1n);
      await expect(
        bridge.connect(operator).ackDeposit(0n, 2n),
      ).to.be.revertedWith("BlackbookBridge: already acknowledged");
    });

    it("reverts if not operator", async () => {
      await expect(bridge.connect(user).ackDeposit(0n, 1n))
        .to.be.revertedWith("BlackbookBridge: not operator");
    });

    it("reverts on non-existent deposit", async () => {
      await expect(
        bridge.connect(operator).ackDeposit(999n, 1n),
      ).to.be.revertedWith("BlackbookBridge: deposit not found");
    });
  });

  // ── releaseWithdrawal() ─────────────────────────────────────────────────────

  describe("releaseWithdrawal", () => {
    // Unique withdrawal IDs (bytes32)
    const WID1 = ethers.id("withdrawal-1") as `0x${string}`;
    const WID2 = ethers.id("withdrawal-2") as `0x${string}`;

    beforeEach(async () => {
      // Seed vault with USDC so there is something to release
      await bridge.connect(user).deposit(await usdc.getAddress(), TEN, BB_WALLET);
    });

    it("operator releases USDC to recipient, emits WithdrawalReleased", async () => {
      const before = await usdc.balanceOf(other.address);
      await expect(
        bridge.connect(operator).releaseWithdrawal(
          other.address, await usdc.getAddress(), TEN, WID1,
        ),
      )
        .to.emit(bridge, "WithdrawalReleased")
        .withArgs(other.address, await usdc.getAddress(), TEN, WID1);

      expect(await usdc.balanceOf(other.address)).to.equal(before + TEN);
    });

    it("prevents double-withdrawal with identical ID", async () => {
      await bridge.connect(operator).releaseWithdrawal(
        other.address, await usdc.getAddress(), TEN, WID1,
      );
      await bridge.connect(user).deposit(await usdc.getAddress(), TEN, BB_WALLET); // refund vault
      await expect(
        bridge.connect(operator).releaseWithdrawal(
          other.address, await usdc.getAddress(), TEN, WID1,   // same ID
        ),
      ).to.be.revertedWith("BlackbookBridge: already processed");
    });

    it("different IDs can process independently", async () => {
      await bridge.connect(user).deposit(await usdc.getAddress(), TEN, BB_WALLET); // extra USDC
      await bridge.connect(operator).releaseWithdrawal(
        other.address, await usdc.getAddress(), TEN, WID1,
      );
      await bridge.connect(operator).releaseWithdrawal(
        other.address, await usdc.getAddress(), TEN, WID2,
      );
      expect(await usdc.balanceOf(await bridge.getAddress())).to.equal(0n);
    });

    it("reverts when vault balance is insufficient", async () => {
      const bigAmount = ethers.parseEther("999999");
      await expect(
        bridge.connect(operator).releaseWithdrawal(
          other.address, await usdc.getAddress(), bigAmount, WID1,
        ),
      ).to.be.revertedWith("BlackbookBridge: insufficient vault balance");
    });

    it("reverts on unsupported token", async () => {
      const FakeF = await ethers.getContractFactory("MockERC20");
      const fake = await FakeF.deploy("FAKE", "FAKE");
      await expect(
        bridge.connect(operator).releaseWithdrawal(
          other.address, await fake.getAddress(), ONE, WID1,
        ),
      ).to.be.revertedWith("BlackbookBridge: token not supported");
    });

    it("reverts on zero recipient", async () => {
      await expect(
        bridge.connect(operator).releaseWithdrawal(
          ethers.ZeroAddress, await usdc.getAddress(), ONE, WID1,
        ),
      ).to.be.revertedWith("BlackbookBridge: zero recipient");
    });

    it("reverts if not operator", async () => {
      await expect(
        bridge.connect(user).releaseWithdrawal(
          other.address, await usdc.getAddress(), ONE, WID1,
        ),
      ).to.be.revertedWith("BlackbookBridge: not operator");
    });
  });

  // ── setOperator() ────────────────────────────────────────────────────────────

  describe("setOperator", () => {
    it("operator can rotate role, emits OperatorUpdated", async () => {
      await expect(bridge.connect(operator).setOperator(other.address))
        .to.emit(bridge, "OperatorUpdated")
        .withArgs(operator.address, other.address);
      expect(await bridge.operator()).to.equal(other.address);
    });

    it("reverts when non-operator tries to rotate", async () => {
      await expect(
        bridge.connect(user).setOperator(user.address),
      ).to.be.revertedWith("BlackbookBridge: not operator");
    });

    it("reverts on zero address", async () => {
      await expect(
        bridge.connect(operator).setOperator(ethers.ZeroAddress),
      ).to.be.revertedWith("BlackbookBridge: zero address");
    });
  });

  // ── view helpers ─────────────────────────────────────────────────────────────

  describe("view helpers", () => {
    it("usdcBalance / usdtBalance reflect vault holdings", async () => {
      await bridge.connect(user).deposit(await usdc.getAddress(), TEN, BB_WALLET);
      expect(await bridge.usdcBalance()).to.equal(TEN);
      expect(await bridge.usdtBalance()).to.equal(0n);
    });
  });
});
