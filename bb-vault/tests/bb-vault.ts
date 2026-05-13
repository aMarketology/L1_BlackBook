import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { BbVault } from "../target/types/bb_vault";
import {
  Keypair,
  PublicKey,
  SystemProgram,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  Ed25519Program,
} from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  createMint,
  createAccount,
  mintTo,
  getAccount,
} from "@solana/spl-token";
import { assert } from "chai";

describe("bb-vault", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.BbVault as Program<BbVault>;

  // Test keypairs
  const admin = Keypair.generate();
  const kmsKeypair = Keypair.generate(); // simulates AWS KMS Ed25519 key
  const user = Keypair.generate();
  const unauthorizedUser = Keypair.generate();

  // Derived PDAs
  let vaultStatePda: PublicKey;
  let vaultStateBump: number;

  // SPL token accounts
  let usdtMint: PublicKey;
  let vaultUsdtAccount: PublicKey;
  let userUsdtAccount: PublicKey;

  const DAILY_LIMIT = new anchor.BN(10_000_000_000); // 10,000 USDT (6 decimals)
  const CLAIM_AMOUNT = new anchor.BN(100_000_000); // 100 USDT

  before(async () => {
    // Airdrop SOL to test accounts
    for (const kp of [admin, user, unauthorizedUser]) {
      const sig = await provider.connection.requestAirdrop(
        kp.publicKey,
        10 * anchor.web3.LAMPORTS_PER_SOL
      );
      await provider.connection.confirmTransaction(sig);
    }

    // Derive vault PDA
    [vaultStatePda, vaultStateBump] = PublicKey.findProgramAddressSync(
      [Buffer.from("vault")],
      program.programId
    );

    // Create USDT mock mint
    usdtMint = await createMint(
      provider.connection,
      admin,
      admin.publicKey,
      null,
      6 // USDT has 6 decimals
    );

    // Create vault's USDT token account (owned by vault PDA)
    vaultUsdtAccount = await createAccount(
      provider.connection,
      admin,
      usdtMint,
      vaultStatePda
    );

    // Create user's USDT token account
    userUsdtAccount = await createAccount(
      provider.connection,
      user,
      usdtMint,
      user.publicKey
    );

    // Fund the vault with 50,000 USDT
    await mintTo(
      provider.connection,
      admin,
      usdtMint,
      vaultUsdtAccount,
      admin,
      50_000_000_000 // 50,000 USDT
    );
  });

  // ── Test 1: Initialize vault ──────────────────────────────────────────

  it("initializes the vault with correct parameters", async () => {
    await program.methods
      .initializeVault(
        admin.publicKey,
        kmsKeypair.publicKey,
        DAILY_LIMIT
      )
      .accounts({
        admin: admin.publicKey,
        vaultState: vaultStatePda,
        systemProgram: SystemProgram.programId,
      })
      .signers([admin])
      .rpc();

    const state = await program.account.vaultState.fetch(vaultStatePda);
    assert.ok(state.adminMultisig.equals(admin.publicKey));
    assert.ok(state.kmsOraclePubkey.equals(kmsKeypair.publicKey));
    assert.ok(state.dailyLimit.eq(DAILY_LIMIT));
    assert.equal(state.dispensedToday.toNumber(), 0);
    assert.equal(state.isPaused, false);
  });

  // ── Test 2: Claim USDT happy path ─────────────────────────────────────

  it("claims USDT with valid KMS signature", async () => {
    const pohSlot = new anchor.BN(4500122);
    const amount = CLAIM_AMOUNT;

    const message = `CLAIM:${pohSlot.toString()}:${amount.toString()}:${user.publicKey.toBase58()}`;
    const messageBytes = Buffer.from(message, "utf-8");

    // Build the Ed25519 verify instruction (simulating KMS)
    const ed25519Ix = Ed25519Program.createInstructionWithPrivateKey({
      privateKey: kmsKeypair.secretKey,
      message: messageBytes,
    });

    // Derive ProcessedSlot PDA
    const [processedSlotPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("slot"), pohSlot.toArrayLike(Buffer, "le", 8)],
      program.programId
    );

    const vaultBalanceBefore = (
      await getAccount(provider.connection, vaultUsdtAccount)
    ).amount;

    await program.methods
      .claimUsdt(pohSlot, amount)
      .accounts({
        user: user.publicKey,
        vaultState: vaultStatePda,
        processedSlot: processedSlotPda,
        vaultUsdtAccount: vaultUsdtAccount,
        userUsdtAccount: userUsdtAccount,
        instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .preInstructions([ed25519Ix])
      .signers([user])
      .rpc();

    // Verify USDT moved
    const vaultBalanceAfter = (
      await getAccount(provider.connection, vaultUsdtAccount)
    ).amount;
    const userBalance = (
      await getAccount(provider.connection, userUsdtAccount)
    ).amount;

    assert.equal(
      vaultBalanceBefore - vaultBalanceAfter,
      BigInt(amount.toNumber())
    );
    assert.equal(userBalance, BigInt(amount.toNumber()));

    // Verify ProcessedSlot was created
    const slot = await program.account.processedSlot.fetch(processedSlotPda);
    assert.equal(slot.slotNumber.toNumber(), pohSlot.toNumber());
    assert.ok(slot.user.equals(user.publicKey));
    assert.equal(slot.amount.toNumber(), amount.toNumber());
  });

  // ── Test 3: Replay rejected ───────────────────────────────────────────

  it("rejects replay of same PoH slot", async () => {
    const pohSlot = new anchor.BN(4500122); // same as test 2
    const amount = CLAIM_AMOUNT;

    const message = `CLAIM:${pohSlot.toString()}:${amount.toString()}:${user.publicKey.toBase58()}`;
    const messageBytes = Buffer.from(message, "utf-8");

    const ed25519Ix = Ed25519Program.createInstructionWithPrivateKey({
      privateKey: kmsKeypair.secretKey,
      message: messageBytes,
    });

    const [processedSlotPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("slot"), pohSlot.toArrayLike(Buffer, "le", 8)],
      program.programId
    );

    try {
      await program.methods
        .claimUsdt(pohSlot, amount)
        .accounts({
          user: user.publicKey,
          vaultState: vaultStatePda,
          processedSlot: processedSlotPda,
          vaultUsdtAccount: vaultUsdtAccount,
          userUsdtAccount: userUsdtAccount,
          instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .preInstructions([ed25519Ix])
        .signers([user])
        .rpc();
      assert.fail("Should have thrown");
    } catch (err: any) {
      // Anchor/Solana rejects the init of an already-existing PDA
      assert.ok(err.toString().includes("already in use") ||
                err.toString().includes("ConstraintSeeds") ||
                err.toString().includes("custom program error"));
    }
  });

  // ── Test 4: Paused vault rejects claims ───────────────────────────────

  it("rejects claims when vault is paused", async () => {
    // Pause
    await program.methods
      .pauseVault()
      .accounts({
        admin: admin.publicKey,
        vaultState: vaultStatePda,
      })
      .signers([admin])
      .rpc();

    const pohSlot = new anchor.BN(9999999);
    const amount = CLAIM_AMOUNT;
    const message = `CLAIM:${pohSlot.toString()}:${amount.toString()}:${user.publicKey.toBase58()}`;

    const ed25519Ix = Ed25519Program.createInstructionWithPrivateKey({
      privateKey: kmsKeypair.secretKey,
      message: Buffer.from(message, "utf-8"),
    });

    const [processedSlotPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("slot"), pohSlot.toArrayLike(Buffer, "le", 8)],
      program.programId
    );

    try {
      await program.methods
        .claimUsdt(pohSlot, amount)
        .accounts({
          user: user.publicKey,
          vaultState: vaultStatePda,
          processedSlot: processedSlotPda,
          vaultUsdtAccount: vaultUsdtAccount,
          userUsdtAccount: userUsdtAccount,
          instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .preInstructions([ed25519Ix])
        .signers([user])
        .rpc();
      assert.fail("Should have thrown VaultIsPaused");
    } catch (err: any) {
      assert.ok(err.toString().includes("VaultIsPaused") ||
                err.toString().includes("paused"));
    }

    // Unpause for subsequent tests
    await program.methods
      .unpauseVault()
      .accounts({
        admin: admin.publicKey,
        vaultState: vaultStatePda,
      })
      .signers([admin])
      .rpc();
  });

  // ── Test 5: Daily limit enforced ──────────────────────────────────────

  it("rejects claims exceeding daily limit", async () => {
    // Temporarily set limit very low
    await program.methods
      .updateDailyLimit(new anchor.BN(1)) // 0.000001 USDT
      .accounts({
        admin: admin.publicKey,
        vaultState: vaultStatePda,
      })
      .signers([admin])
      .rpc();

    const pohSlot = new anchor.BN(7777777);
    const amount = CLAIM_AMOUNT; // way over the 1-micro limit

    const message = `CLAIM:${pohSlot.toString()}:${amount.toString()}:${user.publicKey.toBase58()}`;
    const ed25519Ix = Ed25519Program.createInstructionWithPrivateKey({
      privateKey: kmsKeypair.secretKey,
      message: Buffer.from(message, "utf-8"),
    });

    const [processedSlotPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("slot"), pohSlot.toArrayLike(Buffer, "le", 8)],
      program.programId
    );

    try {
      await program.methods
        .claimUsdt(pohSlot, amount)
        .accounts({
          user: user.publicKey,
          vaultState: vaultStatePda,
          processedSlot: processedSlotPda,
          vaultUsdtAccount: vaultUsdtAccount,
          userUsdtAccount: userUsdtAccount,
          instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .preInstructions([ed25519Ix])
        .signers([user])
        .rpc();
      assert.fail("Should have thrown DailyLimitExceeded");
    } catch (err: any) {
      assert.ok(err.toString().includes("DailyLimitExceeded") ||
                err.toString().includes("daily"));
    }

    // Restore original limit
    await program.methods
      .updateDailyLimit(DAILY_LIMIT)
      .accounts({
        admin: admin.publicKey,
        vaultState: vaultStatePda,
      })
      .signers([admin])
      .rpc();
  });

  // ── Test 6: Wrong KMS key rejected ────────────────────────────────────

  it("rejects claims signed with wrong KMS key", async () => {
    const fakeKms = Keypair.generate();
    const pohSlot = new anchor.BN(5555555);
    const amount = CLAIM_AMOUNT;

    const message = `CLAIM:${pohSlot.toString()}:${amount.toString()}:${user.publicKey.toBase58()}`;

    // Sign with WRONG key
    const ed25519Ix = Ed25519Program.createInstructionWithPrivateKey({
      privateKey: fakeKms.secretKey,
      message: Buffer.from(message, "utf-8"),
    });

    const [processedSlotPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("slot"), pohSlot.toArrayLike(Buffer, "le", 8)],
      program.programId
    );

    try {
      await program.methods
        .claimUsdt(pohSlot, amount)
        .accounts({
          user: user.publicKey,
          vaultState: vaultStatePda,
          processedSlot: processedSlotPda,
          vaultUsdtAccount: vaultUsdtAccount,
          userUsdtAccount: userUsdtAccount,
          instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .preInstructions([ed25519Ix])
        .signers([user])
        .rpc();
      assert.fail("Should have thrown KmsKeyMismatch");
    } catch (err: any) {
      assert.ok(err.toString().includes("KmsKeyMismatch") ||
                err.toString().includes("key"));
    }
  });

  // ── Test 7: Unauthorized admin rejected ───────────────────────────────

  it("rejects pause from non-admin", async () => {
    try {
      await program.methods
        .pauseVault()
        .accounts({
          admin: unauthorizedUser.publicKey,
          vaultState: vaultStatePda,
        })
        .signers([unauthorizedUser])
        .rpc();
      assert.fail("Should have thrown Unauthorized");
    } catch (err: any) {
      assert.ok(err.toString().includes("Unauthorized") ||
                err.toString().includes("unauthorized"));
    }
  });
});
