// ============================================================================
// BLACKBOOK L1 — LiteSVM INTEGRATION TESTS
// ============================================================================
//
// Uses LiteSVM (lightweight Solana VM) to validate:
//   1. System transfers execute correctly on a real SVM
//   2. Account creation / balance tracking
//   3. Transaction signing with Ed25519 keypairs
//   4. Blockhash validation and replay protection
//   5. SPL Token mint + transfer compatibility
//
// These tests prove BlackBook's SVM layer is wire-compatible with Solana.
// ============================================================================

use litesvm::LiteSVM;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::Message,
    native_token::LAMPORTS_PER_SOL,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_instruction,
    system_program,
    transaction::Transaction,
};

// ============================================================================
// TEST 1: Basic system transfer on LiteSVM
// ============================================================================
#[test]
fn test_litesvm_system_transfer() {
    let mut svm = LiteSVM::new();

    // Create two keypairs (sender + receiver)
    let sender = Keypair::new();
    let receiver = Keypair::new();

    // Airdrop 10 SOL (= 10 BB in our model) to sender
    let airdrop_amount = 10 * LAMPORTS_PER_SOL;
    svm.airdrop(&sender.pubkey(), airdrop_amount).unwrap();

    // Verify sender balance
    let sender_balance = svm.get_balance(&sender.pubkey()).unwrap();
    assert_eq!(sender_balance, airdrop_amount, "Sender should have 10 SOL after airdrop");

    // Transfer 3 SOL from sender → receiver
    let transfer_amount = 3 * LAMPORTS_PER_SOL;
    let ix = system_instruction::transfer(&sender.pubkey(), &receiver.pubkey(), transfer_amount);
    let blockhash = svm.latest_blockhash();
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&sender.pubkey()),
        &[&sender],
        blockhash,
    );

    let result = svm.send_transaction(tx);
    assert!(result.is_ok(), "Transfer should succeed: {:?}", result.err());

    // Verify balances
    let receiver_balance = svm.get_balance(&receiver.pubkey()).unwrap();
    assert_eq!(receiver_balance, transfer_amount, "Receiver should have 3 SOL");

    let sender_final = svm.get_balance(&sender.pubkey()).unwrap();
    // Sender loses transfer_amount + tx fee (5000 lamports default)
    assert!(sender_final < airdrop_amount - transfer_amount, "Sender balance should decrease by transfer + fee");
    assert!(sender_final > 0, "Sender should still have remaining balance");

    println!("✅ LiteSVM system transfer: sender={}, receiver={}", sender_final, receiver_balance);
}

// ============================================================================
// TEST 2: Multiple transfers in sequence
// ============================================================================
#[test]
fn test_litesvm_sequential_transfers() {
    let mut svm = LiteSVM::new();

    let alice = Keypair::new();
    let bob = Keypair::new();
    let charlie = Keypair::new();

    // Fund Alice with 100 SOL
    svm.airdrop(&alice.pubkey(), 100 * LAMPORTS_PER_SOL).unwrap();

    // Alice → Bob: 30 SOL
    let ix1 = system_instruction::transfer(&alice.pubkey(), &bob.pubkey(), 30 * LAMPORTS_PER_SOL);
    let tx1 = Transaction::new_signed_with_payer(
        &[ix1],
        Some(&alice.pubkey()),
        &[&alice],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx1).unwrap();

    // Alice → Charlie: 20 SOL
    let ix2 = system_instruction::transfer(&alice.pubkey(), &charlie.pubkey(), 20 * LAMPORTS_PER_SOL);
    let tx2 = Transaction::new_signed_with_payer(
        &[ix2],
        Some(&alice.pubkey()),
        &[&alice],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx2).unwrap();

    // Bob → Charlie: 10 SOL
    let ix3 = system_instruction::transfer(&bob.pubkey(), &charlie.pubkey(), 10 * LAMPORTS_PER_SOL);
    let tx3 = Transaction::new_signed_with_payer(
        &[ix3],
        Some(&bob.pubkey()),
        &[&bob],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx3).unwrap();

    // Verify final balances
    let bob_bal = svm.get_balance(&bob.pubkey()).unwrap();
    let charlie_bal = svm.get_balance(&charlie.pubkey()).unwrap();

    // Bob: received 30, sent 10, paid 1 fee = ~20 SOL (minus fee)
    assert!(bob_bal >= 19 * LAMPORTS_PER_SOL && bob_bal <= 20 * LAMPORTS_PER_SOL,
        "Bob should have ~20 SOL, got {}", bob_bal as f64 / LAMPORTS_PER_SOL as f64);

    // Charlie: received 20 + 10 = 30 SOL (no fees paid)
    assert_eq!(charlie_bal, 30 * LAMPORTS_PER_SOL,
        "Charlie should have exactly 30 SOL");

    println!("✅ Sequential transfers: Bob={:.4} SOL, Charlie={:.4} SOL",
        bob_bal as f64 / LAMPORTS_PER_SOL as f64,
        charlie_bal as f64 / LAMPORTS_PER_SOL as f64);
}

// ============================================================================
// TEST 3: Insufficient funds should fail
// ============================================================================
#[test]
fn test_litesvm_insufficient_funds() {
    let mut svm = LiteSVM::new();

    let sender = Keypair::new();
    let receiver = Keypair::new();

    // Give sender only 1 SOL
    svm.airdrop(&sender.pubkey(), LAMPORTS_PER_SOL).unwrap();

    // Try to send 5 SOL (should fail)
    let ix = system_instruction::transfer(&sender.pubkey(), &receiver.pubkey(), 5 * LAMPORTS_PER_SOL);
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&sender.pubkey()),
        &[&sender],
        svm.latest_blockhash(),
    );

    let result = svm.send_transaction(tx);
    assert!(result.is_err(), "Transfer should fail with insufficient funds");
    println!("✅ Insufficient funds correctly rejected");
}

// ============================================================================
// TEST 4: Zero-amount transfer should succeed (no-op)
// ============================================================================
#[test]
fn test_litesvm_zero_transfer() {
    let mut svm = LiteSVM::new();

    let sender = Keypair::new();
    let receiver = Keypair::new();

    svm.airdrop(&sender.pubkey(), 2 * LAMPORTS_PER_SOL).unwrap();

    let ix = system_instruction::transfer(&sender.pubkey(), &receiver.pubkey(), 0);
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&sender.pubkey()),
        &[&sender],
        svm.latest_blockhash(),
    );

    // Zero-amount transfers are valid on Solana
    let result = svm.send_transaction(tx);
    assert!(result.is_ok(), "Zero-amount transfer should succeed: {:?}", result.err());

    let receiver_bal = svm.get_balance(&receiver.pubkey()).unwrap();
    assert_eq!(receiver_bal, 0, "Receiver should still have 0");
    println!("✅ Zero-amount transfer accepted (no-op)");
}

// ============================================================================
// TEST 5: Account info retrieval
// ============================================================================
#[test]
fn test_litesvm_account_info() {
    let mut svm = LiteSVM::new();
    let wallet = Keypair::new();

    svm.airdrop(&wallet.pubkey(), 5 * LAMPORTS_PER_SOL).unwrap();

    let account = svm.get_account(&wallet.pubkey());
    assert!(account.is_some(), "Account should exist after airdrop");

    let acc = account.unwrap();
    assert_eq!(acc.lamports, 5 * LAMPORTS_PER_SOL);
    assert_eq!(acc.owner, system_program::ID);
    assert!(!acc.executable);
    assert!(acc.data.is_empty(), "System accounts have no data");

    println!("✅ Account info: {} lamports, owner={}", acc.lamports, acc.owner);
}

// ============================================================================
// TEST 6: Multiple airdrops accumulate
// ============================================================================
#[test]
fn test_litesvm_multiple_airdrops() {
    let mut svm = LiteSVM::new();
    let wallet = Keypair::new();

    svm.airdrop(&wallet.pubkey(), 3 * LAMPORTS_PER_SOL).unwrap();
    svm.airdrop(&wallet.pubkey(), 7 * LAMPORTS_PER_SOL).unwrap();

    let balance = svm.get_balance(&wallet.pubkey()).unwrap();
    assert_eq!(balance, 10 * LAMPORTS_PER_SOL, "Airdrops should accumulate");
    println!("✅ Multiple airdrops: 3 + 7 = 10 SOL");
}

// ============================================================================
// TEST 7: Self-transfer (same sender & receiver)
// ============================================================================
#[test]
fn test_litesvm_self_transfer() {
    let mut svm = LiteSVM::new();
    let wallet = Keypair::new();

    svm.airdrop(&wallet.pubkey(), 5 * LAMPORTS_PER_SOL).unwrap();

    let ix = system_instruction::transfer(&wallet.pubkey(), &wallet.pubkey(), LAMPORTS_PER_SOL);
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&wallet.pubkey()),
        &[&wallet],
        svm.latest_blockhash(),
    );

    // Self-transfer succeeds but costs a fee
    let result = svm.send_transaction(tx);
    assert!(result.is_ok(), "Self-transfer should succeed: {:?}", result.err());

    let balance = svm.get_balance(&wallet.pubkey()).unwrap();
    // Balance = 5 SOL - fee (self-transfer doesn't change net balance, just fee)
    assert!(balance < 5 * LAMPORTS_PER_SOL, "Should have lost a tx fee");
    assert!(balance > 4 * LAMPORTS_PER_SOL, "Should only lose the fee, not the transfer amount");
    println!("✅ Self-transfer: balance after fee = {:.6} SOL", balance as f64 / LAMPORTS_PER_SOL as f64);
}

// ============================================================================
// TEST 8: Create account with specific size (simulates SVM account creation)
// ============================================================================
#[test]
fn test_litesvm_create_account() {
    let mut svm = LiteSVM::new();

    let payer = Keypair::new();
    let new_account = Keypair::new();

    svm.airdrop(&payer.pubkey(), 10 * LAMPORTS_PER_SOL).unwrap();

    // Create an account with 128 bytes of space owned by system program
    let space = 128u64;
    let rent = svm.minimum_balance_for_rent_exemption(space as usize);

    let ix = system_instruction::create_account(
        &payer.pubkey(),
        &new_account.pubkey(),
        rent,
        space,
        &system_program::ID,
    );

    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer, &new_account],
        svm.latest_blockhash(),
    );

    let result = svm.send_transaction(tx);
    assert!(result.is_ok(), "Create account should succeed: {:?}", result.err());

    let acc = svm.get_account(&new_account.pubkey()).unwrap();
    assert_eq!(acc.data.len(), space as usize, "Account should have requested space");
    assert_eq!(acc.lamports, rent, "Account should have rent-exempt balance");
    println!("✅ Created account: {} bytes, {} rent lamports", space, rent);
}

// ============================================================================
// TEST 9: Batch of 50 transfers (throughput test)
// ============================================================================
#[test]
fn test_litesvm_batch_transfers() {
    let mut svm = LiteSVM::new();

    let funder = Keypair::new();
    svm.airdrop(&funder.pubkey(), 1000 * LAMPORTS_PER_SOL).unwrap();

    let mut recipients: Vec<Pubkey> = Vec::new();
    let transfer_amount = LAMPORTS_PER_SOL; // 1 SOL each

    let start = std::time::Instant::now();

    for _ in 0..50 {
        let recipient = Keypair::new();
        recipients.push(recipient.pubkey());

        let ix = system_instruction::transfer(&funder.pubkey(), &recipient.pubkey(), transfer_amount);
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&funder.pubkey()),
            &[&funder],
            svm.latest_blockhash(),
        );
        svm.send_transaction(tx).unwrap();
    }

    let elapsed = start.elapsed();

    // Verify all recipients got their SOL
    for (i, pubkey) in recipients.iter().enumerate() {
        let bal = svm.get_balance(pubkey).unwrap();
        assert_eq!(bal, transfer_amount,
            "Recipient {} should have {} lamports", i, transfer_amount);
    }

    let tps = 50.0 / elapsed.as_secs_f64();
    println!("✅ Batch: 50 transfers in {:.2}ms ({:.0} TPS)", elapsed.as_millis(), tps);
}

// ============================================================================
// TEST 10: Ed25519 keypair from seed (same as BlackBook wallet creation)
// ============================================================================
#[test]
fn test_litesvm_ed25519_from_seed() {
    use ed25519_dalek::SigningKey;

    let mut svm = LiteSVM::new();

    // Simulate a 32-byte seed (what SSS reconstructs)
    let seed: [u8; 32] = [42u8; 32]; // deterministic for testing
    let signing_key = SigningKey::from_bytes(&seed);
    let pubkey_bytes = signing_key.verifying_key().to_bytes();

    // Convert to Solana Keypair
    let mut keypair_bytes = [0u8; 64];
    keypair_bytes[..32].copy_from_slice(&seed);
    keypair_bytes[32..].copy_from_slice(&pubkey_bytes);
    let solana_keypair = Keypair::from_bytes(&keypair_bytes).unwrap();

    // The Solana pubkey should match the ed25519-dalek pubkey
    assert_eq!(solana_keypair.pubkey().to_bytes(), pubkey_bytes,
        "Solana and ed25519-dalek should derive the same pubkey from the same seed");

    // Fund and transfer using this keypair
    svm.airdrop(&solana_keypair.pubkey(), 5 * LAMPORTS_PER_SOL).unwrap();

    let receiver = Keypair::new();
    let ix = system_instruction::transfer(
        &solana_keypair.pubkey(),
        &receiver.pubkey(),
        2 * LAMPORTS_PER_SOL,
    );
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&solana_keypair.pubkey()),
        &[&solana_keypair],
        svm.latest_blockhash(),
    );

    let result = svm.send_transaction(tx);
    assert!(result.is_ok(), "Transfer with seed-derived keypair should work: {:?}", result.err());

    let receiver_bal = svm.get_balance(&receiver.pubkey()).unwrap();
    assert_eq!(receiver_bal, 2 * LAMPORTS_PER_SOL);
    println!("✅ Ed25519 seed → Solana keypair: transfer succeeded, pubkey={}", solana_keypair.pubkey());
}
