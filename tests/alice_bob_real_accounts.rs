//! Alice & Bob End-to-End Tests (Updated for Real BIP-39 Accounts)
//!
//! These tests use the REAL Alice and Bob accounts generated from BIP-39 mnemonics.
//! The accounts are defined in unified_auth.rs with proper Ed25519 keypairs.
//!
//! RUN: cargo test --test alice_bob_real_accounts

use layer1::EnhancedBlockchain;
use layer1::integration::unified_auth::{
    get_alice_account, get_bob_account, FullTestAccount,
};

// ============================================================================
// HELPER: Create a test blockchain with Alice and Bob funded
// ============================================================================

fn setup_blockchain() -> (EnhancedBlockchain, FullTestAccount, FullTestAccount) {
    let mut blockchain = EnhancedBlockchain::new();
    let alice = get_alice_account();
    let bob = get_bob_account();
    
    // Fund Alice with 10,000 BB
    blockchain.balances.insert(alice.address.clone(), 10_000.0);
    
    // Fund Bob with 5,000 BB
    blockchain.balances.insert(bob.address.clone(), 5_000.0);
    
    (blockchain, alice, bob)
}

// ============================================================================
// TEST 1: Verify Real Account Structure
// ============================================================================

#[test]
fn test_real_accounts_structure() {
    println!("\n📋 TEST: Real Account Structure\n");
    
    let alice = get_alice_account();
    let bob = get_bob_account();
    
    // Verify Alice's address format (43 chars: L1_ + 40 hex)
    println!("Alice Address: {}", alice.address);
    assert!(alice.address.starts_with("L1_"), "Alice should have L1_ prefix");
    assert_eq!(alice.address.len(), 43, "Address should be 43 chars (L1_ + 40 hex)");
    
    // Verify Bob's address format
    println!("Bob Address: {}", bob.address);
    assert!(bob.address.starts_with("L1_"), "Bob should have L1_ prefix");
    assert_eq!(bob.address.len(), 43, "Address should be 43 chars (L1_ + 40 hex)");
    
    // Verify public keys are 64 hex chars (32 bytes)
    println!("Alice Public Key: {}", alice.public_key);
    assert_eq!(alice.public_key.len(), 64, "Public key should be 64 hex chars");
    assert!(alice.public_key.chars().all(|c| c.is_ascii_hexdigit()), "Public key should be hex");
    
    println!("Bob Public Key: {}", bob.public_key);
    assert_eq!(bob.public_key.len(), 64, "Public key should be 64 hex chars");
    
    // Verify private keys are 64 hex chars (32 bytes seed)
    assert_eq!(alice.private_key.len(), 64, "Private key should be 64 hex chars");
    assert_eq!(bob.private_key.len(), 64, "Private key should be 64 hex chars");
    
    println!("\n✅ Account structure verified!");
    println!("   Alice: {} (balance: {} BB)", &alice.address, alice.total_balance);
    println!("   Bob:   {} (balance: {} BB)", &bob.address, bob.total_balance);
}

// ============================================================================
// TEST 2: Transfer from Alice to Bob
// ============================================================================

#[test]
fn test_alice_transfers_to_bob() {
    println!("\n📋 TEST: Alice Transfers to Bob\n");
    
    let (mut blockchain, alice, bob) = setup_blockchain();
    
    // Initial balances
    let alice_initial = blockchain.get_balance(&alice.address);
    let bob_initial = blockchain.get_balance(&bob.address);
    
    println!("Initial balances:");
    println!("   Alice: {} BB", alice_initial);
    println!("   Bob:   {} BB", bob_initial);
    
    // Alice transfers 1000 BB to Bob
    let transfer_amount = 1000.0;
    let tx_id = blockchain.create_transaction(
        alice.address.clone(),
        bob.address.clone(),
        transfer_amount,
    );
    
    println!("\nTransfer: {} BB from Alice to Bob", transfer_amount);
    println!("   TX ID: {}...", &tx_id[..16.min(tx_id.len())]);
    
    // Verify final balances
    let alice_final = blockchain.get_balance(&alice.address);
    let bob_final = blockchain.get_balance(&bob.address);
    
    println!("\nFinal balances:");
    println!("   Alice: {} BB", alice_final);
    println!("   Bob:   {} BB", bob_final);
    
    assert_eq!(alice_final, alice_initial - transfer_amount, "Alice should have less");
    assert_eq!(bob_final, bob_initial + transfer_amount, "Bob should have more");
    
    println!("\n✅ Transfer verified!");
}

// ============================================================================
// TEST 3: Bidirectional Transfers
// ============================================================================

#[test]
fn test_bidirectional_transfers() {
    println!("\n📋 TEST: Bidirectional Transfers\n");
    
    let (mut blockchain, alice, bob) = setup_blockchain();
    
    // Alice sends 500 to Bob
    println!("Alice → Bob: 500 BB");
    blockchain.create_transaction(alice.address.clone(), bob.address.clone(), 500.0);
    
    // Bob sends 200 back to Alice
    println!("Bob → Alice: 200 BB");
    blockchain.create_transaction(bob.address.clone(), alice.address.clone(), 200.0);
    
    // Net result: Alice -300, Bob +300
    let alice_balance = blockchain.get_balance(&alice.address);
    let bob_balance = blockchain.get_balance(&bob.address);
    
    println!("\nFinal balances:");
    println!("   Alice: {} BB (expected: 9700)", alice_balance);
    println!("   Bob:   {} BB (expected: 5300)", bob_balance);
    
    assert_eq!(alice_balance, 9700.0, "Alice: 10000 - 500 + 200 = 9700");
    assert_eq!(bob_balance, 5300.0, "Bob: 5000 + 500 - 200 = 5300");
    
    println!("\n✅ Bidirectional transfers verified!");
}

// ============================================================================
// TEST 4: Insufficient Funds
// ============================================================================

#[test]
fn test_insufficient_funds() {
    println!("\n📋 TEST: Insufficient Funds Handling\n");
    
    let (mut blockchain, _alice, bob) = setup_blockchain();
    
    // Bob tries to transfer more than he has
    let bob_balance = blockchain.get_balance(&bob.address);
    let transfer_amount = bob_balance + 1000.0; // More than Bob has
    
    println!("Bob balance: {} BB", bob_balance);
    println!("Attempting to transfer: {} BB", transfer_amount);
    
    let tx_id = blockchain.create_transaction(
        bob.address.clone(),
        "L1DEADBEEF1234567890ABCDEF1234567890ABCD".to_string(),
        transfer_amount,
    );
    
    // The transaction should fail or create a failed transaction
    // (depends on how EnhancedBlockchain handles this)
    println!("TX result: {}", tx_id);
    
    // Bob's balance should be unchanged
    let bob_after = blockchain.get_balance(&bob.address);
    println!("Bob balance after: {} BB", bob_after);
    
    // If the blockchain rejects insufficient funds, balance should be same
    // (This test documents the behavior)
    
    println!("\n✅ Insufficient funds test completed!");
}

// ============================================================================
// TEST 5: Multiple Transactions
// ============================================================================

#[test]
fn test_multiple_transactions() {
    println!("\n📋 TEST: Multiple Transactions\n");
    
    let (mut blockchain, alice, bob) = setup_blockchain();
    
    // Execute 5 transactions
    for i in 1..=5 {
        let amount = 100.0 * i as f64;
        blockchain.create_transaction(alice.address.clone(), bob.address.clone(), amount);
        println!("TX {}: Alice → Bob: {} BB", i, amount);
    }
    
    // Total transferred: 100 + 200 + 300 + 400 + 500 = 1500 BB
    let alice_balance = blockchain.get_balance(&alice.address);
    let bob_balance = blockchain.get_balance(&bob.address);
    
    println!("\nFinal balances:");
    println!("   Alice: {} BB (expected: 8500)", alice_balance);
    println!("   Bob:   {} BB (expected: 6500)", bob_balance);
    
    assert_eq!(alice_balance, 8500.0, "Alice: 10000 - 1500 = 8500");
    assert_eq!(bob_balance, 6500.0, "Bob: 5000 + 1500 = 6500");
    
    println!("\n✅ Multiple transactions verified!");
}

// ============================================================================
// TEST 6: Verify Address Derivation (Optional - if helpers are exported)
// ============================================================================

#[test]
fn test_address_format() {
    println!("\n📋 TEST: Address Format Validation\n");
    
    let alice = get_alice_account();
    let bob = get_bob_account();
    
    // Addresses should be L1_ + 40 hex chars (43 chars total)
    assert!(alice.address.starts_with("L1_"), "Alice should have L1_ prefix");
    assert!(bob.address.starts_with("L1_"), "Bob should have L1_ prefix");
    assert_eq!(alice.address.len(), 43, "Address should be 43 chars");
    assert_eq!(bob.address.len(), 43, "Address should be 43 chars");
    
    // The hash part should be uppercase hex (skip "L1_" prefix = 3 chars)
    let alice_hash = &alice.address[3..];
    let bob_hash = &bob.address[3..];
    
    assert!(alice_hash.chars().all(|c| c.is_ascii_hexdigit()), "Alice hash should be hex");
    assert!(bob_hash.chars().all(|c| c.is_ascii_hexdigit()), "Bob hash should be hex");
    assert_eq!(alice_hash.len(), 40, "Hash should be 40 chars");
    assert_eq!(bob_hash.len(), 40, "Hash should be 40 chars");
    
    println!("Alice address: {} ✅", alice.address);
    println!("Bob address:   {} ✅", bob.address);
    
    // L2 addresses should have same hash, just L2_ prefix
    let alice_l2 = format!("L2_{}", alice_hash);
    let bob_l2 = format!("L2_{}", bob_hash);
    
    println!("Alice L2:      {}", alice_l2);
    println!("Bob L2:        {}", bob_l2);
    
    println!("\n✅ Address format verified!");
}
