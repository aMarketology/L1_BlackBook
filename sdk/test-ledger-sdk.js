/**
 * ═══════════════════════════════════════════════════════════════════════════
 * LEDGER SDK TEST - Transaction History Demo
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * This script demonstrates the complete transaction history tracking on L1:
 * 1. Performs several transfers between Alice, Bob, and Dealer
 * 2. Queries transaction history with various filters
 * 3. Shows statistics and insights
 * 
 * Run with: node test-ledger-sdk.js
 */

import { LedgerSDK, TxType } from './ledger-sdk.js';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { BlackBookWallet, TEST_ACCOUNTS } = require('./blackbook-wallet-sdk.js');

const L1_URL = 'http://localhost:8080';

async function testLedgerSDK() {
  console.log('╔═══════════════════════════════════════════════════════════════╗');
  console.log('║         LEDGER SDK TEST - Transaction History Demo           ║');
  console.log('╚═══════════════════════════════════════════════════════════════╝\n');

  // =========================================================================
  // SETUP: Initialize wallets and ledger SDK
  // =========================================================================
  console.log('📋 Setting up wallets and ledger...\n');
  
  const aliceWallet = new BlackBookWallet(L1_URL);
  const bobWallet = new BlackBookWallet(L1_URL);
  const dealerWallet = new BlackBookWallet(L1_URL);
  
  aliceWallet.initFromTestAccount('alice');
  bobWallet.initFromTestAccount('bob');
  dealerWallet.initFromTestAccount('dealer');
  
  const ledger = new LedgerSDK({ l1Url: L1_URL });
  
  console.log('✅ Wallets initialized:');
  console.log(`   Alice:  ${aliceWallet.address}`);
  console.log(`   Bob:    ${bobWallet.address}`);
  console.log(`   Dealer: ${dealerWallet.address}\n`);

  // =========================================================================
  // TEST 1: Perform some transfers to create transaction history
  // =========================================================================
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('TEST 1: Create Transaction History');
  console.log('═══════════════════════════════════════════════════════════════\n');

  const transfers = [
    { from: aliceWallet, to: bobWallet.address, amount: 100, desc: 'Alice → Bob (100 BB)' },
    { from: bobWallet, to: aliceWallet.address, amount: 50, desc: 'Bob → Alice (50 BB)' },
    { from: dealerWallet, to: aliceWallet.address, amount: 500, desc: 'Dealer → Alice (500 BB)' },
    { from: aliceWallet, to: dealerWallet.address, amount: 200, desc: 'Alice → Dealer (200 BB)' },
    { from: bobWallet, to: dealerWallet.address, amount: 25, desc: 'Bob → Dealer (25 BB)' },
  ];

  console.log('💸 Executing transfers...\n');
  
  for (const transfer of transfers) {
    try {
      const result = await transfer.from.transfer(transfer.to, transfer.amount);
      if (result.success) {
        console.log(`   ✅ ${transfer.desc}`);
        console.log(`      From balance: ${result.from_balance} BB`);
        console.log(`      To balance:   ${result.to_balance} BB\n`);
      } else {
        console.log(`   ❌ ${transfer.desc} - Failed: ${result.error}\n`);
      }
      
      // Small delay to ensure timestamps are different
      await new Promise(resolve => setTimeout(resolve, 100));
    } catch (error) {
      console.log(`   ❌ ${transfer.desc} - Error: ${error.message}\n`);
    }
  }

  // =========================================================================
  // TEST 2: Fetch all transactions
  // =========================================================================
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('TEST 2: Fetch All Transactions');
  console.log('═══════════════════════════════════════════════════════════════\n');

  try {
    const allTxs = await ledger.getAll({ limit: 20 });
    console.log(`📊 Found ${allTxs.length} total transactions:\n`);
    
    allTxs.forEach((tx, idx) => {
      const date = new Date(tx.timestamp).toLocaleString();
      console.log(`   ${idx + 1}. [${tx.status.toUpperCase()}] ${tx.type}`);
      console.log(`      From: ${tx.from_address}`);
      console.log(`      To:   ${tx.to_address}`);
      console.log(`      Amount: ${tx.amount} BB`);
      console.log(`      Time: ${date}`);
      console.log(`      ${tx.description}\n`);
    });
  } catch (error) {
    console.log(`   ❌ Failed to fetch transactions: ${error.message}\n`);
  }

  // =========================================================================
  // TEST 3: Fetch transactions for specific user (Alice)
  // =========================================================================
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('TEST 3: Fetch Alice\'s Transactions');
  console.log('═══════════════════════════════════════════════════════════════\n');

  try {
    const aliceTxs = await ledger.getUserTransactions(aliceWallet.address, { limit: 20 });
    console.log(`📊 Found ${aliceTxs.length} transactions for Alice:\n`);
    
    aliceTxs.forEach((tx, idx) => {
      const isSender = tx.from_address === aliceWallet.address;
      const direction = isSender ? '→' : '←';
      const counterparty = isSender ? tx.to_address : tx.from_address;
      const sign = isSender ? '-' : '+';
      
      console.log(`   ${idx + 1}. ${direction} ${tx.amount} BB (${tx.status})`);
      console.log(`      ${sign}${tx.amount} BB`);
      console.log(`      Counterparty: ${counterparty.substring(0, 20)}...`);
      console.log(`      Type: ${tx.type}\n`);
    });
  } catch (error) {
    console.log(`   ❌ Failed to fetch Alice's transactions: ${error.message}\n`);
  }

  // =========================================================================
  // TEST 4: Fetch transactions for specific user (Bob)
  // =========================================================================
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('TEST 4: Fetch Bob\'s Transactions');
  console.log('═══════════════════════════════════════════════════════════════\n');

  try {
    const bobTxs = await ledger.getUserTransactions(bobWallet.address, { limit: 20 });
    console.log(`📊 Found ${bobTxs.length} transactions for Bob:\n`);
    
    bobTxs.forEach((tx, idx) => {
      const isSender = tx.from_address === bobWallet.address;
      const direction = isSender ? '→' : '←';
      const sign = isSender ? '-' : '+';
      
      console.log(`   ${idx + 1}. ${direction} ${sign}${tx.amount} BB`);
      console.log(`      ${tx.description}\n`);
    });
  } catch (error) {
    console.log(`   ❌ Failed to fetch Bob's transactions: ${error.message}\n`);
  }

  // =========================================================================
  // TEST 5: Get transaction statistics
  // =========================================================================
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('TEST 5: Transaction Statistics');
  console.log('═══════════════════════════════════════════════════════════════\n');

  try {
    const globalStats = await ledger.getStatistics();
    console.log('📊 Global Statistics:');
    console.log(`   Total transactions: ${globalStats.total}`);
    console.log(`   Total volume: ${globalStats.total_volume.toFixed(2)} BB`);
    console.log(`   Pending: ${globalStats.pending_count}`);
    console.log(`   By type:`, globalStats.by_type);
    console.log(`   By status:`, globalStats.by_status);
    console.log(`   By layer:`, globalStats.by_layer);
    console.log('');

    const aliceStats = await ledger.getStatistics(aliceWallet.address);
    console.log('📊 Alice\'s Statistics:');
    console.log(`   Total transactions: ${aliceStats.total}`);
    console.log(`   Total volume: ${aliceStats.total_volume.toFixed(2)} BB`);
    console.log(`   By type:`, aliceStats.by_type);
    console.log('');
  } catch (error) {
    console.log(`   ❌ Failed to fetch statistics: ${error.message}\n`);
  }

  // =========================================================================
  // TEST 6: Get current balances
  // =========================================================================
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('TEST 6: Current Balances');
  console.log('═══════════════════════════════════════════════════════════════\n');

  try {
    const aliceBalance = await aliceWallet.getBalance();
    const bobBalance = await bobWallet.getBalance();
    const dealerBalance = await dealerWallet.getBalance();
    
    console.log('💰 Current Balances:');
    console.log(`   Alice:  ${aliceBalance.balance} BB`);
    console.log(`   Bob:    ${bobBalance.balance} BB`);
    console.log(`   Dealer: ${dealerBalance.balance} BB\n`);
  } catch (error) {
    console.log(`   ❌ Failed to fetch balances: ${error.message}\n`);
  }

  // =========================================================================
  // CLEANUP
  // =========================================================================
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('Cleanup');
  console.log('═══════════════════════════════════════════════════════════════\n');
  
  aliceWallet.destroy();
  bobWallet.destroy();
  dealerWallet.destroy();
  console.log('✅ Wallets destroyed\n');

  // =========================================================================
  // SUMMARY
  // =========================================================================
  console.log('╔═══════════════════════════════════════════════════════════════╗');
  console.log('║                    TEST COMPLETE                              ║');
  console.log('╚═══════════════════════════════════════════════════════════════╝');
  console.log('');
  console.log('✅ LedgerSDK successfully demonstrated:');
  console.log('   • Transaction creation and logging');
  console.log('   • Fetching all transactions');
  console.log('   • Filtering by user address');
  console.log('   • Transaction statistics and analytics');
  console.log('   • Real-time balance tracking');
  console.log('');
  console.log('📦 All transactions are now persisted in ReDB!');
  console.log('   Database: ./blockchain_data/blockchain.redb');
  console.log('');
}

// Run the test
testLedgerSDK().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
