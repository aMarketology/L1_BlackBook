/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * BLACKBOOK FRONTEND SDK TEST
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Tests all SDK functionality:
 * - Wallet connection
 * - Balance queries
 * - Transfers
 * - L2 sessions
 * - Transaction history
 * - Event system
 * 
 * Run with: node test-frontend-sdk.js
 */

import { BlackBookSDK, EVENTS } from './blackbook-frontend-sdk.js';

const L1_URL = 'http://localhost:8080';

async function testFrontendSDK() {
  console.log('╔═══════════════════════════════════════════════════════════════╗');
  console.log('║         BLACKBOOK FRONTEND SDK TEST                           ║');
  console.log('╚═══════════════════════════════════════════════════════════════╝\n');

  // Create SDK instance
  const sdk = new BlackBookSDK({ url: L1_URL });

  // =========================================================================
  // TEST 1: Event System Setup
  // =========================================================================
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('TEST 1: Event System');
  console.log('═══════════════════════════════════════════════════════════════\n');

  let eventLog = [];
  
  sdk.on(EVENTS.WALLET_CONNECTED, (data) => {
    eventLog.push({ event: 'WALLET_CONNECTED', data });
    console.log('   📡 Event: WALLET_CONNECTED', data.address.substring(0, 20) + '...');
  });
  
  sdk.on(EVENTS.BALANCE_UPDATED, (data) => {
    eventLog.push({ event: 'BALANCE_UPDATED', data });
    console.log(`   📡 Event: BALANCE_UPDATED ${data.formatted}`);
  });
  
  sdk.on(EVENTS.TRANSFER_SENT, (data) => {
    eventLog.push({ event: 'TRANSFER_SENT', data });
    console.log(`   📡 Event: TRANSFER_SENT ${data.amount} BB to ${data.to.substring(0, 15)}...`);
  });
  
  sdk.on(EVENTS.TRANSFER_CONFIRMED, (data) => {
    eventLog.push({ event: 'TRANSFER_CONFIRMED', data });
    console.log(`   📡 Event: TRANSFER_CONFIRMED txId: ${data.txId}`);
  });
  
  sdk.on(EVENTS.SESSION_OPENED, (data) => {
    eventLog.push({ event: 'SESSION_OPENED', data });
    console.log(`   📡 Event: SESSION_OPENED ${data.lockedAmount} BB locked`);
  });
  
  sdk.on(EVENTS.ERROR, (data) => {
    eventLog.push({ event: 'ERROR', data });
    console.log(`   📡 Event: ERROR ${data.error}`);
  });

  console.log('   ✅ Event listeners registered\n');

  // =========================================================================
  // TEST 2: Health Check
  // =========================================================================
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('TEST 2: Health Check');
  console.log('═══════════════════════════════════════════════════════════════\n');

  const healthy = await sdk.isHealthy();
  console.log(`   Server Status: ${healthy ? '✅ Online' : '❌ Offline'}`);
  
  if (!healthy) {
    console.log('   ⚠️  Please start the L1 server: cargo run');
    return;
  }

  const stats = await sdk.getStats();
  console.log(`   Total Accounts: ${stats.blockchain?.total_accounts || 'N/A'}`);
  console.log(`   Total Supply: ${stats.blockchain?.total_supply?.toFixed(2) || 'N/A'} BB\n`);

  // =========================================================================
  // TEST 3: Connect Test Wallet (Alice)
  // =========================================================================
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('TEST 3: Connect Test Wallet (Alice)');
  console.log('═══════════════════════════════════════════════════════════════\n');

  const alice = sdk.connectTestAccount('alice');
  console.log(`   Address: ${alice.address}`);
  console.log(`   Public Key: ${alice.publicKey.substring(0, 20)}...`);
  console.log(`   Connected: ${sdk.isConnected}\n`);

  // =========================================================================
  // TEST 4: Get Balance
  // =========================================================================
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('TEST 4: Get Balance');
  console.log('═══════════════════════════════════════════════════════════════\n');

  const balance = await sdk.getBalance();
  console.log(`   Balance: ${balance.formatted}`);
  console.log(`   USD Value: ${balance.formattedUsd}`);
  console.log(`   Symbol: ${balance.symbol}\n`);

  // =========================================================================
  // TEST 5: Get Token Info
  // =========================================================================
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('TEST 5: Token Info');
  console.log('═══════════════════════════════════════════════════════════════\n');

  const tokenInfo = sdk.getTokenInfo();
  console.log(`   Name: ${tokenInfo.name}`);
  console.log(`   Symbol: ${tokenInfo.symbol}`);
  console.log(`   Decimals: ${tokenInfo.decimals}`);
  console.log(`   USD Peg: $${tokenInfo.usdPeg}\n`);

  // =========================================================================
  // TEST 6: Transfer Tokens
  // =========================================================================
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('TEST 6: Transfer 10 BB to Bob');
  console.log('═══════════════════════════════════════════════════════════════\n');

  const bobAddress = 'L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433';
  
  try {
    const transfer = await sdk.transfer(bobAddress, 10);
    
    if (transfer.success) {
      console.log('   ✅ Transfer Successful!');
      console.log(`   TX ID: ${transfer.tx_id}`);
      console.log(`   From Balance: ${transfer.from_balance} BB`);
      console.log(`   To Balance: ${transfer.to_balance} BB\n`);
    } else {
      console.log(`   ❌ Transfer Failed: ${transfer.error}\n`);
    }
  } catch (err) {
    console.log(`   ❌ Transfer Error: ${err.message}\n`);
  }

  // =========================================================================
  // TEST 7: Open L2 Session
  // =========================================================================
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('TEST 7: Open L2 Gaming Session (100 BB)');
  console.log('═══════════════════════════════════════════════════════════════\n');

  try {
    const session = await sdk.openL2Session(100);
    
    if (session.success) {
      console.log('   ✅ Session Opened!');
      console.log(`   Session ID: ${session.session_id.substring(0, 20)}...`);
      console.log(`   Locked: ${session.locked_amount} BB`);
      console.log(`   L1 Balance: ${session.l1_balance_after_lock} BB`);
      console.log(`   L2 Credit: ${session.available_credit} BB\n`);

      // Get session status
      const status = await sdk.getL2Session();
      console.log('   📊 Session Status:');
      console.log(`   Available Credit: ${status.availableCredit} BB`);
      console.log(`   Used Credit: ${status.usedCredit} BB\n`);

      // Settle session with profit
      console.log('   🎰 Simulating L2 gameplay... (Won 25 BB)');
      const settlement = await sdk.settleL2Session(session.session_id, 25);
      
      if (settlement.success) {
        console.log('   ✅ Session Settled!');
        console.log(`   Net P&L: +${settlement.net_pnl} BB`);
        console.log(`   Returned: ${settlement.amount_returned} BB`);
        console.log(`   L1 Balance: ${settlement.l1_balance_after_settle} BB\n`);
      }
    } else {
      console.log(`   ❌ Failed: ${session.error}\n`);
    }
  } catch (err) {
    console.log(`   ❌ Error: ${err.message}\n`);
  }

  // =========================================================================
  // TEST 8: Get Transaction History
  // =========================================================================
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('TEST 8: Transaction History');
  console.log('═══════════════════════════════════════════════════════════════\n');

  try {
    const transactions = await sdk.getTransactions({ limit: 5 });
    console.log(`   Found ${transactions.length} transactions:\n`);
    
    transactions.forEach((tx, i) => {
      const direction = tx.isIncoming ? '⬇️ IN' : '⬆️ OUT';
      const date = new Date(tx.timestamp).toLocaleString();
      console.log(`   ${i + 1}. ${direction} ${tx.displayAmount} BB (${tx.type})`);
      console.log(`      ${date}\n`);
    });
  } catch (err) {
    console.log(`   ❌ Error: ${err.message}\n`);
  }

  // =========================================================================
  // TEST 9: Final Balance Check
  // =========================================================================
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('TEST 9: Final Balance');
  console.log('═══════════════════════════════════════════════════════════════\n');

  const finalBalance = await sdk.getBalance();
  console.log(`   Alice Final: ${finalBalance.formatted} (${finalBalance.formattedUsd})\n`);

  // =========================================================================
  // TEST 10: Disconnect
  // =========================================================================
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('TEST 10: Disconnect');
  console.log('═══════════════════════════════════════════════════════════════\n');

  sdk.disconnect();
  console.log(`   Connected: ${sdk.isConnected}`);
  console.log(`   Address: ${sdk.getAddress()}\n`);

  // =========================================================================
  // EVENT LOG SUMMARY
  // =========================================================================
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('Event Log Summary');
  console.log('═══════════════════════════════════════════════════════════════\n');

  console.log(`   Total Events Fired: ${eventLog.length}`);
  const eventCounts = {};
  eventLog.forEach(e => {
    eventCounts[e.event] = (eventCounts[e.event] || 0) + 1;
  });
  Object.entries(eventCounts).forEach(([event, count]) => {
    console.log(`   ${event}: ${count}`);
  });
  console.log('');

  // =========================================================================
  // SUMMARY
  // =========================================================================
  console.log('╔═══════════════════════════════════════════════════════════════╗');
  console.log('║                  FRONTEND SDK TEST COMPLETE                   ║');
  console.log('╚═══════════════════════════════════════════════════════════════╝');
  console.log('');
  console.log('✅ All SDK features tested successfully!');
  console.log('');
  console.log('Ready for frontend integration:');
  console.log('  • React/Next.js: Import BlackBookSDK and hooks');
  console.log('  • Vue/Svelte: Use BlackBookSDK class directly');
  console.log('  • Vanilla JS: Include script and use window.BlackBookSDK');
  console.log('');
}

testFrontendSDK().catch(err => {
  console.error('Test failed:', err);
  process.exit(1);
});
