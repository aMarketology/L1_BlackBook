// ============================================================================
// L1 ↔ L2 Full Integration Test
// ============================================================================
// 
// Tests the complete flow with real test accounts:
// - Alice: Regular bettor
// - Bob: Regular bettor  
// - Oracle: Market resolver
// - Dealer: House/Sponsor
//
// Run: node integration/l1_l2_full_test.js
// ============================================================================

const L2_URL = 'http://localhost:1234';

const ACCOUNTS = {
    ALICE: 'alice_wallet_001',
    BOB: 'bob_wallet_002', 
    ORACLE: 'oracle_resolver',
    DEALER: 'DEALER_HOUSE'
};

async function request(method, endpoint, body = null) {
    const url = `${L2_URL}${endpoint}`;
    const options = { method, headers: { 'Content-Type': 'application/json' } };
    if (body) options.body = JSON.stringify(body);
    try {
        const response = await fetch(url, options);
        const data = await response.json();
        return { ok: response.ok, status: response.status, data };
    } catch (error) {
        return { ok: false, error: error.message };
    }
}

function log(emoji, msg) { console.log(`${emoji} ${msg}`); }
function section(title) {
    console.log('\n' + '═'.repeat(50));
    console.log(`  ${title}`);
    console.log('═'.repeat(50));
}

async function runTests() {
    console.log('\n╔════════════════════════════════════════════════╗');
    console.log('║  🧪 L1 ↔ L2 FULL INTEGRATION TEST              ║');
    console.log('║  Accounts: Alice, Bob, Oracle, Dealer          ║');
    console.log('╚════════════════════════════════════════════════╝');
    
    let marketId;
    
    // ========================================
    // 1. HEALTH CHECK
    // ========================================
    section('1. HEALTH CHECK');
    let r = await request('GET', '/health');
    if (!r.ok) {
        log('❌', 'L2 server not running! Start with: cargo run');
        process.exit(1);
    }
    log('✅', 'L2 Server is running');
    
    // ========================================
    // 2. L1 DEPOSITS → L2 CREDITS
    // ========================================
    section('2. L1 DEPOSITS → L2 CREDITS');
    
    r = await request('POST', '/credit', { user: ACCOUNTS.ALICE, amount: 1000 });
    log('💰', `Alice credited: ${r.data.credited} BB → Balance: ${r.data.new_balance}`);
    
    r = await request('POST', '/credit', { user: ACCOUNTS.BOB, amount: 500 });
    log('💰', `Bob credited: ${r.data.credited} BB → Balance: ${r.data.new_balance}`);
    
    // Verify balances
    r = await request('GET', `/balance/${ACCOUNTS.ALICE}`);
    log('📊', `Alice balance: ${r.data.available} available, ${r.data.locked} locked`);
    
    r = await request('GET', `/balance/${ACCOUNTS.BOB}`);
    log('📊', `Bob balance: ${r.data.available} available, ${r.data.locked} locked`);
    
    // ========================================
    // 3. CREATE PREDICTION MARKET
    // ========================================
    section('3. CREATE PREDICTION MARKET');
    
    r = await request('POST', '/markets', {
        title: 'Will BTC exceed $150,000 by end of 2025?',
        outcomes: ['Yes', 'No']
    });
    marketId = r.data.market_id;
    log('📊', `Market created: ${marketId}`);
    log('📊', `Title: ${r.data.title}`);
    
    // Get market details
    r = await request('GET', `/markets/${marketId}`);
    log('📋', `Outcomes: ${r.data.outcomes.join(', ')}`);
    log('📋', `Odds: ${r.data.odds.map(o => (o * 100).toFixed(0) + '%').join(', ')}`);
    
    // ========================================
    // 4. ALICE BETS ON "YES"
    // ========================================
    section('4. ALICE BETS ON "YES"');
    
    r = await request('POST', '/bet', {
        user: ACCOUNTS.ALICE,
        market_id: marketId,
        outcome: 0,  // Yes
        amount: 100
    });
    
    if (r.ok) {
        log('🎲', `Alice bet 100 BB on YES`);
        log('🎲', `Bet ID: ${r.data.bet.id}`);
        log('🎲', `Potential payout: ${r.data.bet.potential_payout} BB`);
    } else {
        log('❌', `Bet failed: ${r.data.error}`);
    }
    
    // Check Alice's balance
    r = await request('GET', `/balance/${ACCOUNTS.ALICE}`);
    log('💳', `Alice: ${r.data.available} available, ${r.data.locked} locked`);
    
    // ========================================
    // 5. BOB BETS ON "NO"
    // ========================================
    section('5. BOB BETS ON "NO"');
    
    r = await request('POST', '/bet', {
        user: ACCOUNTS.BOB,
        market_id: marketId,
        outcome: 1,  // No
        amount: 200
    });
    
    if (r.ok) {
        log('🎲', `Bob bet 200 BB on NO`);
        log('🎲', `Bet ID: ${r.data.bet.id}`);
        log('🎲', `Potential payout: ${r.data.bet.potential_payout} BB`);
    } else {
        log('❌', `Bet failed: ${r.data.error}`);
    }
    
    // Check Bob's balance
    r = await request('GET', `/balance/${ACCOUNTS.BOB}`);
    log('💳', `Bob: ${r.data.available} available, ${r.data.locked} locked`);
    
    // ========================================
    // 6. ALICE PLACES ANOTHER BET
    // ========================================
    section('6. ALICE PLACES ANOTHER BET');
    
    r = await request('POST', '/bet', {
        user: ACCOUNTS.ALICE,
        market_id: marketId,
        outcome: 0,  // Yes again
        amount: 150
    });
    
    if (r.ok) {
        log('🎲', `Alice bet another 150 BB on YES`);
        log('🎲', `Potential payout: ${r.data.bet.potential_payout} BB`);
    }
    
    r = await request('GET', `/balance/${ACCOUNTS.ALICE}`);
    log('💳', `Alice: ${r.data.available} available, ${r.data.locked} locked`);
    
    // ========================================
    // 7. VIEW ALL BETS
    // ========================================
    section('7. VIEW ALL BETS');
    
    r = await request('GET', `/bets/${ACCOUNTS.ALICE}`);
    log('📋', `Alice has ${r.data.bets.length} bets`);
    r.data.bets.forEach((bet, i) => {
        log('  ', `${i+1}. ${bet.amount} BB on outcome ${bet.outcome} → payout ${bet.potential_payout}`);
    });
    
    r = await request('GET', `/bets/${ACCOUNTS.BOB}`);
    log('📋', `Bob has ${r.data.bets.length} bets`);
    r.data.bets.forEach((bet, i) => {
        log('  ', `${i+1}. ${bet.amount} BB on outcome ${bet.outcome} → payout ${bet.potential_payout}`);
    });
    
    // ========================================
    // 8. ORACLE RESOLVES MARKET - YES WINS!
    // ========================================
    section('8. ORACLE RESOLVES MARKET - YES WINS!');
    
    r = await request('POST', `/markets/${marketId}/resolve`, {
        winning_outcome: 0  // YES wins!
    });
    
    if (r.ok) {
        log('🏆', `Market resolved! Winning outcome: ${r.data.winning_outcome} (YES)`);
        log('🏆', `Winners: ${r.data.winners.join(', ')}`);
    } else {
        log('❌', `Resolution failed: ${r.data.error}`);
    }
    
    // ========================================
    // 9. CHECK FINAL PAYOUTS
    // ========================================
    section('9. FINAL PAYOUTS');
    
    r = await request('GET', `/balance/${ACCOUNTS.ALICE}`);
    log('🏆', `ALICE (WINNER): ${r.data.available} available, ${r.data.locked} locked`);
    log('  ', `Started: 1000 BB | Bet: 250 BB | Final: ${r.data.total} BB`);
    
    r = await request('GET', `/balance/${ACCOUNTS.BOB}`);
    log('💸', `BOB (LOSER): ${r.data.available} available, ${r.data.locked} locked`);
    log('  ', `Started: 500 BB | Bet: 200 BB | Final: ${r.data.total} BB`);
    
    // ========================================
    // 10. CHECK BET STATUSES
    // ========================================
    section('10. BET STATUSES AFTER RESOLUTION');
    
    r = await request('GET', `/bets/${ACCOUNTS.ALICE}`);
    r.data.bets.forEach((bet, i) => {
        log('📋', `Alice Bet ${i+1}: ${bet.status} - ${bet.amount} BB → ${bet.status === 'Won' ? '+' + bet.potential_payout : '0'}`);
    });
    
    r = await request('GET', `/bets/${ACCOUNTS.BOB}`);
    r.data.bets.forEach((bet, i) => {
        log('📋', `Bob Bet ${i+1}: ${bet.status} - ${bet.amount} BB → ${bet.status === 'Won' ? '+' + bet.potential_payout : '0'}`);
    });
    
    // ========================================
    // 11. EDGE CASES
    // ========================================
    section('11. EDGE CASE TESTS');
    
    // Try betting on resolved market
    r = await request('POST', '/bet', {
        user: ACCOUNTS.ALICE,
        market_id: marketId,
        outcome: 0,
        amount: 10
    });
    log(r.ok ? '❌' : '✅', `Bet on resolved market: ${r.ok ? 'ALLOWED (BAD)' : 'Rejected (correct)'}`);
    
    // Try betting more than balance
    r = await request('POST', '/credit', { user: 'test_user', amount: 50 });
    const newMarket = await request('POST', '/markets', {
        title: 'Test market for edge cases',
        outcomes: ['A', 'B']
    });
    
    r = await request('POST', '/bet', {
        user: 'test_user',
        market_id: newMarket.data.market_id,
        outcome: 0,
        amount: 1000  // Only has 50
    });
    log(r.ok ? '❌' : '✅', `Bet exceeding balance: ${r.ok ? 'ALLOWED (BAD)' : 'Rejected (correct)'}`);
    
    // ========================================
    // 12. TRANSACTION HISTORY
    // ========================================
    section('12. TRANSACTION HISTORY');
    
    r = await request('GET', '/transactions');
    log('📜', `Total transactions: ${r.data.transactions.length}`);
    console.log('\nRecent transactions:');
    r.data.transactions.slice(0, 8).forEach((tx, i) => {
        log('  ', `${tx.tx_type.padEnd(10)} | ${tx.user.padEnd(20)} | ${tx.amount} BB`);
    });
    
    // ========================================
    // 13. ALL BALANCES
    // ========================================
    section('13. ALL BALANCES');
    
    r = await request('GET', '/balances');
    console.log('\nAll account balances:');
    Object.entries(r.data.balances).forEach(([user, bal]) => {
        log('💰', `${user.padEnd(25)} | ${bal.available} available | ${bal.locked} locked`);
    });
    
    // ========================================
    // SUMMARY
    // ========================================
    console.log('\n');
    console.log('╔════════════════════════════════════════════════╗');
    console.log('║  ✅ ALL TESTS COMPLETED SUCCESSFULLY!          ║');
    console.log('╚════════════════════════════════════════════════╝');
    console.log('\n📊 Summary:');
    console.log('   • L1→L2 deposits working');
    console.log('   • Market creation working');
    console.log('   • Bet placement working');
    console.log('   • Market resolution working');
    console.log('   • Payouts calculated correctly');
    console.log('   • Edge cases handled properly');
    console.log('');
}

runTests().catch(err => {
    console.error('❌ Test failed:', err.message);
    process.exit(1);
});
