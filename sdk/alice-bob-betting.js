/**
 * ALICE & BOB BETTING TEST
 * =========================
 * Tests the full L1↔L2 betting flow:
 * 1. Approve credit lines (lock tokens on L1)
 * 2. Draw credit to L2 for betting
 * 3. Place bets on market "ab_charges"
 * 4. Resolve bets and settle
 * 
 * Uses SDK TEST_ACCOUNTS as single source of truth
 */

import nacl from 'tweetnacl';

const L1_URL = 'http://localhost:8080';
const CHAIN_ID_L1 = 0x01;

// Market configuration
const MARKET_ID = 'ab_charges';
const MARKET_OPTIONS = ['GUILTY', 'NOT_GUILTY'];

// ============================================================================
// TEST ACCOUNTS (correctly derived from seeds)
// Address = L1_ + SHA256(pubkey)[0..20].toUpperCase()
// ============================================================================
const TEST_ACCOUNTS = {
  ALICE: {
    username: 'alice_test',
    address: 'L1_52882D768C0F3E7932AAD1813CF8B19058D507A8',
    publicKey: '18f2c2e3bcb7a4b5329cfed4bd79bf17df4d47aa1888a6b3d1a1450fb53a8a24',
  },
  BOB: {
    username: 'bob_test',
    address: 'L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433',
    publicKey: 'e4ac49e5a04ef7dfc6e1a838fdf14597f2d514d0029a82cb45c916293487c25b',
  },
  DEALER: {
    username: 'dealer',
    address: 'L1_EB8B2F3A7F97A929D3B8C7E449432BC00D5097BC',
    publicKey: 'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d',
  }
};

// ============================================================================
// CRYPTO UTILITIES
// ============================================================================

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateNonce() {
  return crypto.randomUUID();
}

// Derive Ed25519 keypair from seed
function deriveKeypair(seedHex) {
  const seed = hexToBytes(seedHex);
  const keypair = nacl.sign.keyPair.fromSeed(seed);
  return {
    publicKey: bytesToHex(keypair.publicKey),
    secretKey: keypair.secretKey,
    seed: seedHex
  };
}

// Sign a message with Ed25519
function signMessage(message, secretKey) {
  const messageBytes = new TextEncoder().encode(message);
  const signature = nacl.sign.detached(messageBytes, secretKey);
  return bytesToHex(signature);
}

// ============================================================================
// ACCOUNT SETUP
// ============================================================================

const ALICE = {
  name: 'Alice',
  address: TEST_ACCOUNTS.ALICE.address,
  seed: TEST_ACCOUNTS.ALICE.publicKey,
  keypair: null,  // Will be derived
  bet: { option: 'GUILTY', amount: 500 }  // Alice bets 500 BB on GUILTY
};

const BOB = {
  name: 'Bob',
  address: TEST_ACCOUNTS.BOB.address,
  seed: TEST_ACCOUNTS.BOB.publicKey,
  keypair: null,  // Will be derived
  bet: { option: 'NOT_GUILTY', amount: 500 }  // Bob bets 500 BB on NOT_GUILTY
};

// Initialize keypairs
ALICE.keypair = deriveKeypair(ALICE.seed);
BOB.keypair = deriveKeypair(BOB.seed);

// ============================================================================
// API HELPERS
// ============================================================================

async function getBalance(address) {
  const res = await fetch(`${L1_URL}/balance/${address}`);
  const data = await res.json();
  return data.balance || 0;
}

async function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ============================================================================
// CREDIT LINE OPERATIONS
// ============================================================================

async function approveCredit(user, creditLimit) {
  const nonce = generateNonce();
  const message = `APPROVE_CREDIT:${user.address}:${creditLimit}:${nonce}`;
  const signature = signMessage(message, user.keypair.secretKey);
  
  const res = await fetch(`${L1_URL}/credit/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      wallet_address: user.address,
      credit_limit: creditLimit,
      expires_in_hours: 24,
      public_key: user.keypair.publicKey,
      signature: signature,
      nonce: nonce
    })
  });
  
  return await res.json();
}

async function drawCredit(user, amount, reason) {
  const nonce = generateNonce();
  const message = `CREDIT_DRAW:${user.address}:${amount}:${reason}:${nonce}`;
  const signature = signMessage(message, user.keypair.secretKey);
  
  const res = await fetch(`${L1_URL}/credit/draw`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      wallet_address: user.address,
      amount: amount,
      reason: reason,
      public_key: user.keypair.publicKey,
      signature: signature,
      nonce: nonce
    })
  });
  
  return await res.json();
}

async function getCreditStatus(address) {
  const res = await fetch(`${L1_URL}/credit/status/${address}`);
  return await res.json();
}

async function settleCredit(user, finalPnL) {
  const nonce = generateNonce();
  const message = `CREDIT_SETTLE:${user.address}:${finalPnL}:${nonce}`;
  const signature = signMessage(message, user.keypair.secretKey);
  
  const res = await fetch(`${L1_URL}/credit/settle`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      wallet_address: user.address,
      final_pnl: finalPnL,
      public_key: user.keypair.publicKey,
      signature: signature,
      nonce: nonce
    })
  });
  
  return await res.json();
}

// ============================================================================
// BET SIMULATION (L2 logic simulated locally)
// ============================================================================

class Market {
  constructor(id, options) {
    this.id = id;
    this.options = options;
    this.bets = [];
    this.totalPool = 0;
    this.resolved = false;
    this.winningOption = null;
  }
  
  placeBet(user, option, amount) {
    if (this.resolved) {
      return { success: false, error: 'Market already resolved' };
    }
    if (!this.options.includes(option)) {
      return { success: false, error: `Invalid option. Must be one of: ${this.options.join(', ')}` };
    }
    
    this.bets.push({
      user: user.name,
      address: user.address,
      option: option,
      amount: amount,
      timestamp: Date.now()
    });
    this.totalPool += amount;
    
    return { 
      success: true, 
      bet: this.bets[this.bets.length - 1],
      totalPool: this.totalPool
    };
  }
  
  resolve(winningOption) {
    if (this.resolved) {
      return { success: false, error: 'Already resolved' };
    }
    if (!this.options.includes(winningOption)) {
      return { success: false, error: 'Invalid winning option' };
    }
    
    this.resolved = true;
    this.winningOption = winningOption;
    
    // Calculate payouts
    const winningBets = this.bets.filter(b => b.option === winningOption);
    const losingBets = this.bets.filter(b => b.option !== winningOption);
    
    const winningPool = winningBets.reduce((sum, b) => sum + b.amount, 0);
    const losingPool = losingBets.reduce((sum, b) => sum + b.amount, 0);
    
    // Simple pari-mutuel: winners split losers' pool proportionally
    const results = [];
    
    for (const bet of this.bets) {
      if (bet.option === winningOption) {
        // Winner: get back stake + proportion of losing pool
        const shareOfWinnings = (bet.amount / winningPool) * losingPool;
        const payout = bet.amount + shareOfWinnings;
        const pnl = shareOfWinnings;
        results.push({ ...bet, won: true, payout, pnl });
      } else {
        // Loser: lose stake
        results.push({ ...bet, won: false, payout: 0, pnl: -bet.amount });
      }
    }
    
    return {
      success: true,
      winningOption,
      totalPool: this.totalPool,
      winningPool,
      losingPool,
      results
    };
  }
}

// ============================================================================
// MAIN TEST
// ============================================================================

async function main() {
  console.log('╔═══════════════════════════════════════════════════════════════════════╗');
  console.log('║  ALICE & BOB BETTING TEST - Market: ab_charges                        ║');
  console.log('║  Alice bets GUILTY, Bob bets NOT_GUILTY                               ║');
  console.log('╚═══════════════════════════════════════════════════════════════════════╝');
  console.log('');
  
  // Check server health
  console.log('📡 Checking L1 server...');
  try {
    const health = await fetch(`${L1_URL}/health`).then(r => r.json());
    console.log(`✅ L1 Server: ${health.status}`);
  } catch (e) {
    console.log('❌ L1 Server not responding. Start with: cargo run --bin layer1');
    process.exit(1);
  }
  console.log('');
  
  // Get initial balances
  console.log('💰 Initial L1 Balances:');
  const aliceInitial = await getBalance(ALICE.address);
  const bobInitial = await getBalance(BOB.address);
  console.log(`   Alice: ${aliceInitial} BB`);
  console.log(`   Bob:   ${bobInitial} BB`);
  console.log('');
  
  // =========================================================================
  // STEP 1: Approve Credit Lines
  // =========================================================================
  console.log('═══════════════════════════════════════════════════════════════════════');
  console.log('  STEP 1: APPROVE CREDIT LINES (Lock tokens on L1)');
  console.log('═══════════════════════════════════════════════════════════════════════');
  console.log('');
  
  const CREDIT_LIMIT = 1000;  // Each user locks 1000 BB as collateral
  
  console.log(`🔐 Alice approving ${CREDIT_LIMIT} BB credit line...`);
  await delay(100);
  const aliceApproval = await approveCredit(ALICE, CREDIT_LIMIT);
  if (aliceApproval.success) {
    console.log(`   ✅ Approved! Lock ID: ${aliceApproval.lock_id?.slice(0,16)}...`);
    console.log(`   📍 Session ID: ${aliceApproval.approval?.approval_id}`);
  } else {
    console.log(`   ❌ Failed: ${aliceApproval.error}`);
    if (aliceApproval.existing_session_id) {
      console.log(`   ℹ️  Existing session: ${aliceApproval.existing_session_id}`);
    }
  }
  console.log('');
  
  await delay(100);
  
  console.log(`🔐 Bob approving ${CREDIT_LIMIT} BB credit line...`);
  const bobApproval = await approveCredit(BOB, CREDIT_LIMIT);
  if (bobApproval.success) {
    console.log(`   ✅ Approved! Lock ID: ${bobApproval.lock_id?.slice(0,16)}...`);
    console.log(`   📍 Session ID: ${bobApproval.approval?.approval_id}`);
  } else {
    console.log(`   ❌ Failed: ${bobApproval.error}`);
    if (bobApproval.existing_session_id) {
      console.log(`   ℹ️  Existing session: ${bobApproval.existing_session_id}`);
    }
  }
  console.log('');
  
  // =========================================================================
  // STEP 2: Draw Credit for Betting
  // =========================================================================
  console.log('═══════════════════════════════════════════════════════════════════════');
  console.log('  STEP 2: DRAW CREDIT TO L2 FOR BETTING');
  console.log('═══════════════════════════════════════════════════════════════════════');
  console.log('');
  
  console.log(`💳 Alice drawing ${ALICE.bet.amount} BB for betting...`);
  await delay(100);
  const aliceDraw = await drawCredit(ALICE, ALICE.bet.amount, `bet_${MARKET_ID}`);
  if (aliceDraw.success) {
    console.log(`   ✅ Drew ${ALICE.bet.amount} BB to L2`);
    console.log(`   📊 L2 Balance: ${aliceDraw.l2_balance} BB`);
    console.log(`   📊 Available Credit: ${aliceDraw.credit_status?.available_credit} BB`);
  } else {
    console.log(`   ❌ Failed: ${aliceDraw.error}`);
  }
  console.log('');
  
  await delay(100);
  
  console.log(`💳 Bob drawing ${BOB.bet.amount} BB for betting...`);
  const bobDraw = await drawCredit(BOB, BOB.bet.amount, `bet_${MARKET_ID}`);
  if (bobDraw.success) {
    console.log(`   ✅ Drew ${BOB.bet.amount} BB to L2`);
    console.log(`   📊 L2 Balance: ${bobDraw.l2_balance} BB`);
    console.log(`   📊 Available Credit: ${bobDraw.credit_status?.available_credit} BB`);
  } else {
    console.log(`   ❌ Failed: ${bobDraw.error}`);
  }
  console.log('');
  
  // =========================================================================
  // STEP 3: Place Bets on Market
  // =========================================================================
  console.log('═══════════════════════════════════════════════════════════════════════');
  console.log(`  STEP 3: PLACE BETS ON MARKET "${MARKET_ID}"`);
  console.log('═══════════════════════════════════════════════════════════════════════');
  console.log('');
  
  const market = new Market(MARKET_ID, MARKET_OPTIONS);
  
  console.log(`🎲 Alice betting ${ALICE.bet.amount} BB on ${ALICE.bet.option}...`);
  await delay(100);
  const aliceBet = market.placeBet(ALICE, ALICE.bet.option, ALICE.bet.amount);
  if (aliceBet.success) {
    console.log(`   ✅ Bet placed! Pool: ${aliceBet.totalPool} BB`);
  } else {
    console.log(`   ❌ Failed: ${aliceBet.error}`);
  }
  console.log('');
  
  await delay(100);
  
  console.log(`🎲 Bob betting ${BOB.bet.amount} BB on ${BOB.bet.option}...`);
  const bobBet = market.placeBet(BOB, BOB.bet.option, BOB.bet.amount);
  if (bobBet.success) {
    console.log(`   ✅ Bet placed! Pool: ${bobBet.totalPool} BB`);
  } else {
    console.log(`   ❌ Failed: ${bobBet.error}`);
  }
  console.log('');
  
  // Show market state
  console.log('📊 Market State:');
  console.log(`   Market ID: ${market.id}`);
  console.log(`   Total Pool: ${market.totalPool} BB`);
  console.log(`   Bets:`);
  for (const bet of market.bets) {
    console.log(`     - ${bet.user}: ${bet.amount} BB on ${bet.option}`);
  }
  console.log('');
  
  // =========================================================================
  // STEP 4: Resolve Market
  // =========================================================================
  console.log('═══════════════════════════════════════════════════════════════════════');
  console.log('  STEP 4: RESOLVE MARKET');
  console.log('═══════════════════════════════════════════════════════════════════════');
  console.log('');
  
  // Simulate resolution - GUILTY wins (Alice wins, Bob loses)
  const WINNING_OPTION = 'GUILTY';
  console.log(`⚖️  Resolving market... Winner: ${WINNING_OPTION}`);
  await delay(200);
  
  const resolution = market.resolve(WINNING_OPTION);
  if (resolution.success) {
    console.log(`   ✅ Market resolved!`);
    console.log(`   🏆 Winning Option: ${resolution.winningOption}`);
    console.log(`   💰 Total Pool: ${resolution.totalPool} BB`);
    console.log(`   💚 Winning Pool: ${resolution.winningPool} BB`);
    console.log(`   💔 Losing Pool: ${resolution.losingPool} BB`);
    console.log('');
    console.log('   📊 Results:');
    for (const result of resolution.results) {
      const status = result.won ? '🏆 WON' : '💔 LOST';
      console.log(`     ${result.user}: ${status} | Bet: ${result.amount} BB | P&L: ${result.pnl >= 0 ? '+' : ''}${result.pnl} BB`);
    }
  }
  console.log('');
  
  // =========================================================================
  // STEP 5: Settle Credit Lines
  // =========================================================================
  console.log('═══════════════════════════════════════════════════════════════════════');
  console.log('  STEP 5: SETTLE CREDIT LINES (Unlock tokens on L1)');
  console.log('═══════════════════════════════════════════════════════════════════════');
  console.log('');
  
  // Calculate final P&L for each user
  const alicePnL = resolution.results.find(r => r.user === 'Alice')?.pnl || 0;
  const bobPnL = resolution.results.find(r => r.user === 'Bob')?.pnl || 0;
  
  console.log(`💰 Alice settling with P&L: ${alicePnL >= 0 ? '+' : ''}${alicePnL} BB...`);
  await delay(100);
  const aliceSettle = await settleCredit(ALICE, alicePnL);
  if (aliceSettle.success) {
    console.log(`   ✅ Settled! Tokens unlocked.`);
    console.log(`   📊 Final L1 Balance: ${aliceSettle.new_balance} BB`);
  } else {
    console.log(`   ❌ Failed: ${aliceSettle.error}`);
  }
  console.log('');
  
  await delay(100);
  
  console.log(`💰 Bob settling with P&L: ${bobPnL >= 0 ? '+' : ''}${bobPnL} BB...`);
  const bobSettle = await settleCredit(BOB, bobPnL);
  if (bobSettle.success) {
    console.log(`   ✅ Settled! Tokens unlocked.`);
    console.log(`   📊 Final L1 Balance: ${bobSettle.new_balance} BB`);
  } else {
    console.log(`   ❌ Failed: ${bobSettle.error}`);
  }
  console.log('');
  
  // =========================================================================
  // FINAL SUMMARY
  // =========================================================================
  console.log('═══════════════════════════════════════════════════════════════════════');
  console.log('  FINAL SUMMARY');
  console.log('═══════════════════════════════════════════════════════════════════════');
  console.log('');
  
  const aliceFinal = await getBalance(ALICE.address);
  const bobFinal = await getBalance(BOB.address);
  
  console.log('💰 Final L1 Balances:');
  console.log(`   Alice: ${aliceFinal} BB (${aliceFinal >= aliceInitial ? '+' : ''}${aliceFinal - aliceInitial} BB)`);
  console.log(`   Bob:   ${bobFinal} BB (${bobFinal >= bobInitial ? '+' : ''}${bobFinal - bobInitial} BB)`);
  console.log('');
  
  console.log('📊 Betting Summary:');
  console.log(`┌──────────┬────────────────┬────────────┬────────────┬──────────┐`);
  console.log(`│ User     │ Bet            │ Amount     │ Result     │ P&L      │`);
  console.log(`├──────────┼────────────────┼────────────┼────────────┼──────────┤`);
  console.log(`│ Alice    │ ${ALICE.bet.option.padEnd(14)} │ ${String(ALICE.bet.amount + ' BB').padEnd(10)} │ ${WINNING_OPTION === ALICE.bet.option ? '🏆 WON'.padEnd(10) : '💔 LOST'.padEnd(10)} │ ${(alicePnL >= 0 ? '+' : '') + alicePnL + ' BB'.padEnd(8)} │`);
  console.log(`│ Bob      │ ${BOB.bet.option.padEnd(14)} │ ${String(BOB.bet.amount + ' BB').padEnd(10)} │ ${WINNING_OPTION === BOB.bet.option ? '🏆 WON'.padEnd(10) : '💔 LOST'.padEnd(10)} │ ${(bobPnL >= 0 ? '+' : '') + bobPnL + ' BB'.padEnd(8)} │`);
  console.log(`└──────────┴────────────────┴────────────┴────────────┴──────────┘`);
  console.log('');
  
  console.log(`🎯 Market "${MARKET_ID}" resolved with ${WINNING_OPTION} winning!`);
}

main().catch(console.error);
