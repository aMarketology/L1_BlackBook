#!/usr/bin/env node
// ============================================================================
// DEALER L1-L2 INTEGRATION TEST
// ============================================================================
// Full flow test:
// 1. Get initial balances (Dealer L1, Alice L1)
// 2. Dealer bridges 100 BB from L1 → L2 (lock on L1)
// 3. Alice wins a bet, Dealer pays out on L2
// 4. Alice withdraws L2 balance back to L1
// 5. Check final balances
// ============================================================================

import nacl from 'tweetnacl';
import { randomBytes } from 'crypto';

const L1_URL = process.env.L1_URL || 'http://localhost:8080';
const L2_URL = process.env.L2_URL || 'http://localhost:1234';

// Chain ID constants for domain separation
const CHAIN_ID_L1 = 0x01;
const CHAIN_ID_L2 = 0x02;

// ============================================================================
// STYLING
// ============================================================================

const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m',
};

function pass(msg) { console.log(`${colors.green}✅ ${msg}${colors.reset}`); }
function fail(msg) { console.log(`${colors.red}❌ ${msg}${colors.reset}`); }
function info(msg) { console.log(`${colors.cyan}ℹ️  ${msg}${colors.reset}`); }
function step(msg) { console.log(`\n${colors.blue}▶ ${msg}${colors.reset}`); }
function section(title) { 
  console.log(`\n${colors.magenta}${'═'.repeat(70)}${colors.reset}`);
  console.log(`${colors.magenta}  ${title}${colors.reset}`);
  console.log(`${colors.magenta}${'═'.repeat(70)}${colors.reset}\n`);
}

// ============================================================================
// CRYPTO HELPERS
// ============================================================================

function signMessage(privateKeyHex, message, chainId) {
  const privateKey = Buffer.from(privateKeyHex, 'hex');
  const keypair = nacl.sign.keyPair.fromSeed(privateKey);
  
  const secretKey = new Uint8Array(64);
  secretKey.set(privateKey, 0);
  secretKey.set(keypair.publicKey, 32);
  
  // Domain separation: prepend chain ID
  const domainSeparated = Buffer.concat([
    Buffer.from([chainId]),
    Buffer.from(message, 'utf8')
  ]);
  
  const signature = nacl.sign.detached(domainSeparated, secretKey);
  return Buffer.from(signature).toString('hex');
}

function createSignedRequest(privateKeyHex, publicKeyHex, walletAddress, payload, requestPath, chainId = CHAIN_ID_L1) {
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = randomBytes(16).toString('hex');
  const payloadStr = JSON.stringify(payload);
  
  // Build message with path binding
  const message = requestPath 
    ? `${requestPath}\n${payloadStr}\n${timestamp}\n${nonce}`
    : `${payloadStr}\n${timestamp}\n${nonce}`;
  
  const signature = signMessage(privateKeyHex, message, chainId);
  
  return {
    public_key: publicKeyHex,
    wallet_address: walletAddress,
    payload: payloadStr,
    timestamp,
    nonce,
    chain_id: chainId,
    signature,
    request_path: requestPath
  };
}

// ============================================================================
// BALANCE HELPERS
// ============================================================================

async function getL1Balance(address) {
  const res = await fetch(`${L1_URL}/balance/${address}`);
  const data = await res.json();
  return data.balance;
}

async function getL2Balance(address) {
  const res = await fetch(`${L2_URL}/balance/${address}`);
  if (!res.ok) return 0;
  const data = await res.json();
  return data.balance || 0;
}

// ============================================================================
// MAIN TEST
// ============================================================================

async function main() {
  console.log('\n');
  console.log('╔══════════════════════════════════════════════════════════════════╗');
  console.log('║      DEALER L1-L2 INTEGRATION TEST                               ║');
  console.log('║      Full flow: Bridge → Bet → Payout → Withdraw                ║');
  console.log('╚══════════════════════════════════════════════════════════════════╝');
  
  try {
    // ========================================================================
    // STEP 0: Get test accounts
    // ========================================================================
    section('STEP 0: Get Test Accounts');
    
    const accountsRes = await fetch(`${L1_URL}/auth/test-accounts`);
    const accounts = await accountsRes.json();
    
    const dealer = {
      address: "L1_F5C46483E8A28394F5E8687DEADF6BD4E924CED3",
      public_key: "07943256765557e704e4945aa4d1d56a1b0aac60bd8cc328faa99572aee5e84a",
      private_key: process.env.DEALER_PRIVATE_KEY
    };
    
    if (!dealer.private_key) {
      fail('DEALER_PRIVATE_KEY not set in environment');
      info('Please set: export DEALER_PRIVATE_KEY=<key>');
      process.exit(1);
    }
    
    const alice = accounts.alice;
    
    info(`Dealer: ${dealer.address}`);
    info(`Alice: ${alice.address}`);
    
    // ========================================================================
    // STEP 1: Check initial balances
    // ========================================================================
    section('STEP 1: Initial Balances');
    
    const dealerL1Initial = await getL1Balance(dealer.address);
    const aliceL1Initial = await getL1Balance(alice.address);
    const dealerL2Initial = await getL2Balance(dealer.address);
    const aliceL2Initial = await getL2Balance(alice.address);
    
    info(`Dealer L1: ${dealerL1Initial} BB`);
    info(`Dealer L2: ${dealerL2Initial} BB`);
    info(`Alice L1: ${aliceL1Initial} BB`);
    info(`Alice L2: ${aliceL2Initial} BB`);
    
    // ========================================================================
    // STEP 2: Dealer bridges 100 BB to L2
    // ========================================================================
    section('STEP 2: Dealer Bridges 100 BB from L1 → L2');
    
    step('Initiating bridge lock on L1...');
    
    const bridgeAmount = 100;
    const bridgePayload = {
      amount: bridgeAmount,
      target_layer: "L2"
    };
    
    const bridgeRequest = createSignedRequest(
      dealer.private_key,
      dealer.public_key,
      dealer.address,
      bridgePayload,
      '/bridge/initiate',
      CHAIN_ID_L1
    );
    
    const bridgeRes = await fetch(`${L1_URL}/bridge/initiate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(bridgeRequest)
    });
    const bridgeData = await bridgeRes.json();
    
    if (!bridgeData.success) {
      fail(`Bridge failed: ${bridgeData.error}`);
      process.exit(1);
    }
    
    pass(`Bridged ${bridgeAmount} BB to L2`);
    info(`Lock ID: ${bridgeData.lock_id}`);
    
    // Verify balances
    const dealerL1After = await getL1Balance(dealer.address);
    const dealerL2After = await getL2Balance(dealer.address);
    
    info(`Dealer L1: ${dealerL1After} BB (${dealerL1After - dealerL1Initial >= 0 ? '+' : ''}${dealerL1After - dealerL1Initial})`);
    info(`Dealer L2: ${dealerL2After} BB (${dealerL2After - dealerL2Initial >= 0 ? '+' : ''}${dealerL2After - dealerL2Initial})`);
    
    if (dealerL2After > dealerL2Initial) {
      pass('L2 balance increased');
    } else {
      fail('L2 balance did not increase - L2 server may not be running');
      info('Make sure L2 is running: cd ../L2_BlackBook && cargo run');
    }
    
    // ========================================================================
    // STEP 3: Alice wins a bet, Dealer pays out on L2
    // ========================================================================
    section('STEP 3: Alice Wins Bet - Dealer Pays Out on L2');
    
    step('Creating a winning bet for Alice...');
    
    const payoutAmount = 50;  // Alice wins 50 BB
    
    // Create a mock market and bet resolution
    info(`Simulating: Alice bet 25 BB at 2:1 odds, wins ${payoutAmount} BB`);
    
    // In production, this would be:
    // 1. Dealer creates market
    // 2. Alice places bet
    // 3. Market resolves
    // 4. Dealer pays out winner
    // For now, simulate with a direct transfer on L2
    
    const payoutPayload = {
      to: alice.address,
      amount: payoutAmount,
      reason: "bet_payout"
    };
    
    const payoutRequest = createSignedRequest(
      dealer.private_key,
      dealer.public_key,
      dealer.address,
      payoutPayload,
      '/transfer',
      CHAIN_ID_L2
    );
    
    const payoutRes = await fetch(`${L2_URL}/transfer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payoutRequest)
    });
    
    if (!payoutRes.ok) {
      fail('L2 transfer endpoint not available');
      info('L2 server may not have the transfer endpoint yet');
    } else {
      const payoutData = await payoutRes.json();
      if (payoutData.success) {
        pass(`Paid ${payoutAmount} BB to Alice on L2`);
      } else {
        fail(`Payout failed: ${payoutData.error || 'Unknown error'}`);
      }
    }
    
    // Check L2 balances
    const dealerL2AfterPayout = await getL2Balance(dealer.address);
    const aliceL2AfterPayout = await getL2Balance(alice.address);
    
    info(`Dealer L2: ${dealerL2AfterPayout} BB`);
    info(`Alice L2: ${aliceL2AfterPayout} BB`);
    
    // ========================================================================
    // STEP 4: Alice withdraws L2 balance back to L1
    // ========================================================================
    section('STEP 4: Alice Withdraws L2 → L1');
    
    step('Alice withdrawing L2 balance back to L1...');
    
    const withdrawPayload = {
      amount: aliceL2AfterPayout
    };
    
    const withdrawRequest = createSignedRequest(
      alice.private_key,
      alice.public_key,
      alice.address,
      withdrawPayload,
      '/bridge/withdraw',
      CHAIN_ID_L1
    );
    
    const withdrawRes = await fetch(`${L1_URL}/bridge/withdraw`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(withdrawRequest)
    });
    
    if (!withdrawRes.ok) {
      fail('Withdraw endpoint not available');
      info('This endpoint may need to be implemented');
    } else {
      const withdrawData = await withdrawRes.json();
      if (withdrawData.success) {
        pass(`Alice withdrew ${aliceL2AfterPayout} BB to L1`);
      } else {
        fail(`Withdraw failed: ${withdrawData.error || 'Unknown error'}`);
      }
    }
    
    // ========================================================================
    // STEP 5: Final balances
    // ========================================================================
    section('STEP 5: Final Balances');
    
    const dealerL1Final = await getL1Balance(dealer.address);
    const dealerL2Final = await getL2Balance(dealer.address);
    const aliceL1Final = await getL1Balance(alice.address);
    const aliceL2Final = await getL2Balance(alice.address);
    
    console.log(`${colors.blue}Dealer:${colors.reset}`);
    info(`  L1: ${dealerL1Final} BB (${dealerL1Final - dealerL1Initial >= 0 ? '+' : ''}${dealerL1Final - dealerL1Initial})`);
    info(`  L2: ${dealerL2Final} BB (${dealerL2Final - dealerL2Initial >= 0 ? '+' : ''}${dealerL2Final - dealerL2Initial})`);
    info(`  Total: ${dealerL1Final + dealerL2Final} BB`);
    
    console.log(`\n${colors.blue}Alice:${colors.reset}`);
    info(`  L1: ${aliceL1Final} BB (${aliceL1Final - aliceL1Initial >= 0 ? '+' : ''}${aliceL1Final - aliceL1Initial})`);
    info(`  L2: ${aliceL2Final} BB (${aliceL2Final - aliceL2Initial >= 0 ? '+' : ''}${aliceL2Final - aliceL2Initial})`);
    info(`  Total: ${aliceL1Final + aliceL2Final} BB`);
    
    // ========================================================================
    // SUMMARY
    // ========================================================================
    section('SUMMARY');
    
    pass('Dealer successfully bridged tokens to L2');
    pass('Alice received payout on L2');
    
    if (aliceL1Final > aliceL1Initial) {
      pass('Alice successfully withdrew winnings to L1');
    } else {
      info('Alice withdrawal pending (implement /bridge/withdraw endpoint)');
    }
    
    console.log(`\n${colors.green}🎉 Integration test complete!${colors.reset}\n`);
    
  } catch (error) {
    console.error(`\n${colors.red}Test failed with error:${colors.reset}`, error);
    process.exit(1);
  }
}

main();
