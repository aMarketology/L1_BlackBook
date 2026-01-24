/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * BLACKBOOK L1 - Production Test Runner
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Runs all production-readiness tests in sequence.
 * 
 * Usage:
 *   node test-runner.js              # Run all tests
 *   node test-runner.js --quick      # Run quick smoke tests only
 *   node test-runner.js --category wallet  # Run only wallet tests
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ═══════════════════════════════════════════════════════════════════════════════
// TEST CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

export const CONFIG = {
  L1_URL: process.env.L1_URL || 'http://localhost:8080',
  API_BASE: process.env.L1_URL || 'http://localhost:8080',
  TIMEOUT: 30000,
  VERBOSE: process.env.VERBOSE === 'true',
};

// Test accounts (from TEST_ACCOUNTS.txt)
export const TEST_ACCOUNTS = {
  ALICE: {
    name: 'Alice',
    address: 'L1_52882D768C0F3E7932AAD1813CF8B19058D507A8',
    seed: '18f2c2e3bcb7a4b5329cfed4bd79bf17df4d47aa1888a6b3d1a1450fb53a8a24',
    publicKey: 'c0e349153cbc75e9529b5f1963205cab783463c6835c826a7587e0e0903c6705',
  },
  BOB: {
    name: 'Bob',
    address: 'L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433',
    seed: 'e4ac49e5a04ef7dfc6e1a838fdf14597f2d514d0029a82cb45c916293487c25b',
    publicKey: '582420216093fcff65b0eec2ca2c8227dfc2b6b7428110f36c3fc1349c4b2f5a',
  },
  MAC: {
    name: 'Mac',
    address: 'L1_94B3C863E068096596CE80F04C2233B72AE11790',
    publicKey: 'ec6941c71740e192bbf5933d5f9cc18ea161329ce864da900d8de73d45c28752',
    vault: {
      salt: '579a5c28a02f8c3ecc2801545a216cec',
      encrypted_blob: 'U2FsdGVkX19443Y8LJ1PaUV6/aG4Ctod88tWo7AVDftZlcgWurkSGAhVEAScVQ91+Ew9iP0d588HfIUYlXQPGEmIMDhjj3M6cDPbDtnTZFh848l0Z71CjV0CpB41Avad',
    },
    password: 'MacSecurePassword2026!',
  },
  DEALER: {
    name: 'Dealer',
    address: 'L1_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D',
    seed: 'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d',
    publicKey: '65328794ed4a81cc2a92b93738c22a545f066cc6c0b6a72aa878cfa289f0ba32',
  },
};

// ═══════════════════════════════════════════════════════════════════════════════
// TEST RESULT TRACKING
// ═══════════════════════════════════════════════════════════════════════════════

export class TestResults {
  constructor() {
    this.passed = 0;
    this.failed = 0;
    this.skipped = 0;
    this.errors = [];
    this.startTime = Date.now();
  }

  pass(name) {
    this.passed++;
    console.log(`   ✅ ${name}`);
  }

  fail(name, error) {
    this.failed++;
    this.errors.push({ name, error: error?.message || error });
    console.log(`   ❌ ${name}: ${error?.message || error}`);
  }

  skip(name, reason) {
    this.skipped++;
    console.log(`   ⏭️  ${name}: ${reason}`);
  }

  summary() {
    const duration = ((Date.now() - this.startTime) / 1000).toFixed(2);
    console.log('\n' + '═'.repeat(60));
    console.log('TEST SUMMARY');
    console.log('═'.repeat(60));
    console.log(`   ✅ Passed:  ${this.passed}`);
    console.log(`   ❌ Failed:  ${this.failed}`);
    console.log(`   ⏭️  Skipped: ${this.skipped}`);
    console.log(`   ⏱️  Duration: ${duration}s`);
    
    if (this.errors.length > 0) {
      console.log('\n   FAILURES:');
      this.errors.forEach((e, i) => {
        console.log(`   ${i + 1}. ${e.name}: ${e.error}`);
      });
    }
    
    console.log('═'.repeat(60));
    return this.failed === 0;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// HTTP HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

export async function httpGet(endpoint) {
  const res = await fetch(`${CONFIG.L1_URL}${endpoint}`);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`GET ${endpoint} failed: ${res.status} - ${text}`);
  }
  return res.json();
}

export async function httpPost(endpoint, body) {
  const res = await fetch(`${CONFIG.L1_URL}${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  
  const text = await res.text();
  
  // Try to parse as JSON, otherwise wrap in error object
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    // Server returned non-JSON (likely a text error)
    data = { success: false, error: text };
  }
  
  if (!res.ok && !data.error) {
    throw new Error(`POST ${endpoint} failed: ${res.status}`);
  }
  return data;
}

// ═══════════════════════════════════════════════════════════════════════════════
// TEST CATEGORIES
// ═══════════════════════════════════════════════════════════════════════════════

const TEST_FILES = [
  // ═══════════════════════════════════════════════════════════════════════════
  // CORE WALLET OPERATIONS
  // ═══════════════════════════════════════════════════════════════════════════
  { file: '01-wallet-generate.test.js', category: 'wallet', critical: true },
  { file: '02-wallet-login.test.js', category: 'wallet', critical: true },
  
  // ═══════════════════════════════════════════════════════════════════════════
  // TOKEN OPERATIONS
  // ═══════════════════════════════════════════════════════════════════════════
  { file: '03-send-tokens.test.js', category: 'transfer', critical: true },
  { file: '04-receive-tokens.test.js', category: 'transfer', critical: true },
  
  // ═══════════════════════════════════════════════════════════════════════════
  // BALANCE & LEDGER
  // ═══════════════════════════════════════════════════════════════════════════
  { file: '05-balance-accuracy.test.js', category: 'balance', critical: true },
  { file: '06-transaction-history.test.js', category: 'ledger', critical: true },
  
  // ═══════════════════════════════════════════════════════════════════════════
  // L2 BRIDGE
  // ═══════════════════════════════════════════════════════════════════════════
  { file: '07-l2-session-lock.test.js', category: 'bridge', critical: true },
  { file: '08-l2-settlement.test.js', category: 'bridge', critical: true },
  
  // ═══════════════════════════════════════════════════════════════════════════
  // SECURITY - CORE
  // ═══════════════════════════════════════════════════════════════════════════
  { file: '09-signature-validation.test.js', category: 'security', critical: true },
  { file: '10-double-spend-prevention.test.js', category: 'security', critical: true },
  { file: '11-invalid-inputs.test.js', category: 'security', critical: true },
  
  // ═══════════════════════════════════════════════════════════════════════════
  // SECURITY - DAO ATTACK PREVENTION (like ETH DAO hack)
  // ═══════════════════════════════════════════════════════════════════════════
  { file: '12-reentrancy-prevention.test.js', category: 'security', critical: true },
  { file: '13-balance-invariants.test.js', category: 'security', critical: true },
  
  // ═══════════════════════════════════════════════════════════════════════════
  // SYSTEM HEALTH
  // ═══════════════════════════════════════════════════════════════════════════
  { file: '14-server-health.test.js', category: 'system', critical: true },
  { file: '15-persistence.test.js', category: 'system', critical: true },
  
  // ═══════════════════════════════════════════════════════════════════════════
  // SECURITY - OVERFLOW & NUMERIC ATTACKS
  // ═══════════════════════════════════════════════════════════════════════════
  { file: '16-overflow-underflow.test.js', category: 'security', critical: true },
  
  // ═══════════════════════════════════════════════════════════════════════════
  // SECURITY - FUZZ TESTING
  // ═══════════════════════════════════════════════════════════════════════════
  { file: '17-fuzz-testing.test.js', category: 'fuzz', critical: false },
  
  // ═══════════════════════════════════════════════════════════════════════════
  // PERFORMANCE & DOS PREVENTION
  // ═══════════════════════════════════════════════════════════════════════════
  { file: '18-rate-limiting-dos.test.js', category: 'performance', critical: false },
  
  // ═══════════════════════════════════════════════════════════════════════════
  // CONSENSUS & BLOCK VALIDATION
  // ═══════════════════════════════════════════════════════════════════════════
  { file: '19-consensus-validation.test.js', category: 'consensus', critical: true },
  
  // ═══════════════════════════════════════════════════════════════════════════
  // WALLET & KEY SECURITY
  // ═══════════════════════════════════════════════════════════════════════════
  { file: '20-wallet-key-security.test.js', category: 'security', critical: true },
];

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN RUNNER
// ═══════════════════════════════════════════════════════════════════════════════

async function main() {
  const args = process.argv.slice(2);
  const quick = args.includes('--quick');
  const categoryFilter = args.find(a => a.startsWith('--category='))?.split('=')[1];

  console.log('╔' + '═'.repeat(58) + '╗');
  console.log('║' + ' '.repeat(15) + 'BLACKBOOK L1 TEST SUITE' + ' '.repeat(20) + '║');
  console.log('╚' + '═'.repeat(58) + '╝');
  console.log(`\n   Server: ${CONFIG.L1_URL}`);
  console.log(`   Mode: ${quick ? 'Quick (critical only)' : 'Full'}`);
  if (categoryFilter) console.log(`   Category: ${categoryFilter}`);
  console.log('');

  const allResults = new TestResults();

  for (const test of TEST_FILES) {
    // Filter by category
    if (categoryFilter && test.category !== categoryFilter) continue;
    // Quick mode: only critical tests
    if (quick && !test.critical) continue;

    const testPath = path.join(__dirname, test.file);
    if (!fs.existsSync(testPath)) {
      console.log(`\n⚠️  ${test.file} - NOT FOUND`);
      continue;
    }

    console.log(`\n${'─'.repeat(60)}`);
    console.log(`📋 ${test.file}`);
    console.log(`${'─'.repeat(60)}`);

    try {
      const testModule = await import(`./${test.file}`);
      if (typeof testModule.run === 'function') {
        const results = await testModule.run();
        allResults.passed += results.passed;
        allResults.failed += results.failed;
        allResults.skipped += results.skipped;
        allResults.errors.push(...results.errors);
      }
    } catch (err) {
      allResults.fail(test.file, err);
    }
  }

  const success = allResults.summary();
  process.exit(success ? 0 : 1);
}

// Run if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(err => {
    console.error('Test runner crashed:', err);
    process.exit(1);
  });
}
