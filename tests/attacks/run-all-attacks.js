/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * 🔴 RUN ALL ATTACK SIMULATIONS
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * This script runs the complete attack suite against BlackBook L1 blockchain.
 * All attacks should FAIL if the blockchain is properly secured.
 */

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const ATTACKS = [
  {
    name: 'DAO Reentrancy Attack',
    file: 'dao-reentrancy-attack.js',
    description: 'Simulates the $60M Ethereum DAO hack',
    severity: 'CRITICAL',
  },
  {
    name: 'Replay Attack',
    file: 'replay-attack.js',
    description: 'Attempts to reuse signed transactions',
    severity: 'CRITICAL',
  },
];

console.log('\n🔴 ═══════════════════════════════════════════════════════════');
console.log('   BLACKBOOK L1 SECURITY ATTACK SUITE');
console.log('   Running full attack simulation...');
console.log('═════════════════════════════════════════════════════════════\n');

async function runAttack(attack) {
  return new Promise((resolve) => {
    console.log(`\n${'═'.repeat(65)}`);
    console.log(`🚨 ${attack.name.toUpperCase()}`);
    console.log(`   ${attack.description}`);
    console.log(`   Severity: ${attack.severity}`);
    console.log(`${'═'.repeat(65)}\n`);

    const child = spawn('node', [join(__dirname, attack.file)], {
      stdio: 'inherit',
    });

    child.on('close', (code) => {
      resolve({
        name: attack.name,
        passed: code === 0,
        exitCode: code,
      });
    });

    child.on('error', (err) => {
      console.error(`\n💥 Failed to run ${attack.name}:`, err);
      resolve({
        name: attack.name,
        passed: false,
        error: err.message,
      });
    });
  });
}

async function runAllAttacks() {
  const startTime = Date.now();
  const results = [];

  for (const attack of ATTACKS) {
    const result = await runAttack(attack);
    results.push(result);
  }

  const duration = ((Date.now() - startTime) / 1000).toFixed(2);

  // Summary
  console.log('\n\n');
  console.log('═'.repeat(65));
  console.log('📊 FINAL SECURITY ASSESSMENT');
  console.log('═'.repeat(65));
  console.log('');

  const passed = results.filter(r => r.passed).length;
  const failed = results.filter(r => !r.passed).length;

  results.forEach((result, i) => {
    const status = result.passed ? '✅ SECURE' : '❌ VULNERABLE';
    console.log(`${i + 1}. ${result.name}: ${status}`);
  });

  console.log('');
  console.log(`Total attacks simulated: ${results.length}`);
  console.log(`Attacks prevented:       ${passed}`);
  console.log(`Vulnerabilities found:   ${failed}`);
  console.log(`Duration:                ${duration}s`);
  console.log('');

  if (failed > 0) {
    console.log('❌ SECURITY FAILURES DETECTED ❌');
    console.log('');
    console.log('🚨 CRITICAL: Blockchain has security vulnerabilities!');
    console.log('⚠️  DO NOT DEPLOY TO PRODUCTION');
    console.log('');
    console.log('Failed attacks:');
    results
      .filter(r => !r.passed)
      .forEach(r => console.log(`   • ${r.name}`));
    console.log('');
    process.exit(1);
  } else {
    console.log('✅ ALL ATTACKS PREVENTED ✅');
    console.log('');
    console.log('🛡️  BlackBook L1 blockchain is secure!');
    console.log('   • DAO reentrancy attacks prevented');
    console.log('   • Replay attacks prevented');
    console.log('   • Atomic state consistency maintained');
    console.log('');
    console.log('✨ Safe for production deployment');
    console.log('');
    process.exit(0);
  }
}

runAllAttacks().catch(err => {
  console.error('\n💥 Test suite error:', err);
  process.exit(1);
});
