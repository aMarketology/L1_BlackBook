/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * RUN ALL gRPC/PROTO LOCK TESTS
 * ═══════════════════════════════════════════════════════════════════════════════
 */

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const TESTS = [
  { file: '01-basic-lock-unlock.test.js', name: 'Basic Lock/Unlock' },
  { file: '02-concurrent-locks.test.js', name: 'Concurrent Lock Attempts' },
  { file: '11-end-to-end-game-session.test.js', name: 'End-to-End Game Session' },
];

console.log('\n╔═══════════════════════════════════════════════════════════════╗');
console.log('║  BLACKBOOK L1-L2 gRPC/PROTO LOCK TEST SUITE                  ║');
console.log('╚═══════════════════════════════════════════════════════════════╝\n');

async function runTest(test) {
  return new Promise((resolve) => {
    console.log(`\n${'─'.repeat(65)}`);
    console.log(`🧪 ${test.name}`);
    console.log(`${'─'.repeat(65)}`);

    const child = spawn('node', [join(__dirname, test.file)], {
      stdio: 'inherit',
    });

    child.on('close', (code) => {
      resolve({ name: test.name, passed: code === 0 });
    });

    child.on('error', (err) => {
      console.error(`\n💥 Failed to run ${test.name}:`, err);
      resolve({ name: test.name, passed: false });
    });
  });
}

async function runAllTests() {
  const startTime = Date.now();
  const results = [];

  for (const test of TESTS) {
    const result = await runTest(test);
    results.push(result);
  }

  const duration = ((Date.now() - startTime) / 1000).toFixed(2);

  console.log('\n\n╔═══════════════════════════════════════════════════════════════╗');
  console.log('║  FINAL TEST SUMMARY                                           ║');
  console.log('╚═══════════════════════════════════════════════════════════════╝\n');

  const passed = results.filter(r => r.passed).length;
  const failed = results.filter(r => !r.passed).length;

  results.forEach((result, i) => {
    const status = result.passed ? '✅ PASS' : '❌ FAIL';
    console.log(`${(i + 1).toString().padStart(2)}. ${result.name.padEnd(40)} ${status}`);
  });

  console.log('');
  console.log(`Total tests:  ${results.length}`);
  console.log(`Passed:       ${passed}`);
  console.log(`Failed:       ${failed}`);
  console.log(`Duration:     ${duration}s`);
  console.log('');

  if (failed > 0) {
    console.log('❌ SOME TESTS FAILED');
    process.exit(1);
  } else {
    console.log('✅ ALL TESTS PASSED');
    console.log('🛡️  L1-L2 token locking is secure and functional');
    process.exit(0);
  }
}

runAllTests().catch(err => {
  console.error('\n💥 Test suite error:', err);
  process.exit(1);
});
