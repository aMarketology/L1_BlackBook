/**
 * Run All Tests Sequentially
 * 
 * Runs each test file one at a time for clear output
 */

const tests = [
  'test-01-l1-health.js',
  'test-02-l1-balances.js',
  'test-03-l2-health.js',
  'test-04-l2-balances.js',
  'test-05-l1-transfer.js',
  'test-06-bridge-initiate.js',
  'test-07-l2-markets.js',
  'test-08-credit-line.js',
];

console.log('\n');
console.log('╔══════════════════════════════════════════════════════════╗');
console.log('║        BLACKBOOK L1 ↔ L2 INTEGRATION TEST SUITE          ║');
console.log('╚══════════════════════════════════════════════════════════╝');
console.log('\n');
console.log('Run tests individually:');
tests.forEach((test, i) => {
  console.log(`   ${i+1}. node ${test}`);
});
console.log('\n');
console.log('Or run individually to see detailed output:');
console.log('   cd sdk/tests');
console.log('   node test-01-l1-health.js');
console.log('   node test-02-l1-balances.js');
console.log('   ... etc');
console.log('\n');
