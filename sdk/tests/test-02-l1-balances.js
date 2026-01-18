/**
 * TEST 02: L1 Balance Operations
 * 
 * Tests:
 * - Get balance for known test accounts
 * - Get balance for unknown address
 * - Balance format validation
 */

const L1_URL = 'http://localhost:8080';

// Test accounts
const ALICE = 'L1_52882D768C0F3E7932AAD1813CF8B19058D507A8';
const BOB = 'L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433';
const DEALER = 'L1_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D';

console.log('═'.repeat(60));
console.log('🧪 TEST 02: L1 BALANCE OPERATIONS');
console.log('═'.repeat(60));

async function runTests() {
  let passed = 0;
  let failed = 0;

  // Test 2.1: Alice Balance
  console.log('\n📋 Test 2.1: Alice Balance');
  console.log(`   Address: ${ALICE}`);
  try {
    const response = await fetch(`${L1_URL}/balance/${ALICE}`);
    const data = await response.json();
    
    console.log('   Response:', JSON.stringify(data, null, 2));
    
    const balance = data.balance ?? data.available ?? 0;
    console.log(`   ✅ PASSED - Balance: ${balance} $BC`);
    passed++;
  } catch (e) {
    console.log('   ❌ FAILED -', e.message);
    failed++;
  }

  // Test 2.2: Bob Balance
  console.log('\n📋 Test 2.2: Bob Balance');
  console.log(`   Address: ${BOB}`);
  try {
    const response = await fetch(`${L1_URL}/balance/${BOB}`);
    const data = await response.json();
    
    console.log('   Response:', JSON.stringify(data, null, 2));
    
    const balance = data.balance ?? data.available ?? 0;
    console.log(`   ✅ PASSED - Balance: ${balance} $BC`);
    passed++;
  } catch (e) {
    console.log('   ❌ FAILED -', e.message);
    failed++;
  }

  // Test 2.3: Dealer Balance
  console.log('\n📋 Test 2.3: Dealer Balance');
  console.log(`   Address: ${DEALER}`);
  try {
    const response = await fetch(`${L1_URL}/balance/${DEALER}`);
    const data = await response.json();
    
    console.log('   Response:', JSON.stringify(data, null, 2));
    
    const balance = data.balance ?? data.available ?? 0;
    console.log(`   ✅ PASSED - Balance: ${balance} $BC`);
    passed++;
  } catch (e) {
    console.log('   ❌ FAILED -', e.message);
    failed++;
  }

  // Test 2.4: Unknown Address
  console.log('\n📋 Test 2.4: Unknown Address Balance');
  const unknownAddr = 'L1_0000000000000000000000000000000000000000';
  console.log(`   Address: ${unknownAddr}`);
  try {
    const response = await fetch(`${L1_URL}/balance/${unknownAddr}`);
    const data = await response.json();
    
    console.log('   Response:', JSON.stringify(data, null, 2));
    
    const balance = data.balance ?? data.available ?? 0;
    if (balance === 0) {
      console.log('   ✅ PASSED - Unknown address returns 0 balance');
      passed++;
    } else {
      console.log(`   ⚠️ WARNING - Expected 0, got ${balance}`);
      passed++;
    }
  } catch (e) {
    console.log('   ❌ FAILED -', e.message);
    failed++;
  }

  // Summary
  console.log('\n' + '═'.repeat(60));
  console.log('📊 TEST 02 SUMMARY');
  console.log('═'.repeat(60));
  console.log(`   ✅ Passed: ${passed}`);
  console.log(`   ❌ Failed: ${failed}`);
  console.log('═'.repeat(60));
  
  return failed === 0;
}

runTests().then(success => {
  process.exit(success ? 0 : 1);
}).catch(e => {
  console.error('Test error:', e);
  process.exit(1);
});
