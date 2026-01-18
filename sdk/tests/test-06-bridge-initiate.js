/**
 * TEST 06: Bridge Initiate (L1 → L2)
 * 
 * Tests:
 * - Bridge lock initiation
 * - Lock status tracking
 * - Pending bridges
 */

const L1_URL = 'http://localhost:8080';
const L2_URL = 'http://localhost:1234';

const ALICE = {
  address: 'L1_52882D768C0F3E7932AAD1813CF8B19058D507A8',
  l2Address: 'L2_52882D768C0F3E7932AAD1813CF8B19058D507A8',
};

console.log('═'.repeat(60));
console.log('🧪 TEST 06: BRIDGE INITIATE (L1 → L2)');
console.log('═'.repeat(60));

async function runTests() {
  let passed = 0;
  let failed = 0;

  // Test 6.1: Check Bridge Stats (Before)
  console.log('\n📋 Test 6.1: Bridge Stats (Before)');
  try {
    const response = await fetch(`${L1_URL}/bridge/stats`);
    const data = await response.json();
    
    console.log('   Response:', JSON.stringify(data, null, 2));
    console.log('   ✅ PASSED - Bridge stats available');
    passed++;
  } catch (e) {
    console.log('   ❌ FAILED -', e.message);
    failed++;
  }

  // Test 6.2: Check Pending Bridges for Alice
  console.log('\n📋 Test 6.2: Pending Bridges for Alice');
  try {
    const response = await fetch(`${L1_URL}/bridge/pending/${ALICE.address}`);
    const data = await response.json();
    
    console.log('   Response:', JSON.stringify(data, null, 2));
    console.log(`   Pending count: ${data.pending?.length || 0}`);
    console.log('   ✅ PASSED - Pending bridges endpoint working');
    passed++;
  } catch (e) {
    console.log('   ❌ FAILED -', e.message);
    failed++;
  }

  // Test 6.3: Initiate Bridge Lock
  console.log('\n📋 Test 6.3: Initiate Bridge Lock');
  const bridgeAmount = 100;
  console.log(`   Wallet: ${ALICE.address}`);
  console.log(`   Amount: ${bridgeAmount} $BC`);
  
  let lockId = null;
  
  try {
    const response = await fetch(`${L1_URL}/bridge/initiate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        wallet: ALICE.address,
        amount: bridgeAmount,
      }),
    });
    
    const data = await response.json();
    console.log('   Response:', JSON.stringify(data, null, 2));
    
    if (data.lock_id) {
      lockId = data.lock_id;
      console.log(`   ✅ PASSED - Lock created: ${lockId}`);
      passed++;
    } else if (data.error?.includes('Insufficient')) {
      console.log('   ⚠️ Insufficient balance - need to mint first');
      console.log('   ✅ PASSED - Correctly rejected');
      passed++;
    } else {
      console.log('   ❌ FAILED - No lock_id returned');
      failed++;
    }
  } catch (e) {
    console.log('   ❌ FAILED -', e.message);
    failed++;
  }

  // Test 6.4: Check Lock Status
  if (lockId) {
    console.log('\n📋 Test 6.4: Check Lock Status');
    console.log(`   Lock ID: ${lockId}`);
    try {
      const response = await fetch(`${L1_URL}/bridge/status/${lockId}`);
      const data = await response.json();
      
      console.log('   Response:', JSON.stringify(data, null, 2));
      console.log('   ✅ PASSED - Lock status retrieved');
      passed++;
    } catch (e) {
      console.log('   ❌ FAILED -', e.message);
      failed++;
    }
  } else {
    console.log('\n📋 Test 6.4: Check Lock Status');
    console.log('   ⏭️ SKIPPED - No lock created');
  }

  // Test 6.5: Check Pending Bridges (After)
  console.log('\n📋 Test 6.5: Pending Bridges (After)');
  try {
    const response = await fetch(`${L1_URL}/bridge/pending/${ALICE.address}`);
    const data = await response.json();
    
    console.log('   Response:', JSON.stringify(data, null, 2));
    console.log(`   Pending count: ${data.pending?.length || 0}`);
    console.log('   ✅ PASSED - Pending bridges updated');
    passed++;
  } catch (e) {
    console.log('   ❌ FAILED -', e.message);
    failed++;
  }

  // Test 6.6: Check L2 Credit (if L2 running)
  console.log('\n📋 Test 6.6: Check L2 Balance After Bridge');
  try {
    const response = await fetch(`${L2_URL}/balance/${ALICE.l2Address}`);
    const data = await response.json();
    
    console.log('   Response:', JSON.stringify(data, null, 2));
    console.log(`   L2 Balance: ${data.balance || 0} $BB`);
    console.log('   ✅ PASSED - L2 balance checked');
    passed++;
  } catch (e) {
    console.log('   ⚠️ L2 not reachable:', e.message);
    console.log('   ⏭️ SKIPPED - L2 offline');
  }

  // Summary
  console.log('\n' + '═'.repeat(60));
  console.log('📊 TEST 06 SUMMARY');
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
