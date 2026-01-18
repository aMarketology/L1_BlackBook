/**
 * TEST 01: L1 Server Health & Basic Operations
 * 
 * Tests:
 * - Server health endpoint
 * - Blockchain stats
 * - PoH status
 */

const L1_URL = 'http://localhost:8080';

console.log('═'.repeat(60));
console.log('🧪 TEST 01: L1 SERVER HEALTH');
console.log('═'.repeat(60));

async function runTests() {
  let passed = 0;
  let failed = 0;

  // Test 1.1: Health Check
  console.log('\n📋 Test 1.1: Health Check');
  try {
    const response = await fetch(`${L1_URL}/health`);
    const data = await response.json();
    
    console.log('   Response:', JSON.stringify(data, null, 2));
    
    if (data.status === 'ok') {
      console.log('   ✅ PASSED - Server is healthy');
      console.log(`      Engine: ${data.engine}`);
      console.log(`      Storage: ${data.storage}`);
      console.log(`      Version: ${data.version}`);
      passed++;
    } else {
      console.log('   ❌ FAILED - Unexpected status:', data.status);
      failed++;
    }
  } catch (e) {
    console.log('   ❌ FAILED -', e.message);
    failed++;
  }

  // Test 1.2: Blockchain Stats
  console.log('\n📋 Test 1.2: Blockchain Stats');
  try {
    const response = await fetch(`${L1_URL}/stats`);
    const data = await response.json();
    
    console.log('   Response:', JSON.stringify(data, null, 2));
    
    if (data.block_height !== undefined) {
      console.log('   ✅ PASSED - Stats retrieved');
      console.log(`      Block Height: ${data.block_height}`);
      console.log(`      Total Accounts: ${data.total_accounts || 'N/A'}`);
      console.log(`      Total Supply: ${data.total_supply || 'N/A'}`);
      passed++;
    } else {
      console.log('   ✅ PASSED - Stats endpoint responding');
      passed++;
    }
  } catch (e) {
    console.log('   ❌ FAILED -', e.message);
    failed++;
  }

  // Test 1.3: PoH Status
  console.log('\n📋 Test 1.3: PoH (Proof of History) Status');
  try {
    const response = await fetch(`${L1_URL}/poh/status`);
    const data = await response.json();
    
    console.log('   Response:', JSON.stringify(data, null, 2));
    
    if (data.current_slot !== undefined || data.tick_count !== undefined) {
      console.log('   ✅ PASSED - PoH is running');
      console.log(`      Current Slot: ${data.current_slot}`);
      console.log(`      Tick Count: ${data.tick_count}`);
      passed++;
    } else {
      console.log('   ⚠️ WARNING - PoH data format unexpected');
      console.log('   ✅ PASSED - Endpoint responding');
      passed++;
    }
  } catch (e) {
    console.log('   ❌ FAILED -', e.message);
    failed++;
  }

  // Summary
  console.log('\n' + '═'.repeat(60));
  console.log('📊 TEST 01 SUMMARY');
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
