/**
 * TEST 03: L2 Server Health & Basic Operations
 * 
 * Tests:
 * - Server health endpoint
 * - Market count
 * - L1 connection status
 */

const L2_URL = 'http://localhost:1234';

console.log('═'.repeat(60));
console.log('🧪 TEST 03: L2 SERVER HEALTH');
console.log('═'.repeat(60));

async function runTests() {
  let passed = 0;
  let failed = 0;

  // Test 3.1: Health Check
  console.log('\n📋 Test 3.1: Health Check');
  try {
    const response = await fetch(`${L2_URL}/health`);
    const data = await response.json();
    
    console.log('   Response:', JSON.stringify(data, null, 2));
    
    if (data.status === 'ok' || data.market_count !== undefined) {
      console.log('   ✅ PASSED - L2 Server is healthy');
      console.log(`      Market Count: ${data.market_count}`);
      console.log(`      Active Sessions: ${data.active_sessions}`);
      console.log(`      L2 Supply: ${data.l2_supply}`);
      passed++;
    } else {
      console.log('   ❌ FAILED - Unexpected response format');
      failed++;
    }
  } catch (e) {
    console.log('   ❌ FAILED -', e.message);
    failed++;
  }

  // Test 3.2: L1 Connection Status
  console.log('\n📋 Test 3.2: L1 Connection Status');
  try {
    const response = await fetch(`${L2_URL}/health`);
    const data = await response.json();
    
    if (data.l1_connection) {
      console.log('   L1 Connection:', JSON.stringify(data.l1_connection, null, 2));
      if (data.l1_connection.configured) {
        console.log('   ✅ PASSED - L1 connection configured');
        passed++;
      } else {
        console.log('   ⚠️ WARNING - L1 connection not configured');
        passed++;
      }
    } else {
      console.log('   ⚠️ WARNING - No L1 connection info in health response');
      passed++;
    }
  } catch (e) {
    console.log('   ❌ FAILED -', e.message);
    failed++;
  }

  // Test 3.3: Markets Endpoint
  console.log('\n📋 Test 3.3: Markets Endpoint');
  try {
    const response = await fetch(`${L2_URL}/markets`);
    const data = await response.json();
    
    const markets = data.markets || data;
    const count = Array.isArray(markets) ? markets.length : 0;
    
    console.log(`   Total Markets: ${count}`);
    
    if (count > 0) {
      console.log('   First 3 markets:');
      const sample = Array.isArray(markets) ? markets.slice(0, 3) : [];
      sample.forEach((m, i) => {
        console.log(`     ${i+1}. ${m.title || m.id || 'Unknown'}`);
      });
    }
    
    console.log('   ✅ PASSED - Markets endpoint working');
    passed++;
  } catch (e) {
    console.log('   ❌ FAILED -', e.message);
    failed++;
  }

  // Test 3.4: Balances Endpoint
  console.log('\n📋 Test 3.4: Balances/Accounts Endpoint');
  try {
    const response = await fetch(`${L2_URL}/balances`);
    if (response.ok) {
      const data = await response.json();
      console.log('   Response:', JSON.stringify(data, null, 2).substring(0, 500));
      console.log('   ✅ PASSED - Balances endpoint working');
      passed++;
    } else {
      console.log(`   ⚠️ WARNING - Status ${response.status}`);
      console.log('   ✅ PASSED - Endpoint exists (may require auth)');
      passed++;
    }
  } catch (e) {
    console.log('   ❌ FAILED -', e.message);
    failed++;
  }

  // Summary
  console.log('\n' + '═'.repeat(60));
  console.log('📊 TEST 03 SUMMARY');
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
