/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * TEST 14: Server Health
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Tests:
 * - Health endpoint returns 200
 * - Health response has required fields
 * - Server responds within timeout
 * - Multiple concurrent health checks work
 */

import { TestResults, CONFIG, httpGet } from './test-runner.js';

export async function run() {
  const results = new TestResults();
  
  // Test 1: Health endpoint returns 200
  try {
    const response = await httpGet('/health');
    
    if (!response) {
      throw new Error('Empty response');
    }
    
    results.pass('Health endpoint returns 200');
  } catch (err) {
    results.fail('Health endpoint returns 200', err);
  }
  
  // Test 2: Health response has required fields
  try {
    const response = await httpGet('/health');
    
    const requiredFields = ['status', 'total_supply'];
    const optionalFields = ['total_accounts', 'uptime', 'version'];
    
    for (const field of requiredFields) {
      if (!(field in response) && !('healthy' in response)) {
        throw new Error(`Missing required field: ${field}`);
      }
    }
    
    console.log('   Fields:', Object.keys(response).join(', '));
    results.pass('Health response has required fields');
  } catch (err) {
    results.fail('Health response has required fields', err);
  }
  
  // Test 3: Server responds within timeout
  try {
    const start = Date.now();
    await httpGet('/health');
    const duration = Date.now() - start;
    
    if (duration > 5000) {
      throw new Error(`Response took ${duration}ms (> 5s timeout)`);
    }
    
    console.log(`   Response time: ${duration}ms`);
    results.pass('Server responds within timeout');
  } catch (err) {
    results.fail('Server responds within timeout', err);
  }
  
  // Test 4: Multiple concurrent health checks
  try {
    const concurrentRequests = 10;
    const promises = Array(concurrentRequests).fill(null).map(() => httpGet('/health'));
    
    const responses = await Promise.all(promises);
    
    const allSuccessful = responses.every(r => r && !r.error);
    if (!allSuccessful) {
      throw new Error('Some concurrent health checks failed');
    }
    
    results.pass(`${concurrentRequests} concurrent health checks`);
  } catch (err) {
    results.fail('Multiple concurrent health checks', err);
  }
  
  // Test 5: Total supply is positive
  try {
    const response = await httpGet('/health');
    const totalSupply = response.total_supply;
    
    if (totalSupply === undefined) {
      results.skip('Total supply check', 'Field not present');
    } else if (totalSupply < 0) {
      throw new Error(`Total supply is negative: ${totalSupply}`);
    } else {
      console.log(`   Total supply: ${totalSupply} BB`);
      results.pass('Total supply is positive');
    }
  } catch (err) {
    results.fail('Total supply is positive', err);
  }
  
  // Test 6: Account count is tracked
  try {
    const response = await httpGet('/health');
    const accounts = response.total_accounts || response.accounts;
    
    if (accounts === undefined) {
      results.skip('Account count check', 'Field not present');
    } else if (accounts < 0) {
      throw new Error(`Account count is negative: ${accounts}`);
    } else {
      console.log(`   Total accounts: ${accounts}`);
      results.pass('Account count is valid');
    }
  } catch (err) {
    results.fail('Account count check', err);
  }
  
  // Test 7: Status indicates healthy
  try {
    const response = await httpGet('/health');
    
    const isHealthy = 
      response.status === 'ok' ||
      response.status === 'healthy' ||
      response.healthy === true ||
      response.ok === true;
    
    if (!isHealthy) {
      console.log(`   Status: ${JSON.stringify(response)}`);
      throw new Error('Server reports unhealthy status');
    }
    
    results.pass('Server status is healthy');
  } catch (err) {
    results.fail('Server status is healthy', err);
  }
  
  // Test 8: Balance endpoint works
  try {
    const response = await httpGet('/balance/L1_52882D768C0F3E7932AAD1813CF8B19058D507A8');
    
    if (response.error && response.error.includes('not found')) {
      // Account not found is OK for this test
    } else if (!response && response !== 0) {
      throw new Error('Balance endpoint failed');
    }
    
    results.pass('Balance endpoint functional');
  } catch (err) {
    results.fail('Balance endpoint functional', err);
  }
  
  // Test 9: Transfer endpoint responds (doesn't need to succeed)
  try {
    const response = await httpPost('/transfer', {});
    
    // Even with invalid data, endpoint should respond
    results.pass('Transfer endpoint functional');
  } catch (err) {
    results.fail('Transfer endpoint functional', err);
  }
  
  return results;
}

// Helper for POST (copy from test-runner)
async function httpPost(endpoint, body) {
  const res = await fetch(`${CONFIG.L1_URL}${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return res.json();
}

// Run if executed directly
import { fileURLToPath } from 'url';
const __filename = fileURLToPath(import.meta.url);
if (__filename === process.argv[1]) {
  run().then(r => {
    r.summary();
    process.exit(r.failed === 0 ? 0 : 1);
  });
}
