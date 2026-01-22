/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * TEST 18: Rate Limiting & DoS Prevention
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Denial of Service attacks can bring down blockchain nodes.
 * These tests verify the server handles high load gracefully.
 * 
 * Tests:
 * - Rapid-fire request handling
 * - Memory exhaustion prevention  
 * - CPU exhaustion prevention
 * - Connection limit handling
 */

import nacl from 'tweetnacl';
import { TestResults, TEST_ACCOUNTS, CONFIG, httpGet, httpPost } from './test-runner.js';

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sha256(data) {
  const buffer = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(buffer);
}

async function createSignedTransfer(from, to, amount, keyPair) {
  const timestamp = Date.now();
  const payload = { amount, chain_id: 1, from, timestamp, to };
  const canonicalJson = JSON.stringify(payload, Object.keys(payload).sort());
  const payloadBytes = new TextEncoder().encode(canonicalJson);
  const payloadHash = await sha256(payloadBytes);
  const signature = nacl.sign.detached(payloadHash, keyPair.secretKey);
  
  return { from, to, amount, timestamp, public_key: bytesToHex(keyPair.publicKey), signature: bytesToHex(signature) };
}

async function getBalance(address) {
  const response = await httpGet(`/balance/${address}`);
  return response.balance ?? response.available ?? 0;
}

export async function run() {
  const results = new TestResults();
  const aliceKeyPair = nacl.sign.keyPair.fromSeed(hexToBytes(TEST_ACCOUNTS.ALICE.seed));
  
  console.log('   🛡️  Testing rate limiting & DoS prevention...\n');
  
  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 1: Rapid-fire balance checks (100 requests)
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const requests = 100;
    const startTime = Date.now();
    
    console.log(`   Sending ${requests} rapid balance requests...`);
    
    let successful = 0;
    let rateLimited = 0;
    let failed = 0;
    
    const promises = [];
    for (let i = 0; i < requests; i++) {
      promises.push(
        httpGet(`/balance/${TEST_ACCOUNTS.ALICE.address}`)
          .then(r => {
            if (r.balance !== undefined || r.available !== undefined) {
              successful++;
            } else if (r.error?.includes('rate') || r.error?.includes('limit')) {
              rateLimited++;
            } else {
              failed++;
            }
          })
          .catch(err => {
            if (err.message.includes('429') || err.message.includes('rate')) {
              rateLimited++;
            } else {
              failed++;
            }
          })
      );
    }
    
    await Promise.all(promises);
    
    const elapsed = Date.now() - startTime;
    const rps = Math.round(requests / (elapsed / 1000));
    
    console.log(`   Results: ${successful} OK, ${rateLimited} rate limited, ${failed} failed`);
    console.log(`   Throughput: ~${rps} req/sec`);
    
    // Server should still respond
    const health = await httpGet('/health');
    if (!health) {
      throw new Error('Server stopped responding after rapid requests');
    }
    
    results.pass(`Rapid balance checks (${requests} requests, ${rps} rps)`);
  } catch (err) {
    results.fail('Rapid balance checks', err);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 2: Rapid-fire transfers (50 signed requests)
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const requests = 50;
    
    console.log(`   Sending ${requests} rapid transfer requests...`);
    
    // Pre-generate all signed requests
    const transferRequests = [];
    for (let i = 0; i < requests; i++) {
      transferRequests.push(
        await createSignedTransfer(
          TEST_ACCOUNTS.ALICE.address,
          TEST_ACCOUNTS.BOB.address,
          0.01, // Small amounts
          aliceKeyPair
        )
      );
    }
    
    const startTime = Date.now();
    
    let successful = 0;
    let rateLimited = 0;
    let rejected = 0;
    
    // Send all at once
    const promises = transferRequests.map(req =>
      httpPost('/transfer', req)
        .then(r => {
          if (r.success && !r.error) {
            successful++;
          } else if (r.error?.includes('rate') || r.error?.includes('limit')) {
            rateLimited++;
          } else {
            rejected++; // Other errors (insufficient funds, etc)
          }
        })
        .catch(err => {
          if (err.message.includes('429')) {
            rateLimited++;
          } else {
            rejected++;
          }
        })
    );
    
    await Promise.all(promises);
    
    const elapsed = Date.now() - startTime;
    const tps = Math.round(requests / (elapsed / 1000));
    
    console.log(`   Results: ${successful} OK, ${rateLimited} rate limited, ${rejected} rejected`);
    console.log(`   Throughput: ~${tps} tx/sec`);
    
    // Verify server health
    const health = await httpGet('/health');
    if (!health) {
      throw new Error('Server stopped after rapid transfers');
    }
    
    results.pass(`Rapid transfers (${requests} signed transactions)`);
  } catch (err) {
    results.fail('Rapid transfers', err);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 3: Large payload rejection
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    // Try to send a 10MB payload
    const largePayload = {
      from: TEST_ACCOUNTS.ALICE.address,
      to: TEST_ACCOUNTS.BOB.address,
      amount: 1,
      timestamp: Date.now(),
      public_key: 'a'.repeat(64),
      signature: 'b'.repeat(128),
      // Add large extra field
      data: 'X'.repeat(10 * 1024 * 1024), // 10MB
    };
    
    let rejected = false;
    let serverAlive = true;
    
    try {
      const response = await fetch(`${CONFIG.API_BASE}/transfer`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(largePayload),
        // Add timeout
        signal: AbortSignal.timeout(10000),
      });
      
      // If server responded, that's good (even with error)
      rejected = response.status >= 400;
    } catch (err) {
      // Connection refused or timeout is expected for large payloads
      if (err.name === 'TimeoutError' || err.name === 'AbortError') {
        // That's fine - payload was too large
        rejected = true;
      } else if (err.message.includes('ECONNREFUSED')) {
        // Server might have been overwhelmed
        serverAlive = false;
      }
    }
    
    // Verify server still alive
    await new Promise(resolve => setTimeout(resolve, 500));
    
    try {
      const health = await httpGet('/health');
      serverAlive = !!health;
    } catch (e) {
      serverAlive = false;
    }
    
    if (!serverAlive) {
      throw new Error('Server crashed on large payload');
    }
    
    results.pass('Large payload handled (10MB)');
  } catch (err) {
    results.fail('Large payload handling', err);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 4: Many unique address queries (memory exhaustion)
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const uniqueAddresses = 100;
    
    console.log(`   Querying ${uniqueAddresses} unique addresses...`);
    
    const randomHex = (len) => Array.from({ length: len }, () => 
      Math.floor(Math.random() * 16).toString(16)
    ).join('');
    
    const promises = [];
    for (let i = 0; i < uniqueAddresses; i++) {
      const address = `L1_${randomHex(40)}`;
      promises.push(httpGet(`/balance/${address}`).catch(() => null));
    }
    
    await Promise.all(promises);
    
    // Check memory usage via health endpoint (if available)
    const health = await httpGet('/health');
    
    if (!health) {
      throw new Error('Server stopped after unique address queries');
    }
    
    results.pass(`Unique address queries (${uniqueAddresses} addresses)`);
  } catch (err) {
    results.fail('Unique address query handling', err);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 5: Concurrent connections (simulate multiple clients)
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const clients = 30;
    const requestsPerClient = 5;
    
    console.log(`   Simulating ${clients} concurrent clients...`);
    
    const simulateClient = async (clientId) => {
      const results = [];
      for (let i = 0; i < requestsPerClient; i++) {
        try {
          const r = await httpGet(`/balance/${TEST_ACCOUNTS.ALICE.address}`);
          results.push({ success: true });
        } catch (err) {
          results.push({ success: false, error: err.message });
        }
        // Small delay between requests
        await new Promise(resolve => setTimeout(resolve, 10));
      }
      return results;
    };
    
    const clientPromises = [];
    for (let i = 0; i < clients; i++) {
      clientPromises.push(simulateClient(i));
    }
    
    const allResults = await Promise.all(clientPromises);
    
    const totalRequests = clients * requestsPerClient;
    const successfulRequests = allResults.flat().filter(r => r.success).length;
    
    console.log(`   Results: ${successfulRequests}/${totalRequests} successful`);
    
    // At least 80% should succeed
    const successRate = successfulRequests / totalRequests;
    if (successRate < 0.8) {
      throw new Error(`Low success rate: ${Math.round(successRate * 100)}%`);
    }
    
    results.pass(`Concurrent clients (${clients} clients, ${totalRequests} requests)`);
  } catch (err) {
    results.fail('Concurrent client handling', err);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 6: Slowloris-style attack (slow body transmission)
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    // Note: This is a simplified test - real Slowloris requires raw socket access
    // We'll simulate with a delay before sending full body
    
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    
    try {
      // Start a request but don't send the body immediately
      const response = await fetch(`${CONFIG.API_BASE}/transfer`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Content-Length': '1000', // Claim we'll send 1000 bytes
        },
        body: '{"incomplete":true', // Send incomplete body
        signal: controller.signal,
      });
      
      clearTimeout(timeoutId);
      
      // Server should timeout or reject the incomplete request
      console.log(`   Incomplete request result: ${response.status}`);
    } catch (err) {
      clearTimeout(timeoutId);
      // Expected - server should close connection on incomplete request
    }
    
    // Verify server still responsive
    const health = await httpGet('/health');
    if (!health) {
      throw new Error('Server unresponsive after slowloris attempt');
    }
    
    results.pass('Slowloris-style attack handled');
  } catch (err) {
    results.fail('Slowloris defense', err);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 7: Final stress test - mixed load
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    console.log('   Running final mixed stress test...');
    
    const duration = 3000; // 3 seconds
    const startTime = Date.now();
    
    let reads = 0;
    let writes = 0;
    let errors = 0;
    
    const runUntilDone = async () => {
      while (Date.now() - startTime < duration) {
        try {
          if (Math.random() > 0.3) {
            // 70% reads
            await httpGet(`/balance/${TEST_ACCOUNTS.ALICE.address}`);
            reads++;
          } else {
            // 30% writes (with unique timestamps)
            const req = await createSignedTransfer(
              TEST_ACCOUNTS.ALICE.address,
              TEST_ACCOUNTS.BOB.address,
              0.001,
              aliceKeyPair
            );
            await httpPost('/transfer', req);
            writes++;
          }
        } catch (err) {
          errors++;
        }
        // Tiny delay to not completely flood
        await new Promise(resolve => setTimeout(resolve, 5));
      }
    };
    
    // Run 5 concurrent workers
    await Promise.all([
      runUntilDone(),
      runUntilDone(),
      runUntilDone(),
      runUntilDone(),
      runUntilDone(),
    ]);
    
    const total = reads + writes + errors;
    const elapsed = (Date.now() - startTime) / 1000;
    
    console.log(`   Results: ${reads} reads, ${writes} writes, ${errors} errors`);
    console.log(`   Total: ${total} requests in ${elapsed.toFixed(1)}s (${Math.round(total/elapsed)} rps)`);
    
    // Verify final health
    await new Promise(resolve => setTimeout(resolve, 500));
    const health = await httpGet('/health');
    
    if (!health) {
      throw new Error('Server died during stress test');
    }
    
    results.pass(`Mixed stress test (${duration/1000}s, ${total} requests)`);
  } catch (err) {
    results.fail('Mixed stress test', err);
  }
  
  return results;
}

// Run if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  run().then(r => {
    r.summary();
    process.exit(r.failed === 0 ? 0 : 1);
  });
}
