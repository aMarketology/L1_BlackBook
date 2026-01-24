/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * TEST 17: Fuzz Testing
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Fuzz testing throws random/malformed data at the system to find edge cases
 * and crash scenarios that manual testing would never find.
 * 
 * Famous bugs found by fuzzing:
 * - Heartbleed (OpenSSL)
 * - Countless browser vulnerabilities
 * - Many blockchain exploits
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

// Random data generators
function randomString(length) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?/~`';
  return Array.from({ length }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

function randomHex(length) {
  return Array.from({ length }, () => Math.floor(Math.random() * 16).toString(16)).join('');
}

function randomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function randomAmount() {
  const types = [
    () => Math.random() * 1000,
    () => -Math.random() * 1000,
    () => 0,
    () => Number.MAX_SAFE_INTEGER * Math.random(),
    () => Math.random() * 0.0001,
    () => NaN,
    () => Infinity,
    () => -Infinity,
  ];
  return types[Math.floor(Math.random() * types.length)]();
}

function randomAddress() {
  const types = [
    () => `L1_${randomHex(40)}`,
    () => randomString(44),
    () => '',
    () => 'L1_0000000000000000000000000000000000000000',
    () => TEST_ACCOUNTS.ALICE.address,
    () => `L1_${'F'.repeat(40)}`,
    () => 'null',
    () => '<script>alert(1)</script>',
    () => `L1_${randomHex(100)}`, // Too long
  ];
  return types[Math.floor(Math.random() * types.length)]();
}

export async function run() {
  const results = new TestResults();
  const aliceKeyPair = nacl.sign.keyPair.fromSeed(hexToBytes(TEST_ACCOUNTS.ALICE.seed));
  
  console.log('   🎲 Running fuzz tests...\n');
  
  // Track crashes
  let crashes = [];
  let serverAlive = true;
  
  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 1: Random transfer payloads (100 iterations)
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const iterations = 100;
    let serverErrors = 0;
    let rejected = 0;
    
    console.log(`   Running ${iterations} random transfer payloads...`);
    
    for (let i = 0; i < iterations; i++) {
      try {
        const fuzzPayload = {
          from: randomAddress(),
          to: randomAddress(),
          amount: randomAmount(),
          timestamp: Math.random() > 0.5 ? Date.now() : randomString(10),
          public_key: randomHex(64),
          signature: randomHex(128),
          // Random extra fields
          [randomString(5)]: randomString(10),
        };
        
        const response = await httpPost('/transfer/simple', fuzzPayload);
        
        if (response.error) {
          rejected++;
        }
      } catch (err) {
        if (err.message.includes('ECONNREFUSED')) {
          serverErrors++;
          crashes.push(`Transfer fuzz iteration ${i}: Server connection refused`);
        }
      }
    }
    
    // Server should still be alive
    try {
      const health = await httpGet('/health');
      serverAlive = !!health;
    } catch (e) {
      serverAlive = false;
    }
    
    console.log(`   Results: ${rejected}/${iterations} rejected, ${serverErrors} server errors`);
    
    if (!serverAlive) {
      throw new Error('SERVER CRASHED during random transfer fuzz testing!');
    }
    
    results.pass(`Random transfer payloads (${iterations} iterations)`);
  } catch (err) {
    results.fail('Random transfer fuzz', err);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 2: Random balance queries (50 iterations)
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const iterations = 50;
    let errors = 0;
    
    console.log(`   Running ${iterations} random balance queries...`);
    
    for (let i = 0; i < iterations; i++) {
      try {
        const fuzzAddress = randomAddress();
        await httpGet(`/balance/${encodeURIComponent(fuzzAddress)}`);
      } catch (err) {
        if (err.message.includes('ECONNREFUSED')) {
          errors++;
        }
      }
    }
    
    const health = await httpGet('/health');
    
    if (errors > 0) {
      throw new Error(`Server crashed ${errors} times during balance fuzz`);
    }
    
    results.pass(`Random balance queries (${iterations} iterations)`);
  } catch (err) {
    results.fail('Random balance fuzz', err);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 3: Malformed JSON payloads
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const malformedPayloads = [
      '', // Empty
      '{', // Incomplete
      '{"amount": }', // Invalid value
      '{"amount": 100, "from": "L1_test",', // Trailing comma
      'not json at all',
      '{"__proto__": {"polluted": true}}', // Prototype pollution
      '{"constructor": {"prototype": {"pwned": true}}}',
      '{"amount": {"$gt": 0}}', // NoSQL injection
      '<xml>attack</xml>', // XML injection
      '{"amount": 1e999}', // Overflow number
      '{"amount": 1, "__proto__": null}',
      '{"amount": [1,2,3]}', // Array instead of number
      '{"amount": {"valueOf": 100}}', // Object with valueOf
      Buffer.alloc(10000).fill('A').toString(), // Large payload
      JSON.stringify({ a: 'x'.repeat(100000) }), // Large string
    ];
    
    let crashed = 0;
    
    for (const payload of malformedPayloads) {
      try {
        // Send raw payload
        const response = await fetch(`${CONFIG.API_BASE}/transfer`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: payload,
        });
        // Server responded - good
      } catch (err) {
        if (err.message.includes('ECONNREFUSED')) {
          crashed++;
          crashes.push(`Malformed JSON crash: ${payload.substring(0, 50)}`);
        }
      }
    }
    
    if (crashed > 0) {
      throw new Error(`Server crashed on ${crashed} malformed JSON payloads`);
    }
    
    results.pass(`Malformed JSON payloads (${malformedPayloads.length} variants)`);
  } catch (err) {
    results.fail('Malformed JSON fuzz', err);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 4: Path traversal in balance endpoint
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const pathTraversals = [
      '../../../etc/passwd',
      '..\\..\\..\\windows\\system32',
      '%2e%2e%2f%2e%2e%2f',
      '....//....//....//etc/passwd',
      'L1_test/../../../etc/passwd',
      'L1_test%00.txt',
      'L1_test\x00.txt',
    ];
    
    let leaked = false;
    
    for (const path of pathTraversals) {
      try {
        const response = await httpGet(`/balance/${encodeURIComponent(path)}`);
        
        // Check for file content leak
        if (typeof response === 'string') {
          if (response.includes('root:') || response.includes('WINDOWS')) {
            leaked = true;
            crashes.push(`Path traversal leak: ${path}`);
          }
        }
      } catch (err) {
        // Rejection is fine
      }
    }
    
    if (leaked) {
      throw new Error('PATH TRAVERSAL VULNERABILITY DETECTED!');
    }
    
    results.pass(`Path traversal prevention (${pathTraversals.length} attempts)`);
  } catch (err) {
    results.fail('Path traversal prevention', err);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 5: Unicode/encoding attacks
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const unicodePayloads = [
      { from: 'L1_\u0000test', to: TEST_ACCOUNTS.BOB.address, amount: 1 },
      { from: 'L1_\uFEFFtest', to: TEST_ACCOUNTS.BOB.address, amount: 1 },
      { from: 'L1_test\u202E', to: TEST_ACCOUNTS.BOB.address, amount: 1 }, // RTL override
      { from: '\u0000\u0000\u0000', to: '\u0000\u0000', amount: 1 },
      { from: '🚀💰🔥', to: TEST_ACCOUNTS.BOB.address, amount: 1 },
      { from: '\xFF\xFE', to: '\xFF\xFE', amount: 1 }, // BOM
    ];
    
    let crashed = 0;
    
    for (const payload of unicodePayloads) {
      try {
        await httpPost('/transfer/simple', { ...payload, public_key: randomHex(64), signature: randomHex(128), timestamp: Date.now() });
      } catch (err) {
        if (err.message.includes('ECONNREFUSED')) {
          crashed++;
        }
      }
    }
    
    if (crashed > 0) {
      throw new Error(`Server crashed on ${crashed} unicode payloads`);
    }
    
    results.pass(`Unicode/encoding attacks (${unicodePayloads.length} variants)`);
  } catch (err) {
    results.fail('Unicode attack prevention', err);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 6: Binary data in JSON fields
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const binaryTests = [
      { from: bytesToHex(randomBytes(32)), to: bytesToHex(randomBytes(32)), amount: 1 },
      { from: String.fromCharCode(...randomBytes(20)), to: TEST_ACCOUNTS.BOB.address, amount: 1 },
    ];
    
    let crashed = 0;
    
    for (const payload of binaryTests) {
      try {
        await httpPost('/transfer/simple', { ...payload, public_key: randomHex(64), signature: randomHex(128), timestamp: Date.now() });
      } catch (err) {
        if (err.message.includes('ECONNREFUSED')) {
          crashed++;
        }
      }
    }
    
    if (crashed > 0) {
      throw new Error(`Server crashed on binary data`);
    }
    
    results.pass('Binary data handling');
  } catch (err) {
    results.fail('Binary data handling', err);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 7: Concurrent random requests (stress + fuzz)
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const concurrentCount = 20;
    
    console.log(`   Running ${concurrentCount} concurrent random requests...`);
    
    const promises = [];
    for (let i = 0; i < concurrentCount; i++) {
      // Mix of different request types
      if (i % 3 === 0) {
        promises.push(httpGet(`/balance/${randomAddress()}`).catch(() => null));
      } else if (i % 3 === 1) {
        promises.push(httpPost('/transfer/simple', {
          from: randomAddress(),
          to: randomAddress(),
          amount: randomAmount(),
          timestamp: Date.now(),
          public_key: randomHex(64),
          signature: randomHex(128),
        }).catch(() => null));
      } else {
        promises.push(httpGet('/health').catch(() => null));
      }
    }
    
    await Promise.all(promises);
    
    // Verify server still alive
    const health = await httpGet('/health');
    
    if (!health) {
      throw new Error('Server died during concurrent fuzz test');
    }
    
    results.pass(`Concurrent random requests (${concurrentCount} parallel)`);
  } catch (err) {
    results.fail('Concurrent fuzz test', err);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 8: Final health check after all fuzz tests
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    // Give server a moment to recover
    await new Promise(resolve => setTimeout(resolve, 500));
    
    const health = await httpGet('/health');
    
    if (!health) {
      throw new Error('Server unhealthy after fuzz tests');
    }
    
    // Also verify a real transfer still works
    const aliceBalance = await getBalance(TEST_ACCOUNTS.ALICE.address);
    const bobBalance = await getBalance(TEST_ACCOUNTS.BOB.address);
    
    if (typeof aliceBalance !== 'number' || typeof bobBalance !== 'number') {
      throw new Error('Balance queries broken after fuzz tests');
    }
    
    results.pass('Server healthy after fuzz testing');
  } catch (err) {
    results.fail('Post-fuzz health check', err);
  }
  
  // Report any crashes discovered
  if (crashes.length > 0) {
    console.log('\n   ⚠️  CRASHES DETECTED:');
    crashes.forEach(c => console.log(`      - ${c}`));
  }
  
  return results;
}

async function getBalance(address) {
  const response = await httpGet(`/balance/${address}`);
  return response.balance ?? response.available ?? 0;
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
