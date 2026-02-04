/**
 * BlackBook L1 - ZKP Authentication Load Test
 * 
 * Uses k6 for load testing ZKP challenge/verification at 10K concurrent users
 * 
 * Install k6: https://k6.io/docs/get-started/installation/
 * Run: k6 run k6-zkp-load-test.js
 */

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';
import { randomBytes } from 'k6/crypto';
import exec from 'k6/execution';

// ============================================================================
// CUSTOM METRICS
// ============================================================================

const zkp_challenge_success = new Rate('zkp_challenge_success');
const zkp_verify_success = new Rate('zkp_verify_success');
const zkp_challenge_duration = new Trend('zkp_challenge_duration');
const zkp_verify_duration = new Trend('zkp_verify_duration');
const rate_limit_hits = new Counter('rate_limit_hits');
const transfer_success = new Rate('transfer_success');

// ============================================================================
// LOAD TEST CONFIGURATION
// ============================================================================

export const options = {
    scenarios: {
        // Scenario 1: Ramp up to 10K concurrent users
        stress_test: {
            executor: 'ramping-vus',
            startVUs: 0,
            stages: [
                { duration: '2m', target: 1000 },   // Ramp to 1K
                { duration: '3m', target: 5000 },   // Ramp to 5K
                { duration: '5m', target: 10000 },  // Ramp to 10K
                { duration: '10m', target: 10000 }, // Stay at 10K
                { duration: '3m', target: 5000 },   // Scale down
                { duration: '2m', target: 0 },      // Cool down
            ],
            gracefulRampDown: '30s',
        },
        
        // Scenario 2: Constant high load
        constant_load: {
            executor: 'constant-vus',
            vus: 10000,
            duration: '15m',
            startTime: '25m', // Start after stress test
        },
        
        // Scenario 3: Spike test
        spike_test: {
            executor: 'ramping-vus',
            startVUs: 1000,
            startTime: '45m',
            stages: [
                { duration: '10s', target: 10000 }, // Instant spike
                { duration: '1m', target: 10000 },  // Hold spike
                { duration: '10s', target: 1000 },  // Drop back
            ],
        },
    },
    
    thresholds: {
        // HTTP errors < 5%
        http_req_failed: ['rate<0.05'],
        
        // 95% of requests complete in < 500ms
        http_req_duration: ['p(95)<500'],
        
        // ZKP challenge success rate > 95%
        zkp_challenge_success: ['rate>0.95'],
        
        // ZKP verify success rate > 90% (some intentional failures)
        zkp_verify_success: ['rate>0.90'],
        
        // Custom trends
        zkp_challenge_duration: ['p(95)<200'],
        zkp_verify_duration: ['p(95)<300'],
    },
};

// ============================================================================
// CONFIGURATION
// ============================================================================

const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';
const TEST_WALLETS = [
    'BB_LOAD_TEST_0001',
    'BB_LOAD_TEST_0002', 
    'BB_LOAD_TEST_0003',
    'BB_LOAD_TEST_0004',
    'BB_LOAD_TEST_0005',
];

// ============================================================================
// TEST HELPERS
// ============================================================================

function getRandomWallet() {
    // Generate unique wallet per VU to avoid rate limiting conflicts
    const vuId = exec.vu.idInTest;
    return `BB_LOAD_VU_${vuId.toString().padStart(5, '0')}`;
}

function randomHex(length) {
    const bytes = new Uint8Array(length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = Math.floor(Math.random() * 256);
    }
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

// ============================================================================
// SETUP: Create test wallets before load test
// ============================================================================

export function setup() {
    console.log('🚀 Setting up load test...');
    console.log(`Base URL: ${BASE_URL}`);
    
    // Health check
    const health = http.get(`${BASE_URL}/mnemonic/health`);
    if (health.status !== 200) {
        throw new Error(`Server not healthy: ${health.status}`);
    }
    console.log('✅ Server health check passed');
    
    // Create a pool of test wallets
    const wallets = [];
    for (let i = 0; i < 100; i++) {
        const res = http.post(`${BASE_URL}/mnemonic/create`, JSON.stringify({
            password: `loadtest_password_${i}`,
        }), {
            headers: { 'Content-Type': 'application/json' },
        });
        
        if (res.status === 200) {
            const data = JSON.parse(res.body);
            wallets.push({
                address: data.wallet_address,
                password: `loadtest_password_${i}`,
                mnemonic: data.mnemonic,
            });
        }
    }
    
    console.log(`✅ Created ${wallets.length} test wallets`);
    return { wallets };
}

// ============================================================================
// MAIN TEST SCENARIOS
// ============================================================================

export default function(data) {
    const walletIdx = exec.vu.idInTest % data.wallets.length;
    const wallet = data.wallets[walletIdx];
    
    group('ZKP Authentication Flow', function() {
        // Step 1: Request ZKP Challenge
        let challengeStart = Date.now();
        const challengeRes = http.post(`${BASE_URL}/mnemonic/zkp/challenge`, JSON.stringify({
            wallet_address: wallet.address,
            public_key: randomHex(64), // Simulated public key
        }), {
            headers: { 'Content-Type': 'application/json' },
        });
        zkp_challenge_duration.add(Date.now() - challengeStart);
        
        const challengeSuccess = check(challengeRes, {
            'challenge status 200': (r) => r.status === 200,
            'challenge has data': (r) => r.json('challenge') !== undefined,
        });
        zkp_challenge_success.add(challengeSuccess);
        
        if (challengeRes.status === 429) {
            rate_limit_hits.add(1);
            sleep(1); // Wait before retry
            return;
        }
        
        if (!challengeSuccess) {
            return;
        }
        
        const challenge = challengeRes.json('challenge');
        
        // Step 2: Verify ZKP (simulated signature)
        let verifyStart = Date.now();
        const verifyRes = http.post(`${BASE_URL}/mnemonic/zkp/verify`, JSON.stringify({
            wallet_address: wallet.address,
            challenge: challenge,
            signature: randomHex(128), // Simulated signature (will fail verification)
            public_key: randomHex(64),
        }), {
            headers: { 'Content-Type': 'application/json' },
        });
        zkp_verify_duration.add(Date.now() - verifyStart);
        
        // Note: These will mostly fail since we're using random signatures
        // That's intentional - we're testing rate limiting and system stability
        const verifySuccess = check(verifyRes, {
            'verify status 200 or 401': (r) => r.status === 200 || r.status === 401,
            'no 500 errors': (r) => r.status !== 500,
        });
        zkp_verify_success.add(verifyRes.status === 200);
        
        if (verifyRes.status === 429) {
            rate_limit_hits.add(1);
        }
    });
    
    // Small delay between requests
    sleep(0.1);
}

// ============================================================================
// ADDITIONAL SCENARIOS
// ============================================================================

export function transfer_load_test(data) {
    const walletIdx = exec.vu.idInTest % data.wallets.length;
    const wallet = data.wallets[walletIdx];
    const toWallet = data.wallets[(walletIdx + 1) % data.wallets.length];
    
    group('Transfer Load Test', function() {
        const res = http.post(`${BASE_URL}/mnemonic/transfer`, JSON.stringify({
            wallet_address: wallet.address,
            password: wallet.password,
            to: toWallet.address,
            amount: Math.random() < 0.1 ? 1500 : 50, // 10% high-value transfers
        }), {
            headers: { 'Content-Type': 'application/json' },
        });
        
        transfer_success.add(res.status === 200);
        
        check(res, {
            'transfer status 200': (r) => r.status === 200,
            'no 500 errors': (r) => r.status !== 500,
        });
    });
    
    sleep(0.2);
}

export function siem_endpoint_test() {
    group('SIEM Endpoint Test', function() {
        // Test audit logs endpoint
        const logsRes = http.get(`${BASE_URL}/audit/logs`);
        check(logsRes, {
            'audit logs status 200': (r) => r.status === 200,
        });
        
        // Test export endpoint
        const exportRes = http.post(`${BASE_URL}/audit/export`, JSON.stringify({
            since_timestamp: Math.floor(Date.now() / 1000) - 3600, // Last hour
            limit: 100,
            siem_type: 'webhook',
            include_logs: true,
        }), {
            headers: { 'Content-Type': 'application/json' },
        });
        
        check(exportRes, {
            'audit export status 200': (r) => r.status === 200,
            'has logs': (r) => r.json('total_available') !== undefined,
        });
    });
    
    sleep(1);
}

// ============================================================================
// TEARDOWN
// ============================================================================

export function teardown(data) {
    console.log('🏁 Load test complete!');
    console.log(`Tested with ${data.wallets.length} wallets`);
}
