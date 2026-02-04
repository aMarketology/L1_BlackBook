/**
 * BlackBook L1 - Comprehensive Load Test Suite
 * 
 * Tests all production endpoints at 10K concurrent users
 * 
 * Run: k6 run k6-comprehensive-load-test.js --env BASE_URL=http://localhost:3000
 */

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Counter, Rate, Trend, Gauge } from 'k6/metrics';
import exec from 'k6/execution';

// ============================================================================
// CUSTOM METRICS
// ============================================================================

// Endpoint-specific metrics
const wallet_create_success = new Rate('wallet_create_success');
const balance_check_success = new Rate('balance_check_success');
const transfer_success = new Rate('transfer_success');
const recovery_success = new Rate('recovery_success');
const health_check_success = new Rate('health_check_success');

// Performance metrics
const wallet_create_time = new Trend('wallet_create_time', true);
const transfer_time = new Trend('transfer_time', true);
const balance_time = new Trend('balance_time', true);

// Rate limiting metrics
const rate_limit_ip = new Counter('rate_limit_ip');
const rate_limit_wallet = new Counter('rate_limit_wallet');
const rate_limit_lockout = new Counter('rate_limit_lockout');

// Error tracking
const server_errors = new Counter('server_errors');
const client_errors = new Counter('client_errors');

// ============================================================================
// LOAD TEST CONFIGURATION - 10K CONCURRENT USERS
// ============================================================================

export const options = {
    scenarios: {
        // Main stress test: Ramp to 10K users
        stress_test_10k: {
            executor: 'ramping-vus',
            startVUs: 0,
            stages: [
                { duration: '1m', target: 500 },     // Warm-up
                { duration: '2m', target: 2000 },    // Ramp to 2K
                { duration: '2m', target: 5000 },    // Ramp to 5K
                { duration: '3m', target: 10000 },   // Ramp to 10K
                { duration: '5m', target: 10000 },   // Hold at 10K
                { duration: '2m', target: 5000 },    // Scale down
                { duration: '1m', target: 0 },       // Cool down
            ],
            gracefulRampDown: '30s',
        },
    },
    
    thresholds: {
        // Response time thresholds
        'http_req_duration': ['p(95)<1000', 'p(99)<2000'],
        'http_req_duration{endpoint:health}': ['p(99)<100'],
        'http_req_duration{endpoint:balance}': ['p(95)<200'],
        'http_req_duration{endpoint:transfer}': ['p(95)<500'],
        
        // Error rate thresholds
        'http_req_failed': ['rate<0.05'],
        'server_errors': ['count<100'],
        
        // Success rate thresholds
        'health_check_success': ['rate>0.99'],
        'balance_check_success': ['rate>0.95'],
        'transfer_success': ['rate>0.90'],
        
        // Performance
        'wallet_create_time': ['p(95)<1000'],
        'transfer_time': ['p(95)<500'],
    },
};

// ============================================================================
// CONFIGURATION
// ============================================================================

const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';

// ============================================================================
// TEST SETUP
// ============================================================================

export function setup() {
    console.log('🚀 BlackBook L1 Comprehensive Load Test');
    console.log('========================================');
    console.log(`Target URL: ${BASE_URL}`);
    console.log(`Target: 10,000 concurrent users`);
    console.log(`Duration: ~16 minutes`);
    console.log('');
    
    // Verify server is running
    const healthRes = http.get(`${BASE_URL}/mnemonic/health`);
    if (healthRes.status !== 200) {
        throw new Error(`❌ Server health check failed: ${healthRes.status}`);
    }
    console.log('✅ Server health check passed');
    
    // Pre-create test wallets
    console.log('Creating test wallet pool...');
    const wallets = [];
    const walletsToCreate = 500; // Pool of wallets for load test
    
    for (let i = 0; i < walletsToCreate; i++) {
        try {
            const res = http.post(`${BASE_URL}/mnemonic/create`, JSON.stringify({
                password: `loadtest_${i}_${Date.now()}`,
            }), {
                headers: { 'Content-Type': 'application/json' },
                timeout: '10s',
            });
            
            if (res.status === 200) {
                const data = JSON.parse(res.body);
                wallets.push({
                    address: data.wallet_address,
                    password: `loadtest_${i}_${Date.now()}`,
                    mnemonic: data.mnemonic,
                });
            }
            
            if ((i + 1) % 100 === 0) {
                console.log(`  Created ${i + 1}/${walletsToCreate} wallets...`);
            }
        } catch (e) {
            // Continue on error
        }
    }
    
    console.log(`✅ Created ${wallets.length} test wallets`);
    console.log('');
    console.log('Starting load test...');
    
    return { wallets, startTime: Date.now() };
}

// ============================================================================
// MAIN TEST FUNCTION
// ============================================================================

export default function(data) {
    const vuId = exec.vu.idInTest;
    const iteration = exec.vu.iterationInInstance;
    const walletIdx = vuId % Math.max(data.wallets.length, 1);
    
    // Select test scenario based on iteration
    const scenario = iteration % 10;
    
    switch (scenario) {
        case 0:
        case 1:
            testHealthEndpoint();
            break;
        case 2:
        case 3:
        case 4:
            testBalanceCheck(data, walletIdx);
            break;
        case 5:
        case 6:
            testTransfer(data, walletIdx);
            break;
        case 7:
            testRecovery(data, walletIdx);
            break;
        case 8:
            testWalletCreation();
            break;
        case 9:
            testAuditEndpoints();
            break;
    }
    
    // Small random delay to simulate real users
    sleep(Math.random() * 0.5);
}

// ============================================================================
// ENDPOINT TESTS
// ============================================================================

function testHealthEndpoint() {
    group('Health Check', function() {
        const res = http.get(`${BASE_URL}/mnemonic/health`, {
            tags: { endpoint: 'health' },
        });
        
        health_check_success.add(res.status === 200);
        
        check(res, {
            'health status 200': (r) => r.status === 200,
        });
        
        trackErrors(res);
    });
}

function testBalanceCheck(data, walletIdx) {
    if (data.wallets.length === 0) return;
    
    group('Balance Check', function() {
        const wallet = data.wallets[walletIdx];
        const start = Date.now();
        
        const res = http.get(`${BASE_URL}/mnemonic/balance/${wallet.address}`, {
            tags: { endpoint: 'balance' },
        });
        
        balance_time.add(Date.now() - start);
        balance_check_success.add(res.status === 200);
        
        check(res, {
            'balance status 200': (r) => r.status === 200,
            'has balance field': (r) => r.json('balance') !== undefined,
        });
        
        trackErrors(res);
    });
}

function testTransfer(data, walletIdx) {
    if (data.wallets.length < 2) return;
    
    group('Transfer', function() {
        const fromWallet = data.wallets[walletIdx];
        const toWallet = data.wallets[(walletIdx + 1) % data.wallets.length];
        const start = Date.now();
        
        // 5% high-value transfers to test vault integration
        const amount = Math.random() < 0.05 ? 1500 : Math.floor(Math.random() * 100) + 1;
        
        const res = http.post(`${BASE_URL}/mnemonic/transfer`, JSON.stringify({
            wallet_address: fromWallet.address,
            password: fromWallet.password,
            to: toWallet.address,
            amount: amount,
        }), {
            headers: { 'Content-Type': 'application/json' },
            tags: { endpoint: 'transfer' },
        });
        
        transfer_time.add(Date.now() - start);
        transfer_success.add(res.status === 200);
        
        check(res, {
            'transfer status 200 or insufficient': (r) => r.status === 200 || r.status === 400,
            'no server error': (r) => r.status < 500,
        });
        
        trackErrors(res);
        trackRateLimits(res);
    });
}

function testRecovery(data, walletIdx) {
    if (data.wallets.length === 0) return;
    
    group('Recovery', function() {
        const wallet = data.wallets[walletIdx];
        
        // Test A+B recovery (most common)
        const res = http.post(`${BASE_URL}/mnemonic/recover/ab`, JSON.stringify({
            wallet_address: wallet.address,
            password: wallet.password,
        }), {
            headers: { 'Content-Type': 'application/json' },
            tags: { endpoint: 'recovery' },
        });
        
        recovery_success.add(res.status === 200);
        
        check(res, {
            'recovery status 200 or not found': (r) => r.status === 200 || r.status === 404,
        });
        
        trackErrors(res);
        trackRateLimits(res);
    });
}

function testWalletCreation() {
    group('Wallet Creation', function() {
        const start = Date.now();
        
        const res = http.post(`${BASE_URL}/mnemonic/create`, JSON.stringify({
            password: `loadtest_${Date.now()}_${Math.random().toString(36).substring(7)}`,
        }), {
            headers: { 'Content-Type': 'application/json' },
            tags: { endpoint: 'create' },
        });
        
        wallet_create_time.add(Date.now() - start);
        wallet_create_success.add(res.status === 200);
        
        check(res, {
            'create status 200': (r) => r.status === 200,
            'has wallet_address': (r) => r.json('wallet_address') !== undefined,
            'has mnemonic': (r) => r.json('mnemonic') !== undefined,
        });
        
        trackErrors(res);
    });
}

function testAuditEndpoints() {
    group('Audit Endpoints', function() {
        // Test get all audit logs
        const logsRes = http.get(`${BASE_URL}/audit/logs`, {
            tags: { endpoint: 'audit' },
        });
        
        check(logsRes, {
            'audit logs accessible': (r) => r.status === 200 || r.status === 404,
        });
        
        // Test export endpoint
        const exportRes = http.post(`${BASE_URL}/audit/export`, JSON.stringify({
            since_timestamp: Math.floor(Date.now() / 1000) - 60,
            limit: 10,
            include_logs: true,
        }), {
            headers: { 'Content-Type': 'application/json' },
            tags: { endpoint: 'audit' },
        });
        
        check(exportRes, {
            'audit export accessible': (r) => r.status === 200 || r.status === 404,
        });
        
        trackErrors(logsRes);
        trackErrors(exportRes);
    });
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function trackErrors(res) {
    if (res.status >= 500) {
        server_errors.add(1);
    } else if (res.status >= 400 && res.status !== 429) {
        client_errors.add(1);
    }
}

function trackRateLimits(res) {
    if (res.status === 429) {
        const body = res.body || '';
        if (body.includes('IP')) {
            rate_limit_ip.add(1);
        } else if (body.includes('wallet')) {
            rate_limit_wallet.add(1);
        } else if (body.includes('lockout')) {
            rate_limit_lockout.add(1);
        }
    }
}

// ============================================================================
// TEARDOWN
// ============================================================================

export function teardown(data) {
    const duration = Math.round((Date.now() - data.startTime) / 1000);
    
    console.log('');
    console.log('========================================');
    console.log('🏁 Load Test Complete!');
    console.log('========================================');
    console.log(`Duration: ${duration} seconds`);
    console.log(`Wallets tested: ${data.wallets.length}`);
    console.log('');
    console.log('Key Metrics (see report for details):');
    console.log('- http_req_duration: p(95) should be < 1000ms');
    console.log('- http_req_failed: should be < 5%');
    console.log('- health_check_success: should be > 99%');
    console.log('');
}
