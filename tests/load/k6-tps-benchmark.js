/**
 * BlackBook L1 - TPS Benchmark Test
 * 
 * Focused on measuring maximum sustainable TPS
 * 
 * Run: k6 run k6-tps-benchmark.js --env BASE_URL=http://localhost:8080
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend, Gauge } from 'k6/metrics';
import { textSummary } from 'https://jslib.k6.io/k6-summary/0.0.1/index.js';

// ============================================================================
// TPS-SPECIFIC METRICS
// ============================================================================

const transactions_submitted = new Counter('transactions_submitted');
const transactions_confirmed = new Counter('transactions_confirmed');
const transactions_failed = new Counter('transactions_failed');
const current_tps = new Gauge('current_tps');
const latency_ms = new Trend('latency_ms', true);

// ============================================================================
// CONFIGURATION
// ============================================================================

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const TARGET_TPS = parseInt(__ENV.TARGET_TPS) || 65000;

// Pre-generated wallet addresses for testing
const TEST_WALLETS = [];
for (let i = 0; i < 10000; i++) {
    TEST_WALLETS.push(`BB_benchmark_${i.toString(16).padStart(8, '0')}`);
}

// ============================================================================
// LOAD TEST SCENARIOS
// ============================================================================

export const options = {
    scenarios: {
        // Scenario 1: Find Maximum TPS (ramping)
        find_max_tps: {
            executor: 'ramping-arrival-rate',
            startRate: 100,
            timeUnit: '1s',
            preAllocatedVUs: 500,
            maxVUs: 5000,
            stages: [
                { duration: '30s', target: 1000 },   // Warm-up
                { duration: '1m', target: 5000 },    // Ramp to 5K
                { duration: '1m', target: 10000 },   // Ramp to 10K
                { duration: '1m', target: 25000 },   // Ramp to 25K
                { duration: '1m', target: 50000 },   // Ramp to 50K
                { duration: '2m', target: 65000 },   // Target: 65K
                { duration: '1m', target: 80000 },   // Push beyond
                { duration: '1m', target: 100000 },  // Stretch: 100K
                { duration: '30s', target: 0 },      // Cool down
            ],
            exec: 'transferTest',
        },
    },
    
    // Thresholds for pass/fail
    thresholds: {
        'http_req_duration': ['p(95)<500'],      // 95% under 500ms
        'http_req_failed': ['rate<0.05'],         // <5% error rate
        'transactions_confirmed': ['count>10000'], // At least 10K confirmed
    },
    
    // Don't abort on threshold failure - we want to see max TPS
    abortOnFail: false,
};

// ============================================================================
// SETUP - Verify server and prepare
// ============================================================================

export function setup() {
    console.log('╔════════════════════════════════════════════════════════════════╗');
    console.log('║     BlackBook L1 - TPS BENCHMARK                               ║');
    console.log('╚════════════════════════════════════════════════════════════════╝');
    console.log('');
    console.log(`Target URL: ${BASE_URL}`);
    console.log(`Target TPS: ${TARGET_TPS.toLocaleString()}`);
    console.log('');
    
    // Health check
    const healthRes = http.get(`${BASE_URL}/mnemonic/health`, { timeout: '5s' });
    if (healthRes.status !== 200) {
        console.log('❌ Server health check failed!');
        console.log(`   Status: ${healthRes.status}`);
        console.log(`   Body: ${healthRes.body}`);
        throw new Error('Server not healthy');
    }
    console.log('✅ Server health check passed');
    
    // Try to hit the v2 transfer endpoint to check it exists
    const checkRes = http.post(`${BASE_URL}/v2/transfer`, JSON.stringify({
        from: 'BB_test',
        to: 'BB_test2',
        amount: 0,
        signature: 'test',
        nonce: 0,
    }), {
        headers: { 'Content-Type': 'application/json' },
        timeout: '5s',
    });
    console.log(`Transfer endpoint check: ${checkRes.status}`);
    
    return {
        startTime: Date.now(),
        testWallets: TEST_WALLETS,
    };
}

// ============================================================================
// TRANSFER TEST - Main TPS measurement
// ============================================================================

export function transferTest(data) {
    const vuId = __VU;
    const iterationId = __ITER;
    
    // Generate unique transaction
    const fromIdx = (vuId * 1000 + iterationId) % TEST_WALLETS.length;
    const toIdx = (fromIdx + 1) % TEST_WALLETS.length;
    
    const payload = JSON.stringify({
        from: TEST_WALLETS[fromIdx],
        to: TEST_WALLETS[toIdx],
        amount: 0.001,  // Small amount
        signature: `sig_${vuId}_${iterationId}_${Date.now()}`,
        nonce: Date.now() * 1000 + iterationId,
    });
    
    const startTime = Date.now();
    
    const res = http.post(`${BASE_URL}/v2/transfer`, payload, {
        headers: { 
            'Content-Type': 'application/json',
        },
        timeout: '10s',
        tags: { endpoint: 'transfer' },
    });
    
    const duration = Date.now() - startTime;
    latency_ms.add(duration);
    transactions_submitted.add(1);
    
    const success = check(res, {
        'status is 200': (r) => r.status === 200,
        'has transaction_id': (r) => {
            try {
                const body = JSON.parse(r.body);
                return body.transaction_id !== undefined || body.tx_id !== undefined;
            } catch {
                return false;
            }
        },
    });
    
    if (success) {
        transactions_confirmed.add(1);
    } else {
        transactions_failed.add(1);
        if (res.status >= 500) {
            // Log server errors for debugging
            console.log(`Server error: ${res.status} - ${res.body?.substring(0, 100)}`);
        }
    }
}

// ============================================================================
// BALANCE CHECK TEST - Read performance
// ============================================================================

export function balanceTest(data) {
    const address = TEST_WALLETS[__VU % TEST_WALLETS.length];
    
    const res = http.get(`${BASE_URL}/v2/balance/${address}`, {
        timeout: '5s',
        tags: { endpoint: 'balance' },
    });
    
    check(res, {
        'balance status 200': (r) => r.status === 200,
    });
}

// ============================================================================
// TEARDOWN - Generate TPS report
// ============================================================================

export function teardown(data) {
    const endTime = Date.now();
    const durationSecs = (endTime - data.startTime) / 1000;
    
    console.log('');
    console.log('════════════════════════════════════════════════════════════════');
    console.log('                    TPS BENCHMARK COMPLETE                        ');
    console.log('════════════════════════════════════════════════════════════════');
    console.log(`Duration: ${durationSecs.toFixed(1)} seconds`);
}

// ============================================================================
// SUMMARY - Generate detailed TPS report
// ============================================================================

export function handleSummary(data) {
    const durationMs = data.state.testRunDurationMs;
    const durationSecs = durationMs / 1000;
    
    // Get transaction counts
    const submitted = data.metrics.transactions_submitted?.values?.count || 0;
    const confirmed = data.metrics.transactions_confirmed?.values?.count || 0;
    const failed = data.metrics.transactions_failed?.values?.count || 0;
    
    // Calculate TPS
    const submittedTps = submitted / durationSecs;
    const confirmedTps = confirmed / durationSecs;
    
    // Get latency percentiles
    const p50 = data.metrics.latency_ms?.values?.['p(50)'] || 0;
    const p95 = data.metrics.latency_ms?.values?.['p(95)'] || 0;
    const p99 = data.metrics.latency_ms?.values?.['p(99)'] || 0;
    
    // Error rate
    const errorRate = submitted > 0 ? (failed / submitted) * 100 : 0;
    
    // Build report
    const report = {
        meta: {
            test_date: new Date().toISOString(),
            duration_seconds: durationSecs,
            target_tps: TARGET_TPS,
            base_url: BASE_URL,
        },
        transactions: {
            submitted: submitted,
            confirmed: confirmed,
            failed: failed,
            success_rate_percent: submitted > 0 ? (confirmed / submitted) * 100 : 0,
        },
        tps: {
            submitted_tps: Math.round(submittedTps),
            confirmed_tps: Math.round(confirmedTps),
            target_tps: TARGET_TPS,
            achieved_percent: (confirmedTps / TARGET_TPS) * 100,
        },
        latency_ms: {
            p50: Math.round(p50),
            p95: Math.round(p95),
            p99: Math.round(p99),
        },
        result: confirmedTps >= TARGET_TPS ? 'PASS' : 'FAIL',
    };
    
    // Console output
    const consoleReport = `
╔════════════════════════════════════════════════════════════════╗
║                    TPS BENCHMARK RESULTS                        ║
╠════════════════════════════════════════════════════════════════╣
║  Duration:        ${durationSecs.toFixed(1).padStart(10)} seconds                      ║
║  Target TPS:      ${TARGET_TPS.toLocaleString().padStart(10)}                            ║
╠════════════════════════════════════════════════════════════════╣
║  TRANSACTIONS                                                   ║
║    Submitted:     ${submitted.toLocaleString().padStart(10)}                            ║
║    Confirmed:     ${confirmed.toLocaleString().padStart(10)}                            ║
║    Failed:        ${failed.toLocaleString().padStart(10)}                            ║
║    Success Rate:  ${report.transactions.success_rate_percent.toFixed(2).padStart(10)}%                           ║
╠════════════════════════════════════════════════════════════════╣
║  TPS ACHIEVED                                                   ║
║    Submitted/sec: ${Math.round(submittedTps).toLocaleString().padStart(10)}                            ║
║    Confirmed/sec: ${Math.round(confirmedTps).toLocaleString().padStart(10)}                            ║
║    vs Target:     ${report.tps.achieved_percent.toFixed(1).padStart(10)}%                           ║
╠════════════════════════════════════════════════════════════════╣
║  LATENCY (milliseconds)                                         ║
║    p50:           ${Math.round(p50).toString().padStart(10)}                            ║
║    p95:           ${Math.round(p95).toString().padStart(10)}                            ║
║    p99:           ${Math.round(p99).toString().padStart(10)}                            ║
╠════════════════════════════════════════════════════════════════╣
║  RESULT:          ${report.result.padStart(10)}                            ║
╚════════════════════════════════════════════════════════════════╝
`;
    
    console.log(consoleReport);
    
    // Save results
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    
    return {
        [`results/tps_benchmark_${timestamp}.json`]: JSON.stringify(report, null, 2),
        stdout: textSummary(data, { indent: '  ', enableColors: true }),
    };
}
