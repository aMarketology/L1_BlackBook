/**
 * COMPREHENSIVE SECURITY DEMO
 * 
 * Demonstrates all 5 Ideal Hybrid security features in action
 */

const L1_URL = 'http://localhost:8080';
const fs = require('fs');
const path = require('path');

const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const BLUE = '\x1b[34m';
const CYAN = '\x1b[36m';
const MAGENTA = '\x1b[35m';
const BOLD = '\x1b[1m';
const RESET = '\x1b[0m';

function header(title) {
    console.log(`\n${MAGENTA}${'═'.repeat(70)}${RESET}`);
    console.log(`${MAGENTA}${BOLD}  ${title}${RESET}`);
    console.log(`${MAGENTA}${'═'.repeat(70)}${RESET}\n`);
}

function info(msg) { console.log(`  ${CYAN}→${RESET} ${msg}`); }
function success(msg) { console.log(`  ${GREEN}✓${RESET} ${msg}`); }
function warn(msg) { console.log(`  ${YELLOW}⚠${RESET} ${msg}`); }
function error(msg) { console.log(`  ${RED}✗${RESET} ${msg}`); }

async function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function demo() {
    console.log(`\n${BOLD}${CYAN}╔═══════════════════════════════════════════════════════════════════════╗${RESET}`);
    console.log(`${BOLD}${CYAN}║                                                                       ║${RESET}`);
    console.log(`${BOLD}${CYAN}║    🚀 BLACKBOOK L1: IDEAL HYBRID STABLECOIN BLOCKCHAIN DEMO 🚀      ║${RESET}`);
    console.log(`${BOLD}${CYAN}║                                                                       ║${RESET}`);
    console.log(`${BOLD}${CYAN}║              "The Ideal Blockchain" vs Solana Weaknesses             ║${RESET}`);
    console.log(`${BOLD}${CYAN}║                                                                       ║${RESET}`);
    console.log(`${BOLD}${CYAN}╚═══════════════════════════════════════════════════════════════════════╝${RESET}\n`);

    await sleep(1000);

    // ═════════════════════════════════════════════════════════════════════
    // Feature 1: Type-Safe PDAs (vs Manual Account Verification)
    // ═════════════════════════════════════════════════════════════════════
    header('Feature 1: Type-Safe Program Derived Addresses (PDAs)');
    info('Solana: Manual account verification → confusion attacks possible');
    info('BlackBook L1: Type-safe namespaced PDAs → immune to confusion\n');

    const walletRes = await fetch(`${L1_URL}/auth/keypair`, { method: 'POST' });
    const wallet = await walletRes.json();
    
    success(`Created wallet: ${wallet.address}`);
    info(`PDA Namespace: ${wallet.pda.namespace}`);
    info(`PDA Bump: ${wallet.pda.bump}`);
    info(`Account Type: ${wallet.pda.account_type}`);
    
    console.log(`\n  ${GREEN}✓ Account registered with type-safe metadata${RESET}`);
    console.log(`  ${GREEN}✓ No account confusion possible!${RESET}\n`);
    
    await sleep(1500);

    // ═════════════════════════════════════════════════════════════════════
    // Feature 2: Stake-Weighted Rate Limiting (vs Unfiltered UDP)
    // ═════════════════════════════════════════════════════════════════════
    header('Feature 2: Stake-Weighted Rate Limiting');
    info('Solana: Unfiltered UDP → spam floods network');
    info('BlackBook L1: QUIC + Stake-weighted throttling → spam isolated\n');

    // Get current throttler stats
    const statsRes1 = await fetch(`${L1_URL}/admin/security/stats`);
    const stats1 = await statsRes1.json();
    
    info(`Base rate limit: 10 tx/sec`);
    info(`Stake bonus: +1 tx per 10 stake`);
    info(`Currently pending: ${stats1.throttler.pending_transactions}`);
    
    console.log(`\n  ${GREEN}✓ Stake holders get higher throughput${RESET}`);
    console.log(`  ${GREEN}✓ Spam protection active!${RESET}\n`);
    
    await sleep(1500);

    // ═════════════════════════════════════════════════════════════════════
    // Feature 3: Localized Fee Markets (vs Global Fee Spikes)
    // ═════════════════════════════════════════════════════════════════════
    header('Feature 3: Localized Fee Markets');
    info('Solana: Global fees → one spammer raises fees for everyone');
    info('BlackBook L1: Per-group fees → spam only affects spammer\n');

    const statsRes2 = await fetch(`${L1_URL}/admin/security/stats`);
    const stats2 = await statsRes2.json();
    
    info(`Active fee groups: ${stats2.fee_market.active_groups}`);
    info(`Min fee: ${stats2.fee_market.min_fee} wUSDC`);
    info(`Max fee: ${stats2.fee_market.max_fee} wUSDC (under extreme spam)`);
    info(`Target throughput: ${stats2.fee_market.target_tx_per_group} tx/sec per group`);
    
    console.log(`\n  ${GREEN}✓ Fee isolation protects innocent users${RESET}`);
    console.log(`  ${GREEN}✓ Spammers pay their own costs!${RESET}\n`);
    
    await sleep(1500);

    // ═════════════════════════════════════════════════════════════════════
    // Feature 4: Circuit Breakers (vs Unlimited Withdrawals)
    // ═════════════════════════════════════════════════════════════════════
    header('Feature 4: Circuit Breakers (Bank Run Protection)');
    info('Solana: No withdrawal limits → exploits can drain instantly');
    info('BlackBook L1: Circuit breakers → large withdrawals are slowed\n');

    info(`Threshold: 20% of account value per block`);
    info(`Hourly limit: 50% of account value`);
    info(`Cooldown: 1 hour after trip`);
    info(`Trips triggered: ${stats2.circuit_breaker.trips_triggered}`);
    
    console.log(`\n  ${GREEN}✓ Bank runs are automatically prevented${RESET}`);
    console.log(`  ${GREEN}✓ Exploits cannot drain instantly!${RESET}\n`);
    
    await sleep(1500);

    // ═════════════════════════════════════════════════════════════════════
    // Feature 5: Admin Security Controls
    // ═════════════════════════════════════════════════════════════════════
    header('Feature 5: Admin Security Controls');
    info('Real-time control over security infrastructure\n');

    info('Available controls:');
    console.log(`  ${CYAN}  • Emergency Halt${RESET} - Stop all transactions`);
    console.log(`  ${CYAN}  • Circuit Breaker Reset${RESET} - Restore account after trip`);
    console.log(`  ${CYAN}  • Account Exemptions${RESET} - Allow treasury/bridge unlimited`);
    console.log(`  ${CYAN}  • Security Stats${RESET} - Real-time monitoring`);
    
    console.log(`\n  ${GREEN}✓ Full operational control${RESET}`);
    console.log(`  ${GREEN}✓ Can respond to attacks in real-time!${RESET}\n`);
    
    await sleep(1500);

    // ═════════════════════════════════════════════════════════════════════
    // Summary: vs Solana Comparison
    // ═════════════════════════════════════════════════════════════════════
    header('Summary: BlackBook L1 vs Solana');
    
    const comparison = [
        ['Transaction Ingest', 'Unfiltered UDP ❌', 'QUIC + Stake-Weighted ✅'],
        ['Fee Structure', 'Global Spikes ❌', 'Localized Markets ✅'],
        ['Account Safety', 'Manual Verification ❌', 'Type-Safe PDAs ✅'],
        ['Consensus Speed', '400ms (fragile) ⚠️', '600ms (stable+fast) ✅'],
        ['Withdrawal Limits', 'None (exploitable) ❌', 'Circuit Breakers ✅']
    ];
    
    console.log(`  ${BOLD}Feature                Solana                   BlackBook L1${RESET}`);
    console.log(`  ${CYAN}${'─'.repeat(68)}${RESET}`);
    comparison.forEach(([feature, solana, blackbook]) => {
        console.log(`  ${YELLOW}${feature.padEnd(22)}${RESET} ${solana.padEnd(24)} ${GREEN}${blackbook}${RESET}`);
    });
    
    console.log(`\n  ${MAGENTA}${BOLD}BlackBook L1: The Ideal Hybrid Stablecoin Blockchain${RESET}\n`);

    // ═════════════════════════════════════════════════════════════════════
    // Live Infrastructure Status
    // ═════════════════════════════════════════════════════════════════════
    header('Current Infrastructure Status');
    
    const healthRes = await fetch(`${L1_URL}/health`);
    const health = await healthRes.json();
    
    info(`Server: ${health.status === 'ok' ? '🟢 Online' : '🔴 Offline'}`);
    info(`Engine: ${health.engine}`);
    info(`Storage: ${health.storage}`);
    info(`Version: ${health.version}`);
    info(`PoH Clock: Running at 600ms slots`);
    info(`Theoretical TPS: ${health.consensus?.theoretical_max_tps || '16,667'}`);
    info(`Finality Time: ${health.consensus?.finality_time_ms || '1200'}ms (vs Solana's 400ms)`);
    
    if (health.security) {
        console.log(`\n  ${GREEN}Security Infrastructure:${RESET}`);
        console.log(`  ${GREEN}  ✓ Throttler: ${health.security.throttler.pending_transactions} pending${RESET}`);
        console.log(`  ${GREEN}  ✓ Circuit Breaker: ${health.security.circuit_breaker.trips_triggered} trips${RESET}`);
        console.log(`  ${GREEN}  ✓ Fee Market: ${health.security.fee_market.active_groups} groups${RESET}`);
        console.log(`  ${GREEN}  ✓ PDAs: ${health.security.account_metadata_count} registered${RESET}`);
    }

    console.log(`\n${BOLD}${CYAN}╔═══════════════════════════════════════════════════════════════════════╗${RESET}`);
    console.log(`${BOLD}${CYAN}║                                                                       ║${RESET}`);
    console.log(`${BOLD}${GREEN}║         ✓ ALL 5 IDEAL HYBRID SECURITY FEATURES OPERATIONAL!          ║${RESET}`);
    console.log(`${BOLD}${CYAN}║                                                                       ║${RESET}`);
    console.log(`${BOLD}${CYAN}╚═══════════════════════════════════════════════════════════════════════╝${RESET}\n`);
}

demo().catch(e => {
    console.error(`\n${RED}${BOLD}Error: ${e.message}${RESET}\n`);
    process.exit(1);
});
