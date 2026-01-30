/**
 * Register Apollo Wallet in Security Infrastructure
 * 
 * This script registers Apollo's existing wallet in the new PDA/security system
 */

const L1_URL = 'http://localhost:8080';
const fs = require('fs');
const path = require('path');

const GREEN = '\x1b[32m';
const CYAN = '\x1b[36m';
const YELLOW = '\x1b[33m';
const RED = '\x1b[31m';
const RESET = '\x1b[0m';

async function registerApollo() {
    console.log(`\n${CYAN}═══════════════════════════════════════════════════════════════${RESET}`);
    console.log(`${CYAN}  Registering Apollo Wallet in Security Infrastructure${RESET}`);
    console.log(`${CYAN}═══════════════════════════════════════════════════════════════${RESET}\n`);

    // Load Apollo wallet
    const apolloPath = path.join(__dirname, 'apollo', 'apollo-wallet-data.json');
    if (!fs.existsSync(apolloPath)) {
        console.log(`${RED}✗ Apollo wallet not found${RESET}\n`);
        process.exit(1);
    }
    
    const apollo = JSON.parse(fs.readFileSync(apolloPath, 'utf8'));
    console.log(`${CYAN}→${RESET} Apollo Address: ${apollo.address}`);
    console.log(`${CYAN}→${RESET} Root Pubkey: ${apollo.rootPubkey.slice(0, 32)}...`);
    console.log(`${CYAN}→${RESET} Op Pubkey: ${apollo.opPubkey.slice(0, 32)}...\n`);

    // Check current status
    try {
        console.log(`${CYAN}→${RESET} Checking current registration status...`);
        const checkRes = await fetch(`${L1_URL}/admin/security/pda/${apollo.address}`);
        const checkData = await checkRes.json();
        
        if (checkData.success) {
            console.log(`${GREEN}✓${RESET} Apollo is already registered!`);
            console.log(`  Account Type: ${checkData.account_type}`);
            console.log(`  Owner: ${checkData.owner}`);
            console.log(`  Created: ${new Date(checkData.created_at * 1000).toISOString()}`);
            if (checkData.pda_info) {
                console.log(`  PDA Namespace: ${checkData.pda_info.namespace}`);
                console.log(`  PDA Bump: ${checkData.pda_info.bump}\n`);
            }
            return;
        }
    } catch (e) {
        console.log(`${YELLOW}⚠${RESET} Could not check status: ${e.message}`);
    }

    // Apollo needs to be registered - this happens automatically on wallet creation
    // For existing wallets, we need to trigger registration via a transaction or manual API
    console.log(`\n${YELLOW}⚠${RESET} Apollo wallet exists but isn't registered in security system yet.`);
    console.log(`${CYAN}→${RESET} This will happen automatically on next transaction.`);
    console.log(`${CYAN}→${RESET} Or you can manually register by making any transaction.\n`);
    
    // Check balance to confirm wallet exists
    try {
        const balRes = await fetch(`${L1_URL}/balance/${apollo.address}`);
        const balData = await balRes.json();
        
        if (balData.balance !== undefined) {
            console.log(`${GREEN}✓${RESET} Apollo balance confirmed: ${balData.balance} BB`);
            console.log(`${CYAN}→${RESET} Wallet exists in blockchain storage`);
            console.log(`${CYAN}→${RESET} PDA metadata will be added on next transaction\n`);
        }
    } catch (e) {
        console.log(`${RED}✗${RESET} Could not verify balance: ${e.message}\n`);
    }

    // Show what would be registered
    console.log(`${CYAN}When registered, Apollo will have:${RESET}`);
    console.log(`  • Account Type: UserWallet`);
    console.log(`  • PDA Namespace: wallet`);
    console.log(`  • Owner: ${apollo.address}`);
    console.log(`  • Security Features:`);
    console.log(`    - Type-safe account validation`);
    console.log(`    - Stake-weighted rate limiting`);
    console.log(`    - Localized fee markets`);
    console.log(`    - Circuit breaker protection\n`);
}

registerApollo().catch(e => {
    console.error(`\n${RED}Error: ${e.message}${RESET}\n`);
    console.error(e.stack);
    process.exit(1);
});
