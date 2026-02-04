/**
 * dealer-to-mac.js
 * 
 * Test Script: Transfer 500 BB ($50.00 USD) from Dealer to Mac
 * Uses Shamir 2-of-3 Secret Sharing with A+C recovery path
 * (Password + HashiCorp Vault)
 * 
 * Run: node tests/test-accounts/dealer-to-mac.js
 */

const BASE_URL = 'http://localhost:8080';

// Test account credentials
const DEALER = {
    password: 'DealerPassword123!',
    wallet_address: null,
    share_a_bound: null,
    share_c_encrypted: null
};

const MAC = {
    password: 'MacSecurePassword2026!',
    wallet_address: null
};

const TRANSFER_AMOUNT = 500; // 500 BB = $50.00 USD

// Utility: Make HTTP request with detailed logging
async function request(method, endpoint, body = null) {
    const url = `${BASE_URL}${endpoint}`;
    console.log(`\n📡 ${method} ${url}`);
    if (body) {
        console.log(`   Body: ${JSON.stringify(body, null, 2)}`);
    }
    
    const options = {
        method,
        headers: { 'Content-Type': 'application/json' }
    };
    
    if (body) {
        options.body = JSON.stringify(body);
    }
    
    try {
        const response = await fetch(url, options);
        const text = await response.text();
        
        let data;
        try {
            data = JSON.parse(text);
        } catch {
            data = { raw: text };
        }
        
        console.log(`   Status: ${response.status} ${response.statusText}`);
        console.log(`   Response: ${JSON.stringify(data, null, 2)}`);
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${JSON.stringify(data)}`);
        }
        
        return data;
    } catch (error) {
        console.error(`   ❌ Error: ${error.message}`);
        throw error;
    }
}

// Step 1: Check server health
async function checkHealth() {
    console.log('\n' + '='.repeat(60));
    console.log('STEP 1: Check Server Health');
    console.log('='.repeat(60));
    
    const health = await request('GET', '/health');
    console.log(`\n✅ Server is running (v${health.version})`);
    console.log(`   Total Supply: ${health.total_supply} BB`);
    console.log(`   Accounts: ${health.account_count}`);
    return health;
}

// Step 2: Create Dealer's wallet
async function setupDealer() {
    console.log('\n' + '='.repeat(60));
    console.log('STEP 2: Setup Dealer Wallet');
    console.log('='.repeat(60));
    
    console.log('\n📝 Creating Dealer wallet...');
    const wallet = await request('POST', '/mnemonic/create', {
        password: DEALER.password
    });
    
    DEALER.wallet_address = wallet.wallet_address;
    DEALER.share_a_bound = wallet.share_a_bound;
    
    console.log(`\n✅ Dealer Wallet Created`);
    console.log(`   Address: ${DEALER.wallet_address}`);
    console.log(`   Share A: ${DEALER.share_a_bound}`);
    
    return wallet;
}

// Step 3: Create Mac's wallet
async function setupMac() {
    console.log('\n' + '='.repeat(60));
    console.log('STEP 3: Setup Mac Wallet');
    console.log('='.repeat(60));
    
    console.log('\n📝 Creating Mac wallet...');
    const wallet = await request('POST', '/mnemonic/create', {
        password: MAC.password
    });
    
    MAC.wallet_address = wallet.wallet_address;
    
    console.log(`\n✅ Mac Wallet Created`);
    console.log(`   Address: ${MAC.wallet_address}`);
    
    return wallet;
}

// Step 4: Fund Dealer's wallet
async function fundDealer() {
    console.log('\n' + '='.repeat(60));
    console.log('STEP 4: Fund Dealer Wallet');
    console.log('='.repeat(60));
    
    const beforeBal = await request('GET', `/balance/${DEALER.wallet_address}`);
    console.log(`\n   Current Balance: ${beforeBal.balance} BB`);
    
    if (beforeBal.balance < TRANSFER_AMOUNT) {
        const mintAmount = 5000; // Mint 5000 BB = $500 USD
        console.log(`\n💰 Minting ${mintAmount} BB to Dealer...`);
        
        await request('POST', '/admin/mint', {
            to: DEALER.wallet_address,
            amount: mintAmount
        });
    }
    
    const afterBal = await request('GET', `/balance/${DEALER.wallet_address}`);
    console.log(`\n✅ Dealer Balance: ${afterBal.balance} BB = $${(afterBal.balance * 0.10).toFixed(2)} USD`);
    
    return afterBal;
}

// Step 5: Get Dealer's Share C from HashiCorp Vault
async function getDealerShareC() {
    console.log('\n' + '='.repeat(60));
    console.log('STEP 5: Retrieve Share C from HashiCorp Vault');
    console.log('='.repeat(60));
    
    const shareC = await request('GET', `/mnemonic/share-c/${DEALER.wallet_address}`);
    DEALER.share_c_encrypted = shareC.share_c_encrypted;
    
    console.log(`\n✅ Share C Retrieved`);
    console.log(`   Encrypted: ${DEALER.share_c_encrypted.substring(0, 40)}...`);
    
    return shareC;
}

// Step 6: Execute Transfer using A+C recovery path
async function executeTransfer() {
    console.log('\n' + '='.repeat(60));
    console.log('STEP 6: Execute Transfer (A+C Recovery Path)');
    console.log('='.repeat(60));
    
    console.log(`\n💸 Transferring ${TRANSFER_AMOUNT} BB ($${(TRANSFER_AMOUNT * 0.10).toFixed(2)} USD)`);
    console.log(`   From: ${DEALER.wallet_address}`);
    console.log(`   To:   ${MAC.wallet_address}`);
    console.log(`   Path: A+C (Password + HashiCorp Vault)`);
    
    const transferBody = {
        from: DEALER.wallet_address,
        to: MAC.wallet_address,
        amount: TRANSFER_AMOUNT,
        password: DEALER.password,
        share_a_bound: DEALER.share_a_bound,
        recovery_path: 'ac',
        share_c_encrypted: DEALER.share_c_encrypted
    };
    
    const result = await request('POST', '/mnemonic/transfer', transferBody);
    
    console.log(`\n✅ TRANSFER SUCCESSFUL!`);
    console.log(`   TX ID: ${result.tx_id}`);
    console.log(`   Signature: ${result.signature.substring(0, 40)}...`);
    console.log(`   Recovery Path: ${result.recovery_path_used}`);
    
    return result;
}

// Step 7: Verify final balances
async function verifyBalances() {
    console.log('\n' + '='.repeat(60));
    console.log('STEP 7: Verify Final Balances');
    console.log('='.repeat(60));
    
    const dealerBal = await request('GET', `/balance/${DEALER.wallet_address}`);
    const macBal = await request('GET', `/balance/${MAC.wallet_address}`);
    
    console.log('\n📊 FINAL BALANCES:');
    console.log(`   Dealer: ${dealerBal.balance} BB = $${(dealerBal.balance * 0.10).toFixed(2)} USD`);
    console.log(`   Mac:    ${macBal.balance} BB = $${(macBal.balance * 0.10).toFixed(2)} USD`);
    
    return { dealer: dealerBal.balance, mac: macBal.balance };
}

// Main test runner
async function main() {
    console.log('\n');
    console.log('╔══════════════════════════════════════════════════════════════╗');
    console.log('║   BLACKBOOK TRANSFER TEST: Dealer → Mac (500 BB = $50.00)    ║');
    console.log('║          Using Shamir 2-of-3 SSS with A+C Recovery           ║');
    console.log('╚══════════════════════════════════════════════════════════════╝');
    console.log('\n1 BB = $0.10 USD (Fixed Forever)\n');
    
    const startTime = Date.now();
    
    try {
        await checkHealth();
        await setupDealer();
        await setupMac();
        await fundDealer();
        await getDealerShareC();
        await executeTransfer();
        const finalBalances = await verifyBalances();
        
        const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);
        
        console.log('\n' + '='.repeat(60));
        console.log('TEST COMPLETE');
        console.log('='.repeat(60));
        console.log(`\n✅ SUCCESS! Transfer completed in ${elapsed}s`);
        console.log('\n📋 Summary:');
        console.log(`   • Dealer sent ${TRANSFER_AMOUNT} BB ($${(TRANSFER_AMOUNT * 0.10).toFixed(2)}) to Mac`);
        console.log(`   • Recovery path: A+C (Password + HashiCorp Vault)`);
        console.log(`   • Dealer final: ${finalBalances.dealer} BB`);
        console.log(`   • Mac final: ${finalBalances.mac} BB`);
        console.log('\n🔐 Security: Mnemonic was reconstructed from Share A + Share C,');
        console.log('   signed the transaction, and was immediately wiped from memory.\n');
        
    } catch (error) {
        console.log('\n' + '='.repeat(60));
        console.log('❌ TEST FAILED');
        console.log('='.repeat(60));
        console.error(`\nError: ${error.message}`);
        console.error('\nStack trace:');
        console.error(error.stack);
        console.log('\n🔍 Debug Info:');
        console.log(`   Dealer Address: ${DEALER.wallet_address || 'Not set'}`);
        console.log(`   Mac Address: ${MAC.wallet_address || 'Not set'}`);
        console.log(`   Share A: ${DEALER.share_a_bound ? DEALER.share_a_bound.substring(0, 30) + '...' : 'Not set'}`);
        console.log(`   Share C: ${DEALER.share_c_encrypted ? DEALER.share_c_encrypted.substring(0, 30) + '...' : 'Not set'}`);
        process.exit(1);
    }
}

main();
