/**
 * apollo-to-alice.js
 * 
 * Test Script: Transfer 250 BB ($25.00 USD) from Apollo to Alice
 * Uses Shamir 2-of-3 Secret Sharing with A+C recovery path
 * (Password + HashiCorp Vault)
 * 
 * Run: node tests/test-accounts/apollo-to-alice.js
 */

const BASE_URL = 'http://localhost:8080';

// Test account credentials
const APOLLO = {
    password: 'apollo_secure_password_2026',
    wallet_address: null,
    share_a_bound: null,
    share_c_encrypted: null
};

const ALICE = {
    password: 'AlicePassword123!',
    wallet_address: null
};

const TRANSFER_AMOUNT = 250; // 250 BB = $25.00 USD

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

// Step 2: Create Apollo's wallet
async function setupApollo() {
    console.log('\n' + '='.repeat(60));
    console.log('STEP 2: Setup Apollo Wallet');
    console.log('='.repeat(60));
    
    console.log('\n📝 Creating Apollo wallet...');
    const wallet = await request('POST', '/mnemonic/create', {
        password: APOLLO.password
    });
    
    APOLLO.wallet_address = wallet.wallet_address;
    APOLLO.share_a_bound = wallet.share_a_bound;
    
    console.log(`\n✅ Apollo Wallet Created`);
    console.log(`   Address: ${APOLLO.wallet_address}`);
    console.log(`   Share A: ${APOLLO.share_a_bound}`);
    
    return wallet;
}

// Step 3: Create Alice's wallet
async function setupAlice() {
    console.log('\n' + '='.repeat(60));
    console.log('STEP 3: Setup Alice Wallet');
    console.log('='.repeat(60));
    
    console.log('\n📝 Creating Alice wallet...');
    const wallet = await request('POST', '/mnemonic/create', {
        password: ALICE.password
    });
    
    ALICE.wallet_address = wallet.wallet_address;
    
    console.log(`\n✅ Alice Wallet Created`);
    console.log(`   Address: ${ALICE.wallet_address}`);
    
    return wallet;
}

// Step 4: Fund Apollo's wallet
async function fundApollo() {
    console.log('\n' + '='.repeat(60));
    console.log('STEP 4: Fund Apollo Wallet');
    console.log('='.repeat(60));
    
    const beforeBal = await request('GET', `/balance/${APOLLO.wallet_address}`);
    console.log(`\n   Current Balance: ${beforeBal.balance} BB`);
    
    if (beforeBal.balance < TRANSFER_AMOUNT) {
        const mintAmount = 2000; // Mint 2000 BB = $200 USD
        console.log(`\n💰 Minting ${mintAmount} BB to Apollo...`);
        
        await request('POST', '/admin/mint', {
            to: APOLLO.wallet_address,
            amount: mintAmount
        });
    }
    
    const afterBal = await request('GET', `/balance/${APOLLO.wallet_address}`);
    console.log(`\n✅ Apollo Balance: ${afterBal.balance} BB = $${(afterBal.balance * 0.10).toFixed(2)} USD`);
    
    return afterBal;
}

// Step 5: Get Apollo's Share C from HashiCorp Vault
async function getApolloShareC() {
    console.log('\n' + '='.repeat(60));
    console.log('STEP 5: Retrieve Share C from HashiCorp Vault');
    console.log('='.repeat(60));
    
    const shareC = await request('GET', `/mnemonic/share-c/${APOLLO.wallet_address}`);
    APOLLO.share_c_encrypted = shareC.share_c_encrypted;
    
    console.log(`\n✅ Share C Retrieved`);
    console.log(`   Encrypted: ${APOLLO.share_c_encrypted.substring(0, 40)}...`);
    
    return shareC;
}

// Step 6: Execute Transfer using A+C recovery path
async function executeTransfer() {
    console.log('\n' + '='.repeat(60));
    console.log('STEP 6: Execute Transfer (A+C Recovery Path)');
    console.log('='.repeat(60));
    
    console.log(`\n💸 Transferring ${TRANSFER_AMOUNT} BB ($${(TRANSFER_AMOUNT * 0.10).toFixed(2)} USD)`);
    console.log(`   From: ${APOLLO.wallet_address}`);
    console.log(`   To:   ${ALICE.wallet_address}`);
    console.log(`   Path: A+C (Password + HashiCorp Vault)`);
    
    const transferBody = {
        from: APOLLO.wallet_address,
        to: ALICE.wallet_address,
        amount: TRANSFER_AMOUNT,
        password: APOLLO.password,
        share_a_bound: APOLLO.share_a_bound,
        recovery_path: 'ac',
        share_c_encrypted: APOLLO.share_c_encrypted
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
    
    const apolloBal = await request('GET', `/balance/${APOLLO.wallet_address}`);
    const aliceBal = await request('GET', `/balance/${ALICE.wallet_address}`);
    
    console.log('\n📊 FINAL BALANCES:');
    console.log(`   Apollo: ${apolloBal.balance} BB = $${(apolloBal.balance * 0.10).toFixed(2)} USD`);
    console.log(`   Alice:  ${aliceBal.balance} BB = $${(aliceBal.balance * 0.10).toFixed(2)} USD`);
    
    return { apollo: apolloBal.balance, alice: aliceBal.balance };
}

// Main test runner
async function main() {
    console.log('\n');
    console.log('╔══════════════════════════════════════════════════════════════╗');
    console.log('║  BLACKBOOK TRANSFER TEST: Apollo → Alice (250 BB = $25.00)   ║');
    console.log('║          Using Shamir 2-of-3 SSS with A+C Recovery           ║');
    console.log('╚══════════════════════════════════════════════════════════════╝');
    console.log('\n1 BB = $0.10 USD (Fixed Forever)\n');
    
    const startTime = Date.now();
    
    try {
        await checkHealth();
        await setupApollo();
        await setupAlice();
        await fundApollo();
        await getApolloShareC();
        await executeTransfer();
        const finalBalances = await verifyBalances();
        
        const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);
        
        console.log('\n' + '='.repeat(60));
        console.log('TEST COMPLETE');
        console.log('='.repeat(60));
        console.log(`\n✅ SUCCESS! Transfer completed in ${elapsed}s`);
        console.log('\n📋 Summary:');
        console.log(`   • Apollo sent ${TRANSFER_AMOUNT} BB ($${(TRANSFER_AMOUNT * 0.10).toFixed(2)}) to Alice`);
        console.log(`   • Recovery path: A+C (Password + HashiCorp Vault)`);
        console.log(`   • Apollo final: ${finalBalances.apollo} BB`);
        console.log(`   • Alice final: ${finalBalances.alice} BB`);
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
        console.log(`   Apollo Address: ${APOLLO.wallet_address || 'Not set'}`);
        console.log(`   Alice Address: ${ALICE.wallet_address || 'Not set'}`);
        console.log(`   Share A: ${APOLLO.share_a_bound ? APOLLO.share_a_bound.substring(0, 30) + '...' : 'Not set'}`);
        console.log(`   Share C: ${APOLLO.share_c_encrypted ? APOLLO.share_c_encrypted.substring(0, 30) + '...' : 'Not set'}`);
        process.exit(1);
    }
}

main();
