/**
 * BlackBook L1 - Token Transfer Test Between All Accounts
 * Tests token transfers between Alice, Bob, Mac, Apollo, and checks balances
 */

const path = require('path');
const fs = require('fs');
const { ZKPWallet } = require('../zkp-wallet-sdk');

const L1_API_URL = 'http://localhost:8080';

// Account details
const accounts = [
    {
        name: 'Alice',
        file: 'alice-zkp-wallet.json',
        password: 'AlicePassword123!'
    },
    {
        name: 'Bob',
        file: 'bob-zkp-wallet.json',
        password: 'BobPassword123!'
    },
    {
        name: 'Mac',
        file: 'mac-zkp-wallet.json',
        password: 'MacSecurePassword2026!'
    },
    {
        name: 'Apollo',
        file: 'apollo-zkp-wallet.json',
        password: 'apollo_secure_password_2026'
    }
];

/**
 * Load wallet from file
 */
function loadWallet(filename) {
    const filePath = path.join(__dirname, filename);
    const data = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(data);
}

/**
 * Get wallet balance from L1
 */
async function getBalance(address) {
    try {
        const response = await fetch(`${L1_API_URL}/balance/${address}`);
        if (!response.ok) {
            const text = await response.text();
            throw new Error(`Failed to get balance: ${response.status} - ${text}`);
        }
        const data = await response.json();
        return data.balance || 0;
    } catch (error) {
        console.error(`❌ Error getting balance for ${address}:`, error.message);
        return null;
    }
}

/**
 * Send tokens between wallets
 */
async function sendTokens(fromWallet, fromPassword, toAddress, amount) {
    try {
        console.log(`\n📤 Sending ${amount} tokens...`);
        console.log(`   From: ${fromWallet.address}`);
        console.log(`   To:   ${toAddress}`);

        // Login to wallet to get session
        const session = await ZKPWallet.login(fromWallet, fromPassword, L1_API_URL);
        
        if (!session || !session.isLocked === false) {
            throw new Error('Failed to create session');
        }

        // Create and sign transaction
        const tx = {
            from: fromWallet.address,
            to: toAddress,
            amount: amount,
            timestamp: Date.now(),
            nonce: Math.floor(Math.random() * 1000000)
        };

        const signature = session.signTransaction(tx);
        
        // Send transaction to L1
        const response = await fetch(`${L1_API_URL}/transaction`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                transaction: tx,
                signature: signature
            })
        });

        if (!response.ok) {
            const text = await response.text();
            throw new Error(`Transaction failed: ${response.status} - ${text}`);
        }

        const result = await response.json();
        console.log(`   ✅ Transaction successful!`);
        console.log(`   TX Hash: ${result.txHash || result.hash || 'N/A'}`);
        
        // Lock session
        session.lock();
        
        return true;
    } catch (error) {
        console.error(`   ❌ Transfer failed:`, error.message);
        return false;
    }
}

/**
 * Display all balances
 */
async function displayAllBalances(accounts) {
    console.log('\n' + '='.repeat(70));
    console.log('💰 ACCOUNT BALANCES');
    console.log('='.repeat(70));
    
    let totalBalance = 0;
    
    for (const account of accounts) {
        const walletData = loadWallet(account.file);
        const balance = await getBalance(walletData.address);
        
        if (balance !== null) {
            totalBalance += balance;
            console.log(`\n${account.name}:`);
            console.log(`  Address: ${walletData.address}`);
            console.log(`  Balance: ${balance.toLocaleString()} tokens`);
        }
    }
    
    console.log('\n' + '-'.repeat(70));
    console.log(`Total Balance Across All Accounts: ${totalBalance.toLocaleString()} tokens`);
    console.log('='.repeat(70) + '\n');
}

/**
 * Register wallet if not already registered
 */
async function ensureWalletRegistered(walletData, password) {
    try {
        // Check if already registered
        const checkResponse = await fetch(`${L1_API_URL}/auth/zkp-commitment/${walletData.address}`);
        if (checkResponse.ok) {
            return true; // Already registered
        }

        console.log(`📝 Registering ${walletData.address}...`);
        
        // Need to register - derive Share A from password
        const crypto = require('crypto');
        const argon2 = require('argon2');
        
        // Derive Share A (same as in SDK)
        const shareA = await argon2.hash(password, {
            type: argon2.argon2id,
            memoryCost: 65536,
            timeCost: 3,
            parallelism: 4,
            hashLength: 32,
            salt: Buffer.from(walletData.salt, 'hex')
        });

        // For registration, we need Share B (which we get from wallet creation)
        // But if wallet is already created, we need to reconstruct or use stored Share B
        console.log('⚠️  Wallet needs registration but Share B not available in file');
        console.log('    Attempting to register with available data...');
        
        const registerResponse = await fetch(`${L1_API_URL}/auth/zkp-register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                address: walletData.address,
                zkCommitment: walletData.zkCommitment,
                shareCEncrypted: walletData.shareCEncrypted,
                pubkey: walletData.pubkey
            })
        });

        if (registerResponse.ok) {
            console.log(`✅ Registration successful`);
            return true;
        } else {
            const text = await registerResponse.text();
            console.log(`⚠️  Registration response: ${registerResponse.status} - ${text}`);
            return false;
        }
    } catch (error) {
        console.error(`❌ Registration check failed:`, error.message);
        return false;
    }
}

/**
 * Main test function
 */
async function main() {
    console.log('\n' + '='.repeat(70));
    console.log('🚀 BlackBook L1 - Token Transfer Test');
    console.log('='.repeat(70));
    
    // Step 1: Check initial balances
    console.log('\n📊 Step 1: Initial Balances');
    await displayAllBalances(accounts);
    
    // Step 2: Ensure all wallets are registered
    console.log('\n🔐 Step 2: Ensuring Wallets Are Registered');
    for (const account of accounts) {
        const walletData = loadWallet(account.file);
        await ensureWalletRegistered(walletData, account.password);
    }
    
    // Step 3: Perform token transfers in a circular pattern
    console.log('\n💸 Step 3: Performing Token Transfers');
    console.log('Transfer Pattern: Alice → Bob → Mac → Apollo → Alice');
    
    const transferAmount = 100; // 100 tokens per transfer
    let successCount = 0;
    let totalTransfers = 0;
    
    // Alice → Bob
    totalTransfers++;
    const aliceWallet = loadWallet(accounts[0].file);
    const bobWallet = loadWallet(accounts[1].file);
    if (await sendTokens(aliceWallet, accounts[0].password, bobWallet.address, transferAmount)) {
        successCount++;
    }
    
    // Wait a bit between transactions
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Bob → Mac
    totalTransfers++;
    const macWallet = loadWallet(accounts[2].file);
    if (await sendTokens(bobWallet, accounts[1].password, macWallet.address, transferAmount)) {
        successCount++;
    }
    
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Mac → Apollo
    totalTransfers++;
    const apolloWallet = loadWallet(accounts[3].file);
    if (await sendTokens(macWallet, accounts[2].password, apolloWallet.address, transferAmount)) {
        successCount++;
    }
    
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Apollo → Alice
    totalTransfers++;
    if (await sendTokens(apolloWallet, accounts[3].password, aliceWallet.address, transferAmount)) {
        successCount++;
    }
    
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Additional cross transfers
    console.log('\n🔄 Additional Cross Transfers:');
    
    // Alice → Mac
    totalTransfers++;
    if (await sendTokens(aliceWallet, accounts[0].password, macWallet.address, 50)) {
        successCount++;
    }
    
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Bob → Apollo
    totalTransfers++;
    if (await sendTokens(bobWallet, accounts[1].password, apolloWallet.address, 50)) {
        successCount++;
    }
    
    console.log(`\n📈 Transfer Summary: ${successCount}/${totalTransfers} successful`);
    
    // Step 4: Check final balances
    console.log('\n📊 Step 4: Final Balances (after transfers)');
    await displayAllBalances(accounts);
    
    console.log('\n✅ Test Complete!\n');
}

// Run the test
main().catch(error => {
    console.error('\n❌ Test failed:', error);
    process.exit(1);
});
