/**
 * BlackBook L1 - Simple Token Transfer Test
 * Uses legacy private keys for Alice and Bob to test basic transfers
 */

const nacl = require('tweetnacl');
const crypto = require('crypto');

const L1_API_URL = 'http://localhost:8080';

// Test accounts with legacy private keys
const accounts = {
    alice: {
        name: 'Alice',
        address: 'L1_52882D768C0F3E7932AAD1813CF8B19058D507A8',
        publicKey: 'c0e349153cbc75e9529b5f1963205cab783463c6835c826a7587e0e0903c6705',
        privateKey: '18f2c2e3bcb7a4b5329cfed4bd79bf17df4d47aa1888a6b3d1a1450fb53a8a24'
    },
    bob: {
        name: 'Bob',
        address: 'L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433',
        publicKey: '582420216093fcff65b0eec2ca2c8227dfc2b6b7428110f36c3fc1349c4b2f5a',
        privateKey: 'e4ac49e5a04ef7dfc6e1a838fdf14597f2d514d0029a82cb45c916293487c25b'
    },
    dealer: {
        name: 'Dealer',
        address: 'L1_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D',
        publicKey: '07943256765557e704e4945aa4d1d56a1b0aac60bd8cc328faa99572aee5e84a'
    }
};

/**
 * Get balance for an address
 */
async function getBalance(address) {
    try {
        const response = await fetch(`${L1_API_URL}/balance/${address}`);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        const data = await response.json();
        return data.balance || 0;
    } catch (error) {
        console.error(`❌ Error getting balance for ${address}:`, error.message);
        return null;
    }
}

/**
 * Sign a transaction using Ed25519
 */
function signTransaction(privateKeyHex, payload, timestamp, nonce, chainId = 1) {
    // Convert private key from hex
    const privateKeyBytes = Buffer.from(privateKeyHex, 'hex');
    const keyPair = nacl.sign.keyPair.fromSeed(privateKeyBytes);
    
    // Build message: chain_id byte + payload + \n + timestamp + \n + nonce
    const chainIdByte = Buffer.from([chainId]);
    const payloadBytes = Buffer.from(payload, 'utf8');
    const timestampBytes = Buffer.from(timestamp.toString(), 'utf8');
    const nonceBytes = Buffer.from(nonce, 'utf8');
    
    const message = Buffer.concat([
        chainIdByte,
        payloadBytes,
        Buffer.from('\n'),
        timestampBytes,
        Buffer.from('\n'),
        nonceBytes
    ]);
    
    // Sign the message
    const signature = nacl.sign.detached(message, keyPair.secretKey);
    
    return Buffer.from(signature).toString('hex');
}

/**
 * Send tokens using simple transfer endpoint
 */
async function sendTokens(fromAccount, toAddress, amount) {
    try {
        console.log(`\n📤 Sending ${amount} tokens...`);
        console.log(`   From: ${fromAccount.name} (${fromAccount.address})`);
        console.log(`   To:   ${toAddress}`);
        
        const timestamp = Date.now();
        const nonce = crypto.randomBytes(16).toString('hex');
        const chainId = 1;
        
        // Create payload
        const payload = JSON.stringify({
            to: toAddress,
            amount: amount
        });
        
        // Sign transaction
        const signature = signTransaction(
            fromAccount.privateKey,
            payload,
            timestamp,
            nonce,
            chainId
        );
        
        // Send to L1
        const requestBody = {
            wallet_address: fromAccount.address,
            public_key: fromAccount.publicKey,
            payload: payload,
            signature: signature,
            timestamp: timestamp,
            nonce: nonce,
            chain_id: chainId,
            schema_version: 1
        };
        
        const response = await fetch(`${L1_API_URL}/transfer/simple`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestBody)
        });
        
        const contentType = response.headers.get('content-type');
        let result;
        
        if (contentType && contentType.includes('application/json')) {
            result = await response.json();
        } else {
            const text = await response.text();
            console.log(`   ⚠️  Response (${response.status}): ${text}`);
            return false;
        }
        
        if (!response.ok || !result.success) {
            console.log(`   ❌ Transfer failed: ${result.error || 'Unknown error'}`);
            return false;
        }
        
        console.log(`   ✅ Transfer successful!`);
        if (result.tx_hash || result.hash) {
            console.log(`   TX Hash: ${result.tx_hash || result.hash}`);
        }
        
        return true;
    } catch (error) {
        console.log(`   ❌ Transfer error:`, error.message);
        return false;
    }
}

/**
 * Display balances
 */
async function displayBalances(title) {
    console.log('\n' + '='.repeat(70));
    console.log(`💰 ${title}`);
    console.log('='.repeat(70));
    
    for (const [key, account] of Object.entries(accounts)) {
        const balance = await getBalance(account.address);
        if (balance !== null) {
            console.log(`\n${account.name}:`);
            console.log(`  Address: ${account.address}`);
            console.log(`  Balance: ${balance.toLocaleString()} tokens`);
        }
    }
    
    console.log('\n' + '='.repeat(70) + '\n');
}

/**
 * Main test
 */
async function main() {
    console.log('\n' + '='.repeat(70));
    console.log('🚀 BlackBook L1 - Simple Transfer Test');
    console.log('='.repeat(70));
    
    // Step 1: Check initial balances
    await displayBalances('INITIAL BALANCES');
    
    // Step 2: Perform transfers
    console.log('\n💸 PERFORMING TRANSFERS');
    console.log('━'.repeat(70));
    
    let successCount = 0;
    let totalTransfers = 0;
    
    // Alice → Bob (50 tokens)
    totalTransfers++;
    if (await sendTokens(accounts.alice, accounts.bob.address, 50)) {
        successCount++;
    }
    await new Promise(resolve => setTimeout(resolve, 500));
    
    // Bob → Alice (50 tokens)
    totalTransfers++;
    if (await sendTokens(accounts.bob, accounts.alice.address, 50)) {
        successCount++;
    }
    await new Promise(resolve => setTimeout(resolve, 500));
    
    // Alice → Dealer (50 tokens)
    totalTransfers++;
    if (await sendTokens(accounts.alice, accounts.dealer.address, 50)) {
        successCount++;
    }
    await new Promise(resolve => setTimeout(resolve, 500));
    
    console.log(`\n📊 Transfer Summary: ${successCount}/${totalTransfers} successful\n`);
    
    // Step 3: Check final balances
    await displayBalances('FINAL BALANCES');
    
    console.log('✅ Test Complete!\n');
}

// Run the test
main().catch(error => {
    console.error('\n❌ Test failed:', error);
    process.exit(1);
});
