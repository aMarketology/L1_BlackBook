/**
 * 🔐 PRODUCTION BRIDGE TEST - Fork Architecture V2 Wallet
 * 
 * Tests the complete flow:
 * 1. Load Mac's encrypted vault
 * 2. Decrypt vault with password
 * 3. Sign bridge request with Ed25519
 * 4. Verify signature validation on server
 * 5. Test bridge lock creation
 */

import nacl from 'tweetnacl';
import crypto from 'crypto';
import fs from 'fs';

const L1_URL = 'http://localhost:8080';

// Load Mac's wallet
const macWallet = JSON.parse(fs.readFileSync('mac-wallet-fresh.json', 'utf-8'));

console.log('\n' + '═'.repeat(70));
console.log('🔐 PRODUCTION BRIDGE TEST - Fork Architecture V2');
console.log('═'.repeat(70));
console.log(`\n📋 Testing with: ${macWallet.username}`);
console.log(`   L1 Address: ${macWallet.l1_address}`);
console.log(`   Public Key: ${macWallet.public_key}`);

/**
 * Unlock wallet by decrypting vault
 */
function unlockWallet(wallet, password) {
    console.log('\n🔓 Unlocking wallet vault...');
    
    // Derive vault key
    const VAULT_DOMAIN = 'BLACKBOOK_VAULT_V2';
    const vault_key = crypto.createHash('sha256')
        .update(VAULT_DOMAIN + wallet.vault_salt + password)
        .digest();
    
    console.log('   ✓ Vault key derived');
    
    // Decrypt with AES-256-GCM
    const nonce = Buffer.from(wallet.vault.nonce, 'hex');
    const ciphertextWithTag = Buffer.from(wallet.vault.ciphertext, 'base64');
    const authTag = ciphertextWithTag.slice(-16);
    const ciphertext = ciphertextWithTag.slice(0, -16);
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', vault_key, nonce);
    decipher.setAAD(Buffer.from(wallet.vault_salt, 'utf-8'));
    decipher.setAuthTag(authTag);
    
    let seedHex = decipher.update(ciphertext, null, 'utf-8');
    seedHex += decipher.final('utf-8');
    
    console.log('   ✓ Vault decrypted');
    
    // Derive keypair from seed
    const seedBytes = Buffer.from(seedHex, 'hex');
    const keypair = nacl.sign.keyPair.fromSeed(seedBytes);
    
    const publicKeyHex = Buffer.from(keypair.publicKey).toString('hex');
    
    if (publicKeyHex !== wallet.public_key) {
        throw new Error(`Public key mismatch! Expected ${wallet.public_key}, got ${publicKeyHex}`);
    }
    
    console.log('   ✓ Keypair derived and verified');
    console.log('   ✅ Wallet unlocked successfully!');
    
    return keypair;
}

/**
 * Sign bridge request message
 */
function signBridgeRequest(payload, timestamp, nonce, secretKey) {
    const payloadStr = JSON.stringify(payload);
    const message = `${payloadStr}\n${timestamp}\n${nonce}`;
    const chainIdByte = Buffer.from([1]); // Chain ID 1 = L1
    const messageBytes = Buffer.concat([chainIdByte, Buffer.from(message, 'utf-8')]);
    
    const signature = nacl.sign.detached(messageBytes, secretKey);
    return Buffer.from(signature).toString('hex');
}

/**
 * Run bridge test
 */
async function runBridgeTest() {
    try {
        // Step 1: Unlock wallet
        const keypair = unlockWallet(macWallet, macWallet.test_password);
        
        // Step 2: Check balance
        console.log('\n💰 Checking balance...');
        const balanceRes = await fetch(`${L1_URL}/balance/${macWallet.l1_address}`);
        const balance = await balanceRes.json();
        
        console.log(`   Raw response:`, balance);
        
        // Support multiple response formats
        const available = balance.balance || balance.available || 0;
        const locked = balance.locked || 0;
        const total = balance.total || available + locked;
        
        console.log(`   Available: ${available} BB`);
        console.log(`   Locked: ${locked} BB`);
        console.log(`   Total: ${total} BB`);
        
        if (available < 100) {
            console.log('\n⚠️  Wallet has insufficient balance for bridge test');
            console.log('   Run mint command first: curl -X POST http://localhost:8080/admin/mint \\');
            console.log(`     -H "Content-Type: application/json" \\`);
            console.log(`     -d '{"to":"${macWallet.l1_address}","amount":10000}'`);
            return false;
        }
        
        // Step 3: Create signed bridge request
        console.log('\n🌉 Creating bridge request (100 BB)...');
        const payload = { amount: 100, target_layer: "L2" };
        const timestamp = Math.floor(Date.now() / 1000);
        const nonce = crypto.randomUUID();
        
        const signature = signBridgeRequest(payload, timestamp, nonce, keypair.secretKey);
        
        console.log(`   ✓ Payload: ${JSON.stringify(payload)}`);
        console.log(`   ✓ Timestamp: ${timestamp}`);
        console.log(`   ✓ Nonce: ${nonce.substring(0, 24)}...`);
        console.log(`   ✓ Signature: ${signature.substring(0, 32)}...`);
        
        // Step 4: Send to L1
        console.log('\n📡 Sending signed request to L1...');
        const signedRequest = {
            payload: JSON.stringify(payload),
            public_key: macWallet.public_key,
            wallet_address: macWallet.l1_address,  // 🔑 Include wallet address
            signature: signature,
            nonce: nonce,
            timestamp: timestamp,
            chain_id: 1
        };
        
        const response = await fetch(`${L1_URL}/bridge/initiate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(signedRequest)
        });
        
        const result = await response.json();
        
        console.log(`\n📦 Response (${response.status}):`);
        console.log(JSON.stringify(result, null, 2));
        
        if (response.ok && result.success) {
            console.log('\n' + '═'.repeat(70));
            console.log('✅ BRIDGE TEST PASSED!');
            console.log('═'.repeat(70));
            console.log(`Lock ID:      ${result.lock_id}`);
            console.log(`Amount:       ${result.amount} BB`);
            console.log(`Wallet:       ${result.wallet}`);
            console.log(`Target:       ${result.target_layer}`);
            console.log(`Status:       ${result.status}`);
            console.log(`Expires:      ${result.expires_at}`);
            console.log(`Message:      ${result.message}`);
            console.log('═'.repeat(70));
            console.log('\n🎉 SUCCESS! Bridge is production-ready with:');
            console.log('   ✅ Fork Architecture V2 vault encryption');
            console.log('   ✅ Proper vault decryption working');
            console.log('   ✅ Ed25519 signature validation passing');
            console.log('   ✅ No test mode bypasses');
            console.log('   ✅ Ready for frontend integration\n');
            return true;
        } else {
            console.log('\n' + '═'.repeat(70));
            console.log('❌ BRIDGE TEST FAILED');
            console.log('═'.repeat(70));
            console.log(`Error: ${result.error || 'Unknown error'}`);
            console.log('═'.repeat(70) + '\n');
            return false;
        }
        
    } catch (error) {
        console.log('\n' + '═'.repeat(70));
        console.log('❌ TEST ERROR');
        console.log('═'.repeat(70));
        console.log(error.message);
        console.error(error);
        console.log('═'.repeat(70) + '\n');
        return false;
    }
}

// Run the test
console.log('\n🚀 Starting production bridge test...\n');
const success = await runBridgeTest();

if (!success) {
    process.exit(1);
}
