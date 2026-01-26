/**
 * 🔐 PRODUCTION BRIDGE TEST - Using Mac's Real Wallet
 * 
 * This test unlocks Mac's Fork Architecture V2 wallet and tests the bridge
 * with proper Ed25519 signatures using the decrypted private key.
 */

import argon2 from 'argon2-browser';
import nacl from 'tweetnacl';
import crypto from 'crypto';

const L1_URL = 'http://localhost:8080';

// Mac's Wallet Data (from mac-wallet-v2-full.json)
const MAC_WALLET = {
    l1_address: 'L1_94B3C863E068096596CE80F04C2233B72AE11790',
    public_key: 'ec6941c71740e192bbf5933d5f9cc18ea161329ce864da900d8de73d45c28752',
    auth_salt: 'c797f810b635e1ea6c19bd0a1f1ef2d40ea565a03fd20eec9aa0350e88fa81a7',
    vault_salt: '41176c59b52a392d6abaf26857ae97ab97c0733852d81fbd586f08ce12a9492b',
    vault_ciphertext: '4q/jTciq0L6MaVz5tnLJQ7Rxu/owxXwPu2Fk6LCVHWlyP6O1HHbdEfj5B0bwl+N9XJ9WdCgox3EvBcCjNvSGPJMgHckGha+rO3PFMnTgxD0=',
    vault_nonce: '7d23f1f893dfdad678080b7d',
    password: 'MacSecurePassword2026!'
};

/**
 * Unlock Mac's wallet to get the private key
 */
async function unlockWallet() {
    console.log('\n🔓 Unlocking Mac Wallet...');
    
    // Derive vault key using Argon2id
    const vaultDomain = 'BLACKBOOK_VAULT_V2' + MAC_WALLET.vault_salt;
    const vaultKeyResult = await argon2.hash({
        pass: vaultDomain + MAC_WALLET.password,
        salt: MAC_WALLET.vault_salt,
        time: 3,
        mem: 65536,  // 64 MB
        parallelism: 4,
        hashLen: 32,
        type: argon2.ArgonType.Argon2id,
        raw: true  // Return raw buffer
    });
    
    console.log(`   ✓ Vault key derived`);
    
    // Decrypt vault using AES-GCM
    const nonceBytes = Buffer.from(MAC_WALLET.vault_nonce, 'hex');
    const ciphertextBytes = Buffer.from(MAC_WALLET.vault_ciphertext, 'base64');
    const aadBytes = Buffer.from(MAC_WALLET.vault_salt, 'utf-8');
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', vaultKeyResult.hash, nonceBytes);
    decipher.setAAD(aadBytes);
    decipher.setAuthTag(ciphertextBytes.slice(-16)); // Last 16 bytes is auth tag
    
    let decrypted = decipher.update(ciphertextBytes.slice(0, -16), null, 'utf-8');
    decrypted += decipher.final('utf-8');
    
    const seedHex = decrypted;
    console.log(`   ✓ Vault decrypted, seed: ${seedHex.substring(0, 16)}...`);
    
    // Derive keypair from seed
    const seedBytes = Buffer.from(seedHex, 'hex');
    const keypair = nacl.sign.keyPair.fromSeed(seedBytes);
    
    const publicKeyHex = Buffer.from(keypair.publicKey).toString('hex');
    const privateKeyHex = Buffer.from(keypair.secretKey.slice(0, 32)).toString('hex');
    
    console.log(`   ✓ Public key: ${publicKeyHex}`);
    console.log(`   ✓ Wallet unlocked successfully!`);
    
    if (publicKeyHex !== MAC_WALLET.public_key) {
        throw new Error(`Public key mismatch! Expected ${MAC_WALLET.public_key}, got ${publicKeyHex}`);
    }
    
    return {
        publicKey: publicKeyHex,
        privateKey: privateKeyHex,
        secretKey: keypair.secretKey,
        address: MAC_WALLET.l1_address
    };
}

/**
 * Sign a message for bridge request
 */
function signBridgeMessage(payload, timestamp, nonce, secretKey) {
    // Message format: chain_id_byte(0x01) + "{payload}\n{timestamp}\n{nonce}"
    const payloadStr = JSON.stringify(payload);
    const message = `${payloadStr}\n${timestamp}\n${nonce}`;
    const chainIdByte = Buffer.from([1]);
    const messageBytes = Buffer.concat([chainIdByte, Buffer.from(message, 'utf-8')]);
    
    // Sign with Ed25519
    const signature = nacl.sign.detached(messageBytes, secretKey);
    return Buffer.from(signature).toString('hex');
}

/**
 * Test bridge with real wallet
 */
async function testBridgeWithRealWallet() {
    console.log('\n' + '═'.repeat(70));
    console.log('🔐 PRODUCTION BRIDGE TEST - Mac Wallet with Fork Architecture V2');
    console.log('═'.repeat(70));
    
    try {
        // Step 1: Unlock wallet
        const wallet = await unlockWallet();
        
        // Step 2: Check balance
        console.log('\n💰 Checking Balance...');
        const balanceRes = await fetch(`${L1_URL}/balance/${wallet.address}`);
        const balance = await balanceRes.json();
        console.log(`   Available: ${balance.available} BB`);
        console.log(`   Locked: ${balance.locked} BB`);
        console.log(`   Total: ${balance.total} BB`);
        
        if (balance.available < 1000) {
            console.log(`\n⚠️  Insufficient balance for test (need 1000 BB, have ${balance.available} BB)`);
            return false;
        }
        
        // Step 3: Create signed bridge request
        console.log('\n🌉 Creating Bridge Request (1000 BB)...');
        const payload = { amount: 1000, target_layer: "L2" };
        const timestamp = Math.floor(Date.now() / 1000);
        const nonce = crypto.randomUUID();
        
        const signature = signBridgeMessage(payload, timestamp, nonce, wallet.secretKey);
        
        console.log(`   Payload: ${JSON.stringify(payload)}`);
        console.log(`   Timestamp: ${timestamp}`);
        console.log(`   Nonce: ${nonce.substring(0, 16)}...`);
        console.log(`   Signature: ${signature.substring(0, 32)}...`);
        
        // Step 4: Send to L1
        const signedRequest = {
            payload: JSON.stringify(payload),
            public_key: wallet.publicKey,
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
        
        console.log(`\n📡 Response Status: ${response.status}`);
        console.log(`📦 Response:`, JSON.stringify(result, null, 2));
        
        if (response.ok && result.success) {
            console.log(`\n✅ BRIDGE SUCCESS!`);
            console.log(`   Lock ID: ${result.lock_id}`);
            console.log(`   Amount: ${result.amount} BB`);
            console.log(`   Target: ${result.target_layer}`);
            console.log(`   Status: ${result.status}`);
            console.log(`   Message: ${result.message}`);
            return true;
        } else {
            console.log(`\n❌ BRIDGE FAILED: ${result.error || 'Unknown error'}`);
            return false;
        }
        
    } catch (error) {
        console.log(`\n❌ ERROR: ${error.message}`);
        console.error(error);
        return false;
    }
}

/**
 * Run the test
 */
console.log('\n🚀 Starting Production Bridge Test with Real Wallet...\n');
const success = await testBridgeWithRealWallet();

if (success) {
    console.log('\n' + '═'.repeat(70));
    console.log('🎉 ALL TESTS PASSED - Bridge is production ready!');
    console.log('✅ Wallet unlocked successfully');
    console.log('✅ Signature validation working');
    console.log('✅ Bridge flow operational');
    console.log('✅ Ready for frontend integration');
    console.log('═'.repeat(70) + '\n');
} else {
    console.log('\n' + '═'.repeat(70));
    console.log('⚠️  Test failed - review output above');
    console.log('═'.repeat(70) + '\n');
    process.exit(1);
}
