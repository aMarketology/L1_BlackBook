/**
 * Test Mac → Bob Transfer with New Wallet V2
 */

import nacl from 'tweetnacl';
import argon2 from 'argon2';
import crypto from 'crypto';
import fs from 'fs';

const MAC_WALLET_V2 = JSON.parse(fs.readFileSync('mac-wallet-v2-full.json', 'utf8'));
const PASSWORD = 'MacSecurePassword2026!';
const L1_URL = 'http://127.0.0.1:8080';

const BOB = {
    address: 'L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433'
};

const VAULT_FORK_DOMAIN = "BLACKBOOK_VAULT_V2";
const ARGON2_CONFIG = {
  type: argon2.argon2id,
  timeCost: 3,
  memoryCost: 65536,
  parallelism: 4,
  hashLength: 32
};

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

async function unlockWallet() {
    const vaultDomain = VAULT_FORK_DOMAIN + MAC_WALLET_V2.vault_salt;
    const vaultKeyHash = await argon2.hash(
        Buffer.from(vaultDomain + PASSWORD),
        {
            ...ARGON2_CONFIG,
            salt: Buffer.from(MAC_WALLET_V2.vault_salt, 'hex'),
            raw: true
        }
    );
    
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        vaultKeyHash,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
    );
    
    const encoder = new TextEncoder();
    const aad = encoder.encode(MAC_WALLET_V2.vault_salt);
    const nonceBytes = hexToBytes(MAC_WALLET_V2.vault.nonce);
    const ciphertextBytes = Buffer.from(MAC_WALLET_V2.vault.ciphertext, 'base64');
    
    const decrypted = await crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: nonceBytes,
            additionalData: aad
        },
        cryptoKey,
        ciphertextBytes
    );
    
    const seedHex = new TextDecoder().decode(decrypted);
    const seedBytes = hexToBytes(seedHex);
    return nacl.sign.keyPair.fromSeed(seedBytes);
}

async function sendTokens() {
    console.log('╔══════════════════════════════════════════════════════════════╗');
    console.log('║            MAC → BOB TRANSFER TEST (V2 Wallet)              ║');
    console.log('╚══════════════════════════════════════════════════════════════╝\n');
    
    try {
        // 1. Unlock Mac's wallet
        console.log('🔓 Unlocking Mac\'s V2 wallet...');
        const keypair = await unlockWallet();
        console.log('✓ Wallet unlocked\n');
        
        // 2. Check balances before
        console.log('💰 Checking balances...');
        const macBefore = await fetch(`${L1_URL}/balance/${MAC_WALLET_V2.l1_address}`).then(r => r.json());
        const bobBefore = await fetch(`${L1_URL}/balance/${BOB.address}`).then(r => r.json());
        
        console.log(`  Mac: ${macBefore.balance} BB`);
        console.log(`  Bob: ${bobBefore.balance} BB\n`);
        
        // 3. Send 1 BB from Mac to Bob
        console.log('📤 Sending 1 BB from Mac to Bob...');
        
        const timestamp = Math.floor(Date.now() / 1000);
        const nonce = crypto.randomUUID();
        
        // Create payload hash for V2 canonical format
        const payloadFields = {
            from: MAC_WALLET_V2.l1_address,
            to: BOB.address,
            amount: 1.0,
            timestamp,
            nonce
        };
        
        // Canonical order: from|to|amount|timestamp|nonce
        const canonicalString = `${payloadFields.from}|${payloadFields.to}|${payloadFields.amount}|${timestamp}|${nonce}`;
        const encoder = new TextEncoder();
        const canonicalBytes = encoder.encode(canonicalString);
        const hashBuffer = await crypto.subtle.digest('SHA-256', canonicalBytes);
        const payloadHash = bytesToHex(new Uint8Array(hashBuffer));
        
        // Sign: BLACKBOOK_L1/transfer + payload_hash + timestamp + nonce
        const domainPrefix = 'BLACKBOOK_L1/transfer';
        const messageStr = `${domainPrefix}\n${payloadHash}\n${timestamp}\n${nonce}`;
        const messageBytes = encoder.encode(messageStr);
        
        const signature = nacl.sign.detached(messageBytes, keypair.secretKey);
        
        const response = await fetch(`${L1_URL}/transfer`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                public_key: MAC_WALLET_V2.public_key,
                payload_hash: payloadHash,
                payload_fields: payloadFields,
                operation_type: 'transfer',
                schema_version: 2,
                timestamp,
                nonce,
                chain_id: 1,
                request_path: '/transfer',
                signature: bytesToHex(signature)
            })
        });
        
        const responseText = await response.text();
        console.log('  Response:', responseText.substring(0, 200));
        
        let result;
        try {
            result = JSON.parse(responseText);
        } catch (e) {
            throw new Error(`Failed to parse response: ${responseText.substring(0, 100)}`);
        }
        
        if (result.status === 'success') {
            console.log('✅ Transfer successful!\n');
            
            // 4. Check balances after
            console.log('💰 Checking balances after transfer...');
            const macAfter = await fetch(`${L1_URL}/balance/${MAC_WALLET_V2.l1_address}`).then(r => r.json());
            const bobAfter = await fetch(`${L1_URL}/balance/${BOB.address}`).then(r => r.json());
            
            console.log(`  Mac: ${macAfter.balance} BB (was ${macBefore.balance})`);
            console.log(`  Bob: ${bobAfter.balance} BB (was ${bobBefore.balance})`);
            
            console.log('\n╔══════════════════════════════════════════════════════════════╗');
            console.log('║                 ✅ TRANSFER TEST PASSED                      ║');
            console.log('╚══════════════════════════════════════════════════════════════╝');
            
        } else {
            console.error('❌ Transfer failed:', result.message);
        }
        
    } catch (error) {
        console.error('❌ Error:', error.message);
        process.exit(1);
    }
}

sendTokens();
