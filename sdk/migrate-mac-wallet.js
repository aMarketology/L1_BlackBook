/**
 * Mac Wallet Migration Script
 * 
 * Migrates Mac's wallet from:
 *   OLD: CryptoJS AES-CBC with PBKDF2
 *   NEW: Web Crypto AES-GCM with Argon2id (Fork Architecture V2)
 * 
 * Run: node migrate-mac-wallet.js
 */

import nacl from 'tweetnacl';
import CryptoJS from 'crypto-js';
import argon2 from 'argon2';
import crypto from 'crypto';
import fs from 'fs';

// ═══════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════

const AUTH_FORK_DOMAIN = "BLACKBOOK_AUTH_V2";
const VAULT_FORK_DOMAIN = "BLACKBOOK_VAULT_V2";

const ARGON2_CONFIG = {
  type: argon2.argon2id,
  timeCost: 3,
  memoryCost: 65536,  // 64 MB
  parallelism: 4,
  hashLength: 32
};

// ═══════════════════════════════════════════════════════════════
// OLD MAC WALLET DATA (CryptoJS format)
// ═══════════════════════════════════════════════════════════════

const OLD_MAC_WALLET = {
    username: 'mac_blackbook',
    email: 'mac@blackbook.io',
    l1_address: 'L1_94B3C863E068096596CE80F04C2233B72AE11790',
    public_key: 'ec6941c71740e192bbf5933d5f9cc18ea161329ce864da900d8de73d45c28752',
    password: 'MacSecurePassword2026!',
    vault: {
        salt: '579a5c28a02f8c3ecc2801545a216cec',
        encrypted_blob: 'U2FsdGVkX19443Y8LJ1PaUV6/aG4Ctod88tWo7AVDftZlcgWurkSGAhVEAScVQ91+Ew9iP0d588HfIUYlXQPGEmIMDhjj3M6cDPbDtnTZFh848l0Z71CjV0CpB41Avad',
        algorithm: 'AES-256-CBC',
        kdf: 'PBKDF2',
        kdf_iterations: 100000
    }
};

// ═══════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════

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

async function sha256(data) {
    const encoder = new TextEncoder();
    const dataBuffer = typeof data === 'string' ? encoder.encode(data) : data;
    const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
    return bytesToHex(new Uint8Array(hashBuffer));
}

function deriveL1Address(publicKey) {
    const pubKeyHex = Buffer.from(publicKey).toString('hex');
    const hash = CryptoJS.SHA256(pubKeyHex).toString();
    const addressBytes = hash.substring(0, 40).toUpperCase();
    return `L1_${addressBytes}`;
}

// ═══════════════════════════════════════════════════════════════
// STEP 1: DECRYPT OLD VAULT (CryptoJS PBKDF2)
// ═══════════════════════════════════════════════════════════════

function decryptOldVault(vault, password) {
    console.log('📖 Decrypting OLD vault (CryptoJS PBKDF2 + AES-CBC)...');
    
    // Derive encryption key using PBKDF2
    const encryptionKey = CryptoJS.PBKDF2(password, vault.salt, {
        keySize: 256 / 32,
        iterations: 100000,
        hasher: CryptoJS.algo.SHA256
    });
    
    // Decrypt the vault
    const decrypted = CryptoJS.AES.decrypt(
        vault.encrypted_blob,
        encryptionKey.toString()
    );
    
    const seedHex = decrypted.toString(CryptoJS.enc.Utf8);
    
    if (!seedHex || seedHex.length !== 64) {
        throw new Error('Decryption failed - invalid seed recovered');
    }
    
    console.log('   ✓ Seed recovered (32 bytes)');
    return seedHex;
}

// ═══════════════════════════════════════════════════════════════
// STEP 2: FORK PASSWORD (Auth + Vault Keys)
// ═══════════════════════════════════════════════════════════════

async function forkPassword(password, authSalt, vaultSalt) {
    console.log('\n🔱 Forking password into auth_key and vault_key...');
    
    // FORK A: Auth Key (SHA256 - for server authentication)
    const authDomain = AUTH_FORK_DOMAIN + authSalt;
    const authKey = await sha256(authDomain + password);
    console.log('   ✓ auth_key derived (SHA256)');
    
    // FORK B: Vault Key (Argon2id - for vault encryption)
    // Use raw:true to get the raw hash bytes instead of encoded string
    const vaultDomain = VAULT_FORK_DOMAIN + vaultSalt;
    const vaultKeyHash = await argon2.hash(Buffer.from(vaultDomain + password), {
        ...ARGON2_CONFIG,
        salt: Buffer.from(vaultSalt, 'hex'),
        raw: true  // Return raw hash buffer
    });
    
    console.log('   ✓ vault_key derived (Argon2id, 64MB, 3 iterations)');
    console.log('   ✓ vault_key type:', typeof vaultKeyHash, 'is Buffer:', Buffer.isBuffer(vaultKeyHash));
    
    return {
        authKey,
        vaultKey: vaultKeyHash  // Return the raw hash buffer
    };
}

// ═══════════════════════════════════════════════════════════════
// STEP 3: ENCRYPT NEW VAULT (AES-GCM)
// ═══════════════════════════════════════════════════════════════

async function encryptNewVault(seedHex, vaultKey, vaultSalt) {
    console.log('\n🔐 Encrypting NEW vault (AES-256-GCM)...');
    console.log('   ✓ vaultKey type:', typeof vaultKey, 'length:', vaultKey.length);
    
    // Generate nonce (12 bytes for GCM)
    const nonce = crypto.randomBytes(12);
    
    // The argon2 library returns a hex string - convert to Buffer
    const keyBuffer = Buffer.isBuffer(vaultKey) ? vaultKey : Buffer.from(vaultKey, 'hex');
    console.log('   ✓ keyBuffer length:', keyBuffer.length, 'bytes');
    
    // Import vault key for Web Crypto API
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        keyBuffer,
        { name: 'AES-GCM' },
        false,
        ['encrypt']
    );
    
    // Encrypt with vault_salt in AAD (Additional Authenticated Data)
    const encoder = new TextEncoder();
    const seedBytes = encoder.encode(seedHex);
    const aad = encoder.encode(vaultSalt);
    
    const ciphertext = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: nonce,
            additionalData: aad
        },
        cryptoKey,
        seedBytes
    );
    
    const ciphertextBase64 = Buffer.from(ciphertext).toString('base64');
    const nonceHex = bytesToHex(nonce);
    
    console.log('   ✓ Vault encrypted with AES-GCM');
    console.log('   ✓ Nonce: ' + nonceHex);
    
    return {
        ciphertext: ciphertextBase64,
        nonce: nonceHex
    };
}

// ═══════════════════════════════════════════════════════════════
// MAIN MIGRATION
// ═══════════════════════════════════════════════════════════════

async function migrateMacWallet() {
    console.log('╔══════════════════════════════════════════════════════════════╗');
    console.log('║        MAC WALLET MIGRATION: CryptoJS → AES-GCM V2          ║');
    console.log('╚══════════════════════════════════════════════════════════════╝\n');
    
    try {
        // STEP 1: Decrypt old vault
        const seedHex = decryptOldVault(OLD_MAC_WALLET.vault, OLD_MAC_WALLET.password);
        
        // Verify seed produces correct public key
        const seedBytes = hexToBytes(seedHex);
        const keypair = nacl.sign.keyPair.fromSeed(seedBytes);
        const publicKeyHex = bytesToHex(keypair.publicKey);
        const derivedAddress = deriveL1Address(keypair.publicKey);
        
        if (publicKeyHex !== OLD_MAC_WALLET.public_key) {
            throw new Error('Public key mismatch! Decryption failed.');
        }
        if (derivedAddress !== OLD_MAC_WALLET.l1_address) {
            throw new Error('Address mismatch! Decryption failed.');
        }
        
        console.log('   ✓ Public key verified: ' + publicKeyHex.substring(0, 16) + '...');
        console.log('   ✓ Address verified: ' + derivedAddress);
        
        // STEP 2: Generate new salts for Fork Architecture
        console.log('\n🧂 Generating new salts for Fork Architecture V2...');
        const authSalt = bytesToHex(crypto.randomBytes(32));
        const vaultSalt = bytesToHex(crypto.randomBytes(32));
        console.log('   ✓ auth_salt: ' + authSalt.substring(0, 32) + '...');
        console.log('   ✓ vault_salt: ' + vaultSalt.substring(0, 32) + '...');
        
        // STEP 3: Fork password
        const forkedKeys = await forkPassword(
            OLD_MAC_WALLET.password,
            authSalt,
            vaultSalt
        );
        
        // STEP 4: Encrypt with new format
        const { ciphertext, nonce } = await encryptNewVault(
            seedHex,
            forkedKeys.vaultKey,
            vaultSalt
        );
        
        // STEP 5: Build new wallet structure
        const newWallet = {
            // Identity
            username: OLD_MAC_WALLET.username,
            email: OLD_MAC_WALLET.email,
            
            // Public blockchain data
            l1_address: OLD_MAC_WALLET.l1_address,
            l2_address: OLD_MAC_WALLET.l1_address.replace('L1_', 'L2_'),
            public_key: OLD_MAC_WALLET.public_key,
            
            // Fork Architecture V2
            auth_salt: authSalt,
            vault_salt: vaultSalt,
            
            // NEW: AES-GCM vault (with nonce!)
            vault: {
                version: 2,
                algorithm: 'AES-256-GCM',
                kdf: 'Argon2id',
                kdf_params: {
                    time_cost: 3,
                    memory_cost: 65536,  // 64 MB
                    parallelism: 4,
                    hash_length: 32
                },
                ciphertext: ciphertext,
                nonce: nonce,
                created_at: new Date().toISOString()
            },
            
            // For server authentication (server stores bcrypt(auth_key))
            auth_key: forkedKeys.authKey,
            
            // Metadata
            fork_version: 2,
            migrated_at: new Date().toISOString(),
            migrated_from: 'cryptojs_pbkdf2'
        };
        
        // STEP 6: Test decryption
        console.log('\n🧪 Testing NEW vault decryption...');
        await testDecryption(newWallet, seedHex);
        
        // STEP 7: Generate output files
        console.log('\n💾 Generating output files...');
        
        // Save full wallet data (for database)
        fs.writeFileSync(
            'mac-wallet-v2-full.json',
            JSON.stringify(newWallet, null, 2)
        );
        console.log('   ✓ Saved: mac-wallet-v2-full.json');
        
        // Save vault only (what goes in database)
        const vaultRecord = {
            username: newWallet.username,
            email: newWallet.email,
            l1_address: newWallet.l1_address,
            l2_address: newWallet.l2_address,
            public_key: newWallet.public_key,
            auth_salt: newWallet.auth_salt,
            vault_salt: newWallet.vault_salt,
            vault_ciphertext: newWallet.vault.ciphertext,
            vault_nonce: newWallet.vault.nonce,
            vault_version: 2,
            created_at: newWallet.vault.created_at
        };
        
        fs.writeFileSync(
            'mac-wallet-v2-vault.json',
            JSON.stringify(vaultRecord, null, 2)
        );
        console.log('   ✓ Saved: mac-wallet-v2-vault.json');
        
        // Update macwallet.txt
        generateMacWalletTxt(newWallet);
        
        console.log('\n╔══════════════════════════════════════════════════════════════╗');
        console.log('║                    ✅ MIGRATION SUCCESSFUL                    ║');
        console.log('╚══════════════════════════════════════════════════════════════╝\n');
        
        console.log('📋 NEXT STEPS:\n');
        console.log('1. Review mac-wallet-v2-full.json');
        console.log('2. Update your database with mac-wallet-v2-vault.json');
        console.log('3. Review updated macwallet.txt');
        console.log('4. Test with your frontend using AES-GCM decryption');
        console.log('\n⚠️  IMPORTANT: Keep the password secure: ' + OLD_MAC_WALLET.password);
        console.log('⚠️  IMPORTANT: Store auth_key_hash = bcrypt(auth_key) on server\n');
        
        return newWallet;
        
    } catch (error) {
        console.error('\n❌ MIGRATION FAILED:', error.message);
        console.error(error.stack);
        process.exit(1);
    }
}

// ═══════════════════════════════════════════════════════════════
// TEST DECRYPTION
// ═══════════════════════════════════════════════════════════════

async function testDecryption(newWallet, originalSeedHex) {
    // Re-derive vault key from password
    const vaultDomain = VAULT_FORK_DOMAIN + newWallet.vault_salt;
    const vaultKeyHash = await argon2.hash(
        Buffer.from(vaultDomain + OLD_MAC_WALLET.password),
        {
            ...ARGON2_CONFIG,
            salt: Buffer.from(newWallet.vault_salt, 'hex'),
            raw: true  // Get raw hash buffer
        }
    );
    
    // Ensure we have a Buffer
    const vaultKeyBuffer = Buffer.isBuffer(vaultKeyHash) ? vaultKeyHash : Buffer.from(vaultKeyHash);
    
    // Import key
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        vaultKeyBuffer,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
    );
    
    // Decrypt
    const encoder = new TextEncoder();
    const aad = encoder.encode(newWallet.vault_salt);
    const nonceBytes = hexToBytes(newWallet.vault.nonce);
    const ciphertextBytes = Buffer.from(newWallet.vault.ciphertext, 'base64');
    
    const decrypted = await crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: nonceBytes,
            additionalData: aad
        },
        cryptoKey,
        ciphertextBytes
    );
    
    const recoveredSeed = new TextDecoder().decode(decrypted);
    
    if (recoveredSeed !== originalSeedHex) {
        throw new Error('Decryption test failed - seed mismatch!');
    }
    
    console.log('   ✓ Decryption test PASSED');
    console.log('   ✓ Seed matches original');
}

// ═══════════════════════════════════════════════════════════════
// GENERATE UPDATED MACWALLET.TXT
// ═══════════════════════════════════════════════════════════════

function generateMacWalletTxt(newWallet) {
    const content = `╔══════════════════════════════════════════════════════════════════════════════╗
║                      MAC'S BLACKBOOK WALLET - V2 (MIGRATED)                  ║
║                      Fork Architecture with AES-GCM Encryption                ║
╚══════════════════════════════════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📋 WALLET IDENTIFICATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

L1 Address:       ${newWallet.l1_address}
L2 Address:       ${newWallet.l2_address}
Public Key:       ${newWallet.public_key}

Username:         ${newWallet.username}
Email:            ${newWallet.email}
Created:          ${newWallet.vault.created_at}
Migrated:         ${newWallet.migrated_at}
Chain:            BlackBook L1
Curve:            Ed25519


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔐 FORK ARCHITECTURE V2 (AES-GCM VAULT)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Auth Salt:        ${newWallet.auth_salt}
Vault Salt:       ${newWallet.vault_salt}

Vault Algorithm:  ${newWallet.vault.algorithm}
Vault KDF:        ${newWallet.vault.kdf}
KDF Memory:       64 MB
KDF Iterations:   3
KDF Parallelism:  4

Ciphertext:       ${newWallet.vault.ciphertext.substring(0, 64)}...
Nonce:            ${newWallet.vault.nonce}

⚠️ TEST PASSWORD:  MacSecurePassword2026!
   (In production, user provides their own secure password)


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔑 FORK ARCHITECTURE - How It Works
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

USER ENTERS PASSWORD → SPLIT INTO TWO KEYS:

1. AUTH KEY (for server authentication):
   auth_key = SHA256(AUTH_DOMAIN + auth_salt + password)
   → Sent to server (server stores bcrypt(auth_key))
   → Used for login authentication only

2. VAULT KEY (for vault decryption):
   vault_key = Argon2id(VAULT_DOMAIN + vault_salt + password)
   → NEVER sent to server
   → Stays in browser/client
   → Used to decrypt vault

SERVER CANNOT DECRYPT VAULT because:
- Server only has bcrypt(auth_key), not auth_key itself
- Server never receives vault_key
- Vault key is derived with different domain separator


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
💡 DECRYPTION CODE (Frontend)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// Import required libraries
import argon2 from 'argon2-browser';

async function unlockMacWallet(password, vaultData) {
    // Step 1: Derive vault key from password
    const vaultDomain = "BLACKBOOK_VAULT_V2" + vaultData.vault_salt;
    const vaultKeyResult = await argon2.hash({
        pass: vaultDomain + password,
        salt: vaultData.vault_salt,
        time: 3,
        mem: 65536,  // 64 MB
        parallelism: 4,
        hashLen: 32,
        type: argon2.ArgonType.Argon2id
    });
    
    // Step 2: Import key for Web Crypto API
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        vaultKeyResult.hash,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
    );
    
    // Step 3: Decrypt vault
    const encoder = new TextEncoder();
    const aad = encoder.encode(vaultData.vault_salt);
    const nonceBytes = hexToBytes(vaultData.vault_nonce);
    const ciphertextBytes = Uint8Array.from(
        atob(vaultData.vault_ciphertext),
        c => c.charCodeAt(0)
    );
    
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
    
    // Step 4: Derive keypair from seed
    const seedBytes = hexToBytes(seedHex);
    const keypair = nacl.sign.keyPair.fromSeed(seedBytes);
    
    return keypair;  // { publicKey, secretKey }
}


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔒 SECURITY IMPROVEMENTS OVER OLD FORMAT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

OLD (CryptoJS):               NEW (Fork Architecture V2):
┌────────────────────────┐   ┌────────────────────────────────┐
│ Algorithm: AES-CBC     │   │ Algorithm: AES-GCM             │
│ KDF: PBKDF2            │   │ KDF: Argon2id                  │
│ Iterations: 100k       │   │ Memory: 64 MB                  │
│ No auth separation     │   │ Iterations: 3                  │
│ Server could decrypt   │   │ Fork architecture              │
│                        │   │ Server CANNOT decrypt          │
└────────────────────────┘   └────────────────────────────────┘

✅ AES-GCM provides authenticated encryption
✅ Argon2id is memory-hard (resistant to GPU/ASIC attacks)
✅ Fork architecture provides host-proof security
✅ Server authentication separate from vault decryption


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📦 DATABASE RECORD (for Supabase/Backend)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{
    "username": "${newWallet.username}",
    "email": "${newWallet.email}",
    "l1_address": "${newWallet.l1_address}",
    "l2_address": "${newWallet.l2_address}",
    "public_key": "${newWallet.public_key}",
    "auth_salt": "${newWallet.auth_salt}",
    "vault_salt": "${newWallet.vault_salt}",
    "vault_ciphertext": "${newWallet.vault.ciphertext}",
    "vault_nonce": "${newWallet.vault.nonce}",
    "vault_version": 2,
    "fork_version": 2,
    "created_at": "${newWallet.vault.created_at}",
    "migrated_at": "${newWallet.migrated_at}"
}

⚠️ Server should also store: auth_key_hash = bcrypt(${newWallet.auth_key})


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📚 RELATED FILES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

sdk/migrate-mac-wallet.js          - This migration script
sdk/blackbook-wallet-sdk.js        - Production wallet SDK with AES-GCM
mac-wallet-v2-full.json            - Complete migrated wallet data
mac-wallet-v2-vault.json           - Database-ready vault record
tests/js/02-wallet-login.test.js   - Wallet login tests


╔══════════════════════════════════════════════════════════════════════════════╗
║                     END OF MAC WALLET V2 DOCUMENTATION                        ║
╚══════════════════════════════════════════════════════════════════════════════╝
`;

    fs.writeFileSync('macwallet.txt', content);
    console.log('   ✓ Updated: macwallet.txt');
}

// ═══════════════════════════════════════════════════════════════
// RUN MIGRATION
// ═══════════════════════════════════════════════════════════════

migrateMacWallet().catch(console.error);
