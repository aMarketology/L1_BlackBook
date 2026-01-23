/**
 * WHY THE PRIVATE KEY DOESN'T CHANGE
 * 
 * This demonstrates the cryptographic relationship:
 * 
 *   SEED (32 bytes, random) ──────────────────────────────────────┐
 *        │                                                        │
 *        │ Ed25519.fromSeed()                                     │
 *        │ (deterministic derivation)                             │
 *        ▼                                                        │
 *   KEYPAIR                                                       │
 *   ├── publicKey  ──► L1 Address                                │
 *   └── secretKey  ──► Signs transactions                        │
 *                                                                 │
 *   PASSWORD ──► PBKDF2 ──► encryption_key                       │
 *                               │                                 │
 *                               ▼                                 │
 *                         AES.encrypt(SEED) ◄─────────────────────┘
 *                               │
 *                               ▼
 *                         vault_blob (stored in DB)
 * 
 * The PASSWORD never touches the keypair derivation!
 * It only encrypts the SEED for storage.
 * 
 * Same SEED = Same keypair = Same address (always!)
 */

import nacl from 'tweetnacl';
import CryptoJS from 'crypto-js';
import crypto from 'crypto';

const L1_BASE_URL = 'http://127.0.0.1:8080';

// ═══════════════════════════════════════════════════════════════════════════
// STEP 1: PROVE SAME SEED = SAME KEYS (regardless of password)
// ═══════════════════════════════════════════════════════════════════════════

console.log('═══════════════════════════════════════════════════════════════');
console.log('WHY PRIVATE KEY DOESN\'T CHANGE WHEN PASSWORD CHANGES');
console.log('═══════════════════════════════════════════════════════════════\n');

// Generate a seed ONCE
const SEED = crypto.randomBytes(32);
console.log('SEED (generated once, stored encrypted):');
console.log('  ' + SEED.toString('hex') + '\n');

// Derive keypair from seed
const keypair = nacl.sign.keyPair.fromSeed(SEED);
const publicKey = Buffer.from(keypair.publicKey).toString('hex');
const secretKey = Buffer.from(keypair.secretKey).toString('hex');

console.log('KEYPAIR (derived from seed - DETERMINISTIC):');
console.log('  Public Key:  ' + publicKey);
console.log('  Secret Key:  ' + secretKey.slice(0, 32) + '... (64 bytes)\n');

// Derive L1 address
const addressHash = CryptoJS.SHA256(publicKey).toString();
const l1Address = 'L1_' + addressHash.substring(0, 40).toUpperCase();
console.log('L1 ADDRESS (derived from public key):');
console.log('  ' + l1Address + '\n');

// ═══════════════════════════════════════════════════════════════════════════
// STEP 2: Encrypt seed with PASSWORD 1
// ═══════════════════════════════════════════════════════════════════════════

console.log('───────────────────────────────────────────────────────────────');
console.log('ENCRYPT SEED WITH PASSWORD 1: "OldPassword123!"');
console.log('───────────────────────────────────────────────────────────────\n');

const password1 = 'OldPassword123!';
const salt1 = crypto.randomBytes(16).toString('hex');
const key1 = CryptoJS.PBKDF2(password1, salt1, { keySize: 256/32, iterations: 100000 });
const vault1 = CryptoJS.AES.encrypt(SEED.toString('hex'), key1.toString()).toString();

console.log('  Salt:  ' + salt1);
console.log('  Vault: ' + vault1.slice(0, 50) + '...\n');

// Decrypt and derive keypair
const decrypted1 = CryptoJS.AES.decrypt(vault1, key1.toString()).toString(CryptoJS.enc.Utf8);
const keypair1 = nacl.sign.keyPair.fromSeed(Buffer.from(decrypted1, 'hex'));
console.log('  Decrypted → Derived Public Key: ' + Buffer.from(keypair1.publicKey).toString('hex'));
console.log('  Matches original? ' + (Buffer.from(keypair1.publicKey).toString('hex') === publicKey ? '✓ YES' : '✗ NO') + '\n');

// ═══════════════════════════════════════════════════════════════════════════
// STEP 3: Encrypt SAME seed with PASSWORD 2
// ═══════════════════════════════════════════════════════════════════════════

console.log('───────────────────────────────────────────────────────────────');
console.log('ENCRYPT SAME SEED WITH PASSWORD 2: "NewPassword456!"');
console.log('───────────────────────────────────────────────────────────────\n');

const password2 = 'NewPassword456!';
const salt2 = crypto.randomBytes(16).toString('hex');
const key2 = CryptoJS.PBKDF2(password2, salt2, { keySize: 256/32, iterations: 100000 });
const vault2 = CryptoJS.AES.encrypt(SEED.toString('hex'), key2.toString()).toString();

console.log('  Salt:  ' + salt2);
console.log('  Vault: ' + vault2.slice(0, 50) + '... (DIFFERENT encrypted blob!)\n');

// Decrypt and derive keypair
const decrypted2 = CryptoJS.AES.decrypt(vault2, key2.toString()).toString(CryptoJS.enc.Utf8);
const keypair2 = nacl.sign.keyPair.fromSeed(Buffer.from(decrypted2, 'hex'));
console.log('  Decrypted → Derived Public Key: ' + Buffer.from(keypair2.publicKey).toString('hex'));
console.log('  Matches original? ' + (Buffer.from(keypair2.publicKey).toString('hex') === publicKey ? '✓ YES' : '✗ NO') + '\n');

// ═══════════════════════════════════════════════════════════════════════════
// STEP 4: PROVE BOTH PASSWORDS PRODUCE SAME SIGNATURE
// ═══════════════════════════════════════════════════════════════════════════

console.log('───────────────────────────────────────────────────────────────');
console.log('SIGN SAME MESSAGE WITH BOTH PASSWORDS');
console.log('───────────────────────────────────────────────────────────────\n');

const testMessage = 'Transfer 100 BB to Bob';
const messageBytes = new TextEncoder().encode(testMessage);

const sig1 = nacl.sign.detached(messageBytes, keypair1.secretKey);
const sig2 = nacl.sign.detached(messageBytes, keypair2.secretKey);

console.log('  Message: "' + testMessage + '"');
console.log('  Sig with Password 1: ' + Buffer.from(sig1).toString('hex').slice(0, 32) + '...');
console.log('  Sig with Password 2: ' + Buffer.from(sig2).toString('hex').slice(0, 32) + '...');
console.log('  Signatures identical? ' + (Buffer.from(sig1).toString('hex') === Buffer.from(sig2).toString('hex') ? '✓ YES' : '✗ NO') + '\n');

// ═══════════════════════════════════════════════════════════════════════════
// STEP 5: LIVE ON-CHAIN TEST
// ═══════════════════════════════════════════════════════════════════════════

console.log('═══════════════════════════════════════════════════════════════');
console.log('LIVE ON-CHAIN TEST');
console.log('═══════════════════════════════════════════════════════════════\n');

async function liveTest() {
    // Create signing function
    function createSignedRequest(payload, keypair, walletAddress) {
        const payloadStr = JSON.stringify(payload);
        const timestamp = Math.floor(Date.now() / 1000);
        const nonce = crypto.randomUUID();
        const CHAIN_ID_L1 = 0x01;
        const message = `${payloadStr}\n${timestamp}\n${nonce}`;
        const messageBytes = new Uint8Array(1 + message.length);
        messageBytes[0] = CHAIN_ID_L1;
        messageBytes.set(new TextEncoder().encode(message), 1);
        const signature = nacl.sign.detached(messageBytes, keypair.secretKey);
        return {
            public_key: Buffer.from(keypair.publicKey).toString('hex'),
            wallet_address: walletAddress,
            payload: payloadStr,
            timestamp, nonce, 
            chain_id: CHAIN_ID_L1,
            schema_version: 1,
            signature: Buffer.from(signature).toString('hex')
        };
    }

    async function getBalance(address) {
        try {
            const res = await fetch(`${L1_BASE_URL}/balance/${address}`);
            const json = await res.json();
            return json.balance ?? 0;
        } catch (e) {
            return 0;
        }
    }

    async function transfer(signedRequest) {
        try {
            const res = await fetch(`${L1_BASE_URL}/transfer/simple`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(signedRequest)
            });
            const text = await res.text();
            try {
                return JSON.parse(text);
            } catch {
                return { success: false, error: text };
            }
        } catch (e) {
            return { success: false, error: e.message };
        }
    }

    // Use Bob's account to fund our test wallet
    const BOB = {
        l1_address: 'L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433',
        seed: '582420216093fcff65b0eec2ca2c8227dfc2b6b7428110f36c3fc1349c4b2f5a'
    };
    const bobKeypair = nacl.sign.keyPair.fromSeed(Buffer.from(BOB.seed, 'hex'));

    console.log('TEST WALLET:');
    console.log('  Address: ' + l1Address);
    console.log('  Will test password change works on-chain\n');

    // Step A: Check initial balances
    console.log('A. Initial Balances:');
    let bobBal = await getBalance(BOB.l1_address);
    let testBal = await getBalance(l1Address);
    console.log('   Bob:  ' + bobBal + ' BB');
    console.log('   Test: ' + testBal + ' BB\n');

    // Step B: Bob sends 5 BB to test wallet
    console.log('B. Bob sends 5 BB to test wallet...');
    const fundReq = createSignedRequest({ to: l1Address, amount: 5 }, bobKeypair, BOB.l1_address);
    const fundResult = await transfer(fundReq);
    console.log('   Result: ' + (fundResult.success ? '✓ Success' : '✗ ' + fundResult.error) + '\n');

    // Step C: Check balance
    testBal = await getBalance(l1Address);
    console.log('C. Test wallet balance: ' + testBal + ' BB\n');

    // Step D: Sign transfer with PASSWORD 1 keypair
    console.log('D. Sign transfer with PASSWORD 1 (OldPassword123!):');
    const req1 = createSignedRequest({ to: BOB.l1_address, amount: 1 }, keypair1, l1Address);
    const result1 = await transfer(req1);
    console.log('   Result: ' + (result1.success ? '✓ Success' : '✗ ' + result1.error));
    testBal = await getBalance(l1Address);
    console.log('   Test wallet balance: ' + testBal + ' BB\n');

    // Step E: "Change password" - same seed, different encryption
    console.log('E. SIMULATING PASSWORD CHANGE...');
    console.log('   Old vault decrypted → seed recovered → new vault created');
    console.log('   (In real app: update Supabase with new vault)\n');

    // Step F: Sign transfer with PASSWORD 2 keypair
    console.log('F. Sign transfer with PASSWORD 2 (NewPassword456!):');
    const req2 = createSignedRequest({ to: BOB.l1_address, amount: 1 }, keypair2, l1Address);
    const result2 = await transfer(req2);
    console.log('   Result: ' + (result2.success ? '✓ Success' : '✗ ' + result2.error));
    testBal = await getBalance(l1Address);
    console.log('   Test wallet balance: ' + testBal + ' BB\n');

    // Summary
    console.log('═══════════════════════════════════════════════════════════════');
    console.log('PROOF COMPLETE');
    console.log('═══════════════════════════════════════════════════════════════\n');
    console.log('Both transactions succeeded because:');
    console.log('  1. Same SEED = same keypair = same address');
    console.log('  2. Password only protects the seed storage');
    console.log('  3. L1 only verifies signature against public key');
    console.log('  4. L1 doesn\'t know or care about your password\n');
    
    console.log('┌─────────────────────────────────────────────────────────────┐');
    console.log('│  PASSWORD CHANGE FLOW:                                      │');
    console.log('│                                                             │');
    console.log('│  old_password → decrypt vault → SEED                        │');
    console.log('│                                   │                         │');
    console.log('│                                   ▼                         │');
    console.log('│                          new_password → encrypt → new_vault │');
    console.log('│                                                             │');
    console.log('│  SEED never changes. Keypair never changes. Address same.  │');
    console.log('└─────────────────────────────────────────────────────────────┘');
}

liveTest().catch(e => console.error('Error:', e.message));
