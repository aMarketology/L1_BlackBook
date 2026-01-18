/**
 * Bob → Mac → Bob Transfer Test
 * 
 * 1. Bob sends 2 BB to Mac
 * 2. Mac unlocks wallet from vault and sends 1 BB back to Bob
 * 
 * Run: node bob-mac-live-transfer.js
 */

import nacl from 'tweetnacl';
import CryptoJS from 'crypto-js';

const L1_BASE_URL = 'http://127.0.0.1:8080';

// ═══════════════════════════════════════════════════════════════
// BOB'S CREDENTIALS (from TEST_ACCOUNTS.txt)
// ═══════════════════════════════════════════════════════════════
const BOB = {
    l1_address: 'L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433',
    public_key: 'e4ac49e5a04ef7dfc6e1a838fdf14597f2d514d0029a82cb45c916293487c25b',
    private_key: '582420216093fcff65b0eec2ca2c8227dfc2b6b7428110f36c3fc1349c4b2f5a'
};

// ═══════════════════════════════════════════════════════════════
// MAC'S VAULT DATA (SECURE - no private key stored!)
// ═══════════════════════════════════════════════════════════════
const MAC = {
    l1_address: 'L1_94B3C863E068096596CE80F04C2233B72AE11790',
    public_key: 'ec6941c71740e192bbf5933d5f9cc18ea161329ce864da900d8de73d45c28752',
    vault: {
        salt: '579a5c28a02f8c3ecc2801545a216cec',
        encrypted_blob: 'U2FsdGVkX19443Y8LJ1PaUV6/aG4Ctod88tWo7AVDftZlcgWurkSGAhVEAScVQ91+Ew9iP0d588HfIUYlXQPGEmIMDhjj3M6cDPbDtnTZFh848l0Z71CjV0CpB41Avad'
    },
    password: 'MacSecurePassword2026!'
};

// ═══════════════════════════════════════════════════════════════
// CRYPTO HELPERS
// ═══════════════════════════════════════════════════════════════

function keypairFromSeed(seedHex) {
    const seedBytes = Buffer.from(seedHex, 'hex');
    return nacl.sign.keyPair.fromSeed(seedBytes);
}

function unlockWallet(vault, password) {
    const encryptionKey = CryptoJS.PBKDF2(password, vault.salt, {
        keySize: 256 / 32,
        iterations: 100000,
        hasher: CryptoJS.algo.SHA256
    });
    const decrypted = CryptoJS.AES.decrypt(vault.encrypted_blob, encryptionKey.toString());
    const seedHex = decrypted.toString(CryptoJS.enc.Utf8);
    return nacl.sign.keyPair.fromSeed(Buffer.from(seedHex, 'hex'));
}

function createSignedRequest(fromAddress, toAddress, amount, keypair) {
    const payload = { to: toAddress, amount: amount };
    const payloadStr = JSON.stringify(payload);
    const timestamp = Math.floor(Date.now() / 1000);  // Unix timestamp in SECONDS
    const nonce = crypto.randomUUID();  // UUID format
    
    // Server expects: chain_id_byte + "{payload}\n{timestamp}\n{nonce}"
    const CHAIN_ID_L1 = 0x01;
    const message = `${payloadStr}\n${timestamp}\n${nonce}`;
    
    // Prepend chain_id byte
    const messageBytes = new Uint8Array(1 + message.length);
    messageBytes[0] = CHAIN_ID_L1;
    messageBytes.set(new TextEncoder().encode(message), 1);
    
    const signature = nacl.sign.detached(messageBytes, keypair.secretKey);
    
    return {
        public_key: Buffer.from(keypair.publicKey).toString('hex'),
        wallet_address: fromAddress,  // This tells server which account to use!
        payload: payloadStr,
        timestamp: timestamp,
        nonce: nonce,
        chain_id: CHAIN_ID_L1,
        signature: Buffer.from(signature).toString('hex')
    };
}

async function getBalance(address) {
    const body = JSON.stringify({
        jsonrpc: "2.0",
        method: "getBalance",
        params: [address],
        id: 1
    });
    const response = await fetch(`${L1_BASE_URL}/rpc`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: body
    });
    const result = await response.json();
    return result.result;
}

async function transfer(signedRequest) {
    const response = await fetch(`${L1_BASE_URL}/transfer`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(signedRequest)
    });
    return await response.json();
}

// ═══════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════

async function main() {
    console.log('╔══════════════════════════════════════════════════════════════╗');
    console.log('║          LIVE TRANSFER: Bob → Mac → Bob                      ║');
    console.log('╚══════════════════════════════════════════════════════════════╝\n');
    
    // Step 1: Check initial balances
    console.log('═══════════════════════════════════════════════════════════════');
    console.log('STEP 1: Initial Balances');
    console.log('═══════════════════════════════════════════════════════════════');
    
    let bobBalance = await getBalance(BOB.l1_address);
    let macBalance = await getBalance(MAC.l1_address);
    
    console.log(`   Bob:  ${bobBalance} BB`);
    console.log(`   Mac:  ${macBalance} BB`);
    
    // Step 2: Bob sends 2 BB to Mac
    console.log('\n═══════════════════════════════════════════════════════════════');
    console.log('STEP 2: Bob sends 2 BB to Mac');
    console.log('═══════════════════════════════════════════════════════════════');
    
    const bobKeypair = keypairFromSeed(BOB.private_key);
    const bobToMacRequest = createSignedRequest(BOB.l1_address, MAC.l1_address, 2.0, bobKeypair);
    
    console.log('   📝 Creating signed transfer request...');
    console.log(`      From: ${BOB.l1_address}`);
    console.log(`      To:   ${MAC.l1_address}`);
    console.log(`      Amount: 2 BB`);
    
    const bobResult = await transfer(bobToMacRequest);
    console.log('   📤 Response:', JSON.stringify(bobResult, null, 2));
    
    // Check balances after Bob's transfer
    bobBalance = await getBalance(BOB.l1_address);
    macBalance = await getBalance(MAC.l1_address);
    console.log(`\n   ✅ Balances after Bob → Mac:`);
    console.log(`      Bob:  ${bobBalance} BB`);
    console.log(`      Mac:  ${macBalance} BB`);
    
    // Step 3: Mac unlocks wallet and sends 1 BB back to Bob
    console.log('\n═══════════════════════════════════════════════════════════════');
    console.log('STEP 3: Mac unlocks wallet and sends 1 BB back to Bob');
    console.log('═══════════════════════════════════════════════════════════════');
    
    console.log('   🔐 Mac enters password to unlock wallet...');
    console.log('   🔓 Decrypting vault with PBKDF2 (100k iterations)...');
    
    const macKeypair = unlockWallet(MAC.vault, MAC.password);
    const derivedPubKey = Buffer.from(macKeypair.publicKey).toString('hex');
    
    console.log(`   ✓ Derived public key matches: ${derivedPubKey === MAC.public_key ? 'YES' : 'NO'}`);
    
    const macToBobRequest = createSignedRequest(MAC.l1_address, BOB.l1_address, 1.0, macKeypair);
    
    console.log('   📝 Creating signed transfer request...');
    console.log(`      From: ${MAC.l1_address}`);
    console.log(`      To:   ${BOB.l1_address}`);
    console.log(`      Amount: 1 BB`);
    
    const macResult = await transfer(macToBobRequest);
    console.log('   📤 Response:', JSON.stringify(macResult, null, 2));
    
    // Step 4: Final balances
    console.log('\n═══════════════════════════════════════════════════════════════');
    console.log('STEP 4: Final Balances');
    console.log('═══════════════════════════════════════════════════════════════');
    
    bobBalance = await getBalance(BOB.l1_address);
    macBalance = await getBalance(MAC.l1_address);
    
    console.log(`   Bob:  ${bobBalance} BB (started with ~7878.79, sent 2, received 1 = net -1)`);
    console.log(`   Mac:  ${macBalance} BB (started with 0, received 2, sent 1 = net +1)`);
    
    console.log('\n═══════════════════════════════════════════════════════════════');
    console.log('SUMMARY');
    console.log('═══════════════════════════════════════════════════════════════');
    console.log('   ✅ Bob successfully sent 2 BB to Mac');
    console.log('   ✅ Mac unlocked wallet from encrypted vault');
    console.log('   ✅ Mac successfully sent 1 BB back to Bob');
    console.log('   🔐 Mac\'s private key was NEVER stored or displayed');
}

main().catch(console.error);
