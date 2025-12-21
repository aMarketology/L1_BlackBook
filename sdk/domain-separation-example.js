/**
 * BlackBook Unified Wallet SDK - Domain Separation Example
 * 
 * This demonstrates how to sign transactions for L1 (Bank) and L2 (Gaming)
 * using the same private key while preventing replay attacks.
 */

const nacl = require('tweetnacl');
const { sha256 } = require('@noble/hashes/sha256');
const { bytesToHex, hexToBytes } = require('@noble/hashes/utils');

// Domain Separation Constants
const CHAIN_ID_L1 = 0x01; // Bank/Vault
const CHAIN_ID_L2 = 0x02; // Gaming/Casino

/**
 * Generate a deterministic L1/L2 address from a public key
 * 
 * @param {Uint8Array} publicKey - Ed25519 public key (32 bytes)
 * @returns {{l1: string, l2: string, core: string}}
 */
function generateAddresses(publicKey) {
    // Hash the public key
    const hash = sha256(publicKey);
    
    // Take first 20 bytes (40 hex chars) = 160-bit security (same as Bitcoin RIPEMD160)
    const coreId = bytesToHex(hash.slice(0, 20)).toUpperCase();
    
    return {
        l1: `L1${coreId}`,      // e.g., "L148F582A1BC8976D3E45F6789ABCDEF01234567"
        l2: `L2${coreId}`,      // e.g., "L248F582A1BC8976D3E45F6789ABCDEF01234567"
        core: coreId,           // e.g., "48F582A1BC8976D3E45F6789ABCDEF01234567"
    };
}

/**
 * Sign a message with domain separation
 * 
 * @param {Uint8Array} privateKey - Ed25519 private key (32 bytes)
 * @param {string} message - Message to sign
 * @param {number} chainId - CHAIN_ID_L1 or CHAIN_ID_L2
 * @returns {string} Hex-encoded signature
 */
function signWithDomainSeparation(privateKey, message, chainId) {
    if (chainId !== CHAIN_ID_L1 && chainId !== CHAIN_ID_L2) {
        throw new Error(`Invalid chain_id: 0x${chainId.toString(16)}`);
    }
    
    // Construct domain-separated message
    const messageBytes = new TextEncoder().encode(message);
    const domainSeparatedMessage = new Uint8Array(1 + messageBytes.length);
    domainSeparatedMessage[0] = chainId;  // <--- CRITICAL: Domain separator
    domainSeparatedMessage.set(messageBytes, 1);
    
    // Sign
    const keyPair = nacl.sign.keyPair.fromSeed(privateKey);
    const signature = nacl.sign.detached(domainSeparatedMessage, keyPair.secretKey);
    
    return bytesToHex(signature);
}

/**
 * Create a signed request for the BlackBook API
 * 
 * @param {Uint8Array} privateKey - Ed25519 private key (32 bytes)
 * @param {Uint8Array} publicKey - Ed25519 public key (32 bytes)
 * @param {object} payload - Request payload
 * @param {number} chainId - CHAIN_ID_L1 or CHAIN_ID_L2
 * @returns {object} SignedRequest ready to send
 */
function createSignedRequest(privateKey, publicKey, payload, chainId) {
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = crypto.randomUUID();
    const payloadStr = JSON.stringify(payload);
    
    // Construct message to sign: payload\ntimestamp\nnonce
    const message = `${payloadStr}\n${timestamp}\n${nonce}`;
    
    // Sign with domain separation
    const signature = signWithDomainSeparation(privateKey, message, chainId);
    
    return {
        public_key: bytesToHex(publicKey),
        wallet_address: null, // Optional
        payload: payloadStr,
        timestamp,
        nonce,
        chain_id: chainId,
        signature,
    };
}

// ============================================================================
// EXAMPLES
// ============================================================================

async function exampleUsage() {
    console.log('🔐 BlackBook Domain Separation Example\n');
    
    // 1. Generate a wallet
    const seed = new Uint8Array(32);
    crypto.getRandomValues(seed);
    const keyPair = nacl.sign.keyPair.fromSeed(seed);
    
    const addresses = generateAddresses(keyPair.publicKey);
    console.log('📍 Wallet Addresses:');
    console.log(`   L1 (Bank):   ${addresses.l1}`);
    console.log(`   L2 (Gaming): ${addresses.l2}`);
    console.log(`   Core ID:     ${addresses.core}\n`);
    
    // 2. Sign for L1 (Bank operation)
    const l1Payload = { action: 'deposit', amount: 1000 };
    const l1Request = createSignedRequest(
        keyPair.secretKey.slice(0, 32),
        keyPair.publicKey,
        l1Payload,
        CHAIN_ID_L1
    );
    
    console.log('💰 L1 Request (Bank Deposit):');
    console.log(`   Chain ID: 0x${l1Request.chain_id.toString(16)}`);
    console.log(`   Signature: ${l1Request.signature.substring(0, 32)}...`);
    console.log(`   Payload: ${l1Request.payload}\n`);
    
    // 3. Sign for L2 (Gaming operation)
    const l2Payload = { action: 'bet', amount: 100, market: 'BTC_100K' };
    const l2Request = createSignedRequest(
        keyPair.secretKey.slice(0, 32),
        keyPair.publicKey,
        l2Payload,
        CHAIN_ID_L2
    );
    
    console.log('🎰 L2 Request (Place Bet):');
    console.log(`   Chain ID: 0x${l2Request.chain_id.toString(16)}`);
    console.log(`   Signature: ${l2Request.signature.substring(0, 32)}...`);
    console.log(`   Payload: ${l2Request.payload}\n`);
    
    // 4. Demonstrate that signatures are different
    console.log('🔒 Security Check:');
    console.log(`   Same key? Yes`);
    console.log(`   Same timestamp? ${l1Request.timestamp === l2Request.timestamp ? 'No (different nonces)' : 'No'}`);
    console.log(`   Same signatures? ${l1Request.signature === l2Request.signature ? 'YES - BROKEN!' : 'No - SECURE ✓'}`);
    
    // 5. Send requests to API
    console.log('\n📡 Sending Requests:');
    
    try {
        // L1 Request
        const l1Response = await fetch('http://localhost:3030/api/v2/wallet/deposit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(l1Request),
        });
        console.log(`   L1 Response: ${l1Response.status} ${l1Response.statusText}`);
        
        // L2 Request
        const l2Response = await fetch('http://localhost:3030/api/v2/markets/bet', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(l2Request),
        });
        console.log(`   L2 Response: ${l2Response.status} ${l2Response.statusText}`);
    } catch (error) {
        console.log(`   Error: ${error.message}`);
        console.log('   (Server not running? That\'s okay, this is just a demo)');
    }
}

// ============================================================================
// REPLAY ATTACK DEMONSTRATION
// ============================================================================

function demonstrateReplayAttack() {
    console.log('\n⚠️  Replay Attack Demonstration\n');
    
    const seed = new Uint8Array(32).fill(1);
    const keyPair = nacl.sign.keyPair.fromSeed(seed);
    
    // User signs a legitimate L1 transaction
    const message = JSON.stringify({ action: 'withdraw', amount: 1000 });
    const l1Signature = signWithDomainSeparation(
        keyPair.secretKey.slice(0, 32),
        message,
        CHAIN_ID_L1
    );
    
    console.log('1️⃣  User signs legitimate L1 withdrawal:');
    console.log(`   Message: ${message}`);
    console.log(`   L1 Signature: ${l1Signature.substring(0, 32)}...\n`);
    
    // Attacker tries to replay on L2
    console.log('2️⃣  Attacker intercepts and tries to replay on L2...\n');
    
    // Verify with L2 chain_id
    const messageBytes = new TextEncoder().encode(message);
    const l2Message = new Uint8Array(1 + messageBytes.length);
    l2Message[0] = CHAIN_ID_L2;  // L2 expects this
    l2Message.set(messageBytes, 1);
    
    const isValid = nacl.sign.detached.verify(
        l2Message,
        hexToBytes(l1Signature),
        keyPair.publicKey
    );
    
    console.log('3️⃣  L2 Node Verification Result:');
    console.log(`   Expected message: [0x02]${message}`);
    console.log(`   Signature was for: [0x01]${message}`);
    console.log(`   Valid? ${isValid ? '✅ YES - VULNERABLE!' : '❌ NO - PROTECTED ✓'}`);
    
    if (!isValid) {
        console.log('\n   🛡️  Attack PREVENTED by domain separation!');
    }
}

// Run examples
if (require.main === module) {
    exampleUsage().then(() => {
        demonstrateReplayAttack();
    }).catch(console.error);
}

module.exports = {
    CHAIN_ID_L1,
    CHAIN_ID_L2,
    generateAddresses,
    signWithDomainSeparation,
    createSignedRequest,
};
