// Sign ZKP challenge for Share B retrieval
const crypto = require('crypto');
const nacl = require('tweetnacl');

// Bob's credentials from accounts.txt
const privateKeyHex = '80c470406b817e178d85788062ef3bfc234dbb276afd2a243c7992c33b271973';
const publicKeyHex = 'd107ea1e684349bb2a67f026fd98ebc28ba12b273b94c498b85dbbd867f62d4a';
const address = 'bb_d8ed1c2f27ed27081bf11e58bb6eb160';

// Challenge from server (pass as command line argument)
const challenge = process.argv[2];

if (!challenge) {
    console.error('Usage: node sign-zkp-challenge.js <challenge_hex>');
    process.exit(1);
}

// Construct the message according to ZKP protocol
const message = `BLACKBOOK_SHARE_B\n${challenge}\n${address}`;
const messageBytes = Buffer.from(message, 'utf8');

// Sign with Ed25519
const privateKey = Buffer.from(privateKeyHex, 'hex');
const publicKey = Buffer.from(publicKeyHex, 'hex');

// tweetnacl requires 64-byte secret key (private + public)
const secretKey = Buffer.concat([privateKey, publicKey]);
const signature = nacl.sign.detached(messageBytes, secretKey);

console.log('\n=== ZKP Proof Generated ===');
console.log('Public Key:', publicKeyHex);
console.log('Signature:', Buffer.from(signature).toString('hex'));
console.log('\nJSON Payload:');
console.log(JSON.stringify({
    public_key: publicKeyHex,
    signature: Buffer.from(signature).toString('hex')
}, null, 2));
