// Sign ZKP challenge using mnemonic-derived private key
const bip39 = require('bip39');
const { derivePath } = require('ed25519-hd-key');
const nacl = require('tweetnacl');
const crypto = require('crypto');

// Usage: node sign-with-mnemonic.js <mnemonic> <challenge> <address>
const mnemonic = process.argv[2];
const challenge = process.argv[3];
const address = process.argv[4];

if (!mnemonic || !challenge || !address) {
    console.error('Usage: node sign-with-mnemonic.js "<mnemonic>" <challenge_hex> <address>');
    console.error('Example: node sign-with-mnemonic.js "word1 word2..." abc123... bb_abc...');
    process.exit(1);
}

// Convert mnemonic to seed
const seed = bip39.mnemonicToSeedSync(mnemonic, ''); // No BIP39 passphrase

// Derive Ed25519 key using SLIP-10 path: m/44'/501'/0'/0' (Solana-compatible)
const path = "m/44'/501'/0'/0'";
const derived = derivePath(path, seed.toString('hex'));

// Extract private and public keys
const privateKey = derived.key;
const keyPair = nacl.sign.keyPair.fromSeed(privateKey);
const publicKey = keyPair.publicKey;
const secretKey = keyPair.secretKey; // 64-byte (32 private + 32 public)

// Derive wallet address from public key (first 16 bytes as hex)
const derivedAddress = 'bb_' + Buffer.from(publicKey).toString('hex').substring(0, 32);

console.log('\n=== Mnemonic-Derived Keys ===');
console.log('Public Key:', Buffer.from(publicKey).toString('hex'));
console.log('Derived Address:', derivedAddress);
console.log('Expected Address:', address);

if (derivedAddress !== address) {
    console.error('\n❌ ERROR: Derived address does not match expected address!');
    console.error('This means either the mnemonic is wrong or the address is from a different wallet.');
    process.exit(1);
}

// Construct ZKP challenge message
const message = `BLACKBOOK_SHARE_B\n${challenge}\n${address}`;
const messageBytes = Buffer.from(message, 'utf8');

// Sign the message
const signature = nacl.sign.detached(messageBytes, secretKey);

console.log('\n=== ZKP Proof Generated ===');
console.log('Challenge:', challenge);
console.log('Signature:', Buffer.from(signature).toString('hex'));

console.log('\n=== JSON Payload ===');
const payload = {
    public_key: Buffer.from(publicKey).toString('hex'),
    signature: Buffer.from(signature).toString('hex')
};
console.log(JSON.stringify(payload, null, 2));

// Also output PowerShell command
console.log('\n=== PowerShell Command ===');
console.log(`$zkpProof = @{
    public_key = "${payload.public_key}"
    signature = "${payload.signature}"
} | ConvertTo-Json; Invoke-RestMethod -Uri "http://localhost:8080/mnemonic/share-b/${address}" -Method POST -Body $zkpProof -ContentType "application/json"`);
