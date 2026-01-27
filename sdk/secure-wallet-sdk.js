import crypto from 'crypto';
import argon2 from 'argon2';
import * as ed from '@noble/ed25519';

/**
 * BlackBook Secure Wallet SDK
 * Implements "Dual Key" Architecture:
 * 1. Root Key (Recovery): High-entropy, SSS-split, Offline
 * 2. Operational Key (Daily): Password-derived (Argon2id), Online
 */

// ============================================================================
// SHAMIR'S SECRET SHARING (GF(2^256))
// ============================================================================
// Simple implementation for 2-of-3 split
// WARNING: For production, review with cryptographer or use vetted lib

const PRIME = 2n ** 256n - 189n;

function randomBigInt(max) {
    const bytes = crypto.randomBytes(32);
    const num = BigInt('0x' + bytes.toString('hex'));
    return num % max;
}

function modInverse(a, m) {
    let [old_r, r] = [a, m];
    let [old_s, s] = [1n, 0n];
    while (r !== 0n) {
        const q = old_r / r;
        [old_r, r] = [r, old_r - q * r];
        [old_s, s] = [s, old_s - q * s];
    }
    if (old_s < 0n) old_s += m;
    return old_s;
}

function splitSecret(secretBytes, n, k) {
    const secret = BigInt('0x' + secretBytes.toString('hex'));
    const coeffs = [secret];
    for (let i = 1; i < k; i++) coeffs.push(randomBigInt(PRIME));
    
    const shares = [];
    for (let i = 1; i <= n; i++) {
        const x = BigInt(i);
        let y = 0n;
        for (let j = 0; j < k; j++) {
            y = (y + coeffs[j] * (x ** BigInt(j))) % PRIME;
        }
        shares.push({ x: i, y: y.toString(16) });
    }
    return shares;
}

function reconstructSecret(shares) {
    // shares: [{x: 1, y: 'hex'}, ...]
    let secret = 0n;
    for (let i = 0; i < shares.length; i++) {
        const xi = BigInt(shares[i].x);
        const yi = BigInt('0x' + shares[i].y);
        let num = 1n;
        let den = 1n;
        
        for (let j = 0; j < shares.length; j++) {
            if (i === j) continue;
            const xj = BigInt(shares[j].x);
            num = (num * (0n - xj)) % PRIME;
            den = (den * (xi - xj)) % PRIME;
        }
        
        const langrange = (yi * num * modInverse(den, PRIME)) % PRIME;
        secret = (secret + langrange) % PRIME;
    }
    
    // Handle potential negative result from modulo
    if (secret < 0n) secret += PRIME;
    
    let hex = secret.toString(16);
    if (hex.length % 2 !== 0) hex = '0' + hex;
    return Buffer.from(hex, 'hex');
}

// ============================================================================
// KEY DERIVATION & ACCOUNT MANAGEMENT
// ============================================================================

export class SecureWallet {
    /**
     * Create a new secure account from scratch
     * @param {string} password - User's password
     * @returns {Object} { address, root_shares, op_key_details, tx_payload }
     */
    static async createAccount(password) {
        // 1. Generate Root Key (Random 32 bytes)
        const rootKey = crypto.randomBytes(32);
        const rootPub = await ed.getPublicKey(rootKey);
        const rootPubHex = Buffer.from(rootPub).toString('hex');
        
        // 2. Split Root Key (3 shares, threshold 2)
        // Share 1: Server (Encrypted?) or just User? User request says: "Printed, Hardware, Trusted Person"
        // Returning raw shares for UI to distribute.
        const shares = splitSecret(rootKey, 3, 2);
        
        // 3. Derive Operational Key
        // Salt should be unique per account. Since we don't have account ID yet, generate random.
        const salt = crypto.randomBytes(16);
        const opKeySeed = await SecureWallet.deriveOpKey(password, salt);
        const opPub = await ed.getPublicKey(opKeySeed);
        const opPubHex = Buffer.from(opPub).toString('hex');
        
        // 4. Address Derivation
        // We'll use Hash(RootPub) as the immutable address
        const addressBytes = crypto.createHash('sha256').update(rootPub).digest();
        const address = '0x' + addressBytes.toString('hex').slice(0, 40); // 20 bytes
        
        // 5. KDF Params to store
        const kdfParams = {
            salt: salt.toString('hex'),
            params: {
                type: argon2.argon2id,
                mem: 2**16,
                time: 3,
                len: 32
            }
        };
        const kdfParamsStr = JSON.stringify(kdfParams);
        const kdfHash = crypto.createHash('sha256').update(kdfParamsStr).digest('hex');

        return {
            address,
            // SECURITY: Never return raw rootKey. Only shares.
            shares: shares.map(s => ({ index: s.x, value: s.y })),
            op_wallet: {
                publicKey: opPubHex,
                // In a real app, private key stays in memory or encrypted storage
                privateKeyPreview: opKeySeed.toString('hex').slice(0, 8) + '...',
                salt: salt.toString('hex')
            },
            // The Transaction to broadcast
            create_tx: {
                type: 'CreateAccount',
                from: address,
                data: {
                    root_pubkey: rootPubHex,
                    initial_op_pubkey: opPubHex,
                    kdf_params_hash: kdfHash
                },
                // NOTE: In the protocol I wrote "CreateAccount" doesn't strict check sig, 
                // but usually self-signed by Root or Op.
                // We'll sign with Root Key just to prove possession during creation (optional)
                signature: Buffer.from(await ed.sign(Buffer.from("CreateAccount"), rootKey)).toString('hex')
            },
            storage: {
                // What to save to local storage
                address,
                salt: salt.toString('hex'),
                // The wallet needs the password to regenerate the key next time
            }
        };
    }

    /**
     * Login: Derive Op Key from Password + Salt
     */
    static async login(password, saltHex) {
        const salt = Buffer.from(saltHex, 'hex');
        const opKeySeed = await SecureWallet.deriveOpKey(password, salt);
        const publicKey = await ed.getPublicKey(opKeySeed);
        
        return {
            privateKey: opKeySeed,
            publicKey: Buffer.from(publicKey).toString('hex')
        };
    }

    /**
     * Recover: Reconstruct Root Key -> Sign Rotation Tx
     */
    static async recoverAccount(sharesInput, newPassword, oldAddress) {
        // 1. Reconstruct Root Key
        // format input: [{x:1, y:'...'}, {x:2, y:'...'}]
        const rootKey = reconstructSecret(sharesInput);
        // Verify? Only if we know the pubkey hash/address.
        const rootPub = await ed.getPublicKey(rootKey);
        const addressBytes = crypto.createHash('sha256').update(rootPub).digest();
        const derivedAddr = '0x' + addressBytes.toString('hex').slice(0, 40);
        
        if (oldAddress && derivedAddr !== oldAddress) {
            throw new Error("Recovered key does not match account address!");
        }

        // 2. Generate New Op Key
        const newSalt = crypto.randomBytes(16);
        const newOpSeed = await SecureWallet.deriveOpKey(newPassword, newSalt);
        const newOpPub = await ed.getPublicKey(newOpSeed);
        const newOpPubHex = Buffer.from(newOpPub).toString('hex');

        // 3. Create Key Rotation Transaction
        // Signed by ROOT Key
        const kdfParams = { salt: newSalt.toString('hex') };
        const kdfHash = crypto.createHash('sha256').update(JSON.stringify(kdfParams)).digest('hex');
        
        // Payload to sign
        // Usually we sign the Hash(TxData). For simplicity string here.
        const txData = `RotateOpKey:${newOpPubHex}:${kdfHash}:${Date.now()}`;
        const signature = await ed.sign(Buffer.from(txData), rootKey);

        return {
            new_storage: {
                address: derivedAddr,
                salt: newSalt.toString('hex')
            },
            rotation_tx: {
                type: 'RotateOpKey',
                from: derivedAddr,
                data: {
                    new_op_pubkey: newOpPubHex,
                    kdf_params_hash: kdfHash
                },
                signature: Buffer.from(signature).toString('hex'),
                signer_pubkey: Buffer.from(rootPub).toString('hex')
            }
        };
    }

    /**
     * Internal Argon2id Wrapper
     */
    static async deriveOpKey(password, salt) {
        return await argon2.hash(password, {
            type: argon2.argon2id,
            memoryCost: 2 ** 16, // 64 MB
            timeCost: 3,
            parallelism: 1,
            hashLength: 32,
            raw: true,
            salt: salt
        });
    }
}
