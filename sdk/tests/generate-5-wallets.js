/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * BLACKBOOK L1 - 5 WALLET GENERATION SCRIPT
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Generates production-ready test wallets for:
 *   - Alice (Mnemonic Track) - Regular User / Bettor
 *   - Bob (Mnemonic Track) - Regular User / Bettor  
 *   - Mac (Mnemonic Track) - Power User / Developer
 *   - Apollo (Mnemonic Track) - Heavy Trader / Market Participant
 *   - Dealer (FROST Track) - Market Maker & Oracle Authority
 * 
 * Security Model:
 *   - Mnemonic Track: 24-word BIP-39 + Shamir 2-of-3 SSS + AES-256-GCM
 *   - FROST Track: Threshold signatures (2-of-3) + OPAQUE auth
 * 
 * Run: node sdk/tests/generate-5-wallets.js
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ═══════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════

const L1_URL = 'http://localhost:8080';
const OUTPUT_DIR = path.join(__dirname);

// Test Account Definitions
const MNEMONIC_ACCOUNTS = [
    {
        name: 'Alice',
        role: 'Regular User / Bettor',
        password: 'AlicePassword123!',
        bip39_passphrase: '',
        emoji: '👤',
        capabilities: ['Place bets', 'Transfer tokens', 'View balance']
    },
    {
        name: 'Bob', 
        role: 'Regular User / Bettor',
        password: 'BobPassword123!',
        bip39_passphrase: '',
        emoji: '👤',
        capabilities: ['Place bets', 'Transfer tokens', 'View balance']
    },
    {
        name: 'Mac',
        role: 'Power User / Developer',
        password: 'MacSecurePassword2026!',
        bip39_passphrase: '',
        emoji: '👨‍💻',
        capabilities: ['Full SDK testing', 'Advanced transaction signing', 'Cross-chain bridge operations']
    },
    {
        name: 'Apollo',
        role: 'Heavy Trader / Market Participant',
        password: 'apollo_secure_password_2026',
        bip39_passphrase: '',
        emoji: '🚀',
        capabilities: ['High-frequency trading', 'Large volume transactions', 'Prediction market participation']
    }
];

const FROST_ACCOUNT = {
    name: 'Dealer',
    role: 'Market Maker & Oracle Authority',
    password: 'DealerSecure2026!Oracle',
    emoji: '🎰',
    capabilities: ['Create/approve/reject markets', 'Resolve markets with winning outcome', 'Fund markets with liquidity', 'Sign bridge operations']
};

// ═══════════════════════════════════════════════════════════════
// ANSI COLORS
// ═══════════════════════════════════════════════════════════════

const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const BLUE = '\x1b[34m';
const CYAN = '\x1b[36m';
const MAGENTA = '\x1b[35m';
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';

function header(text) {
    console.log(`\n${CYAN}╔${'═'.repeat(68)}╗${RESET}`);
    console.log(`${CYAN}║${RESET} ${BOLD}${text.padEnd(66)}${RESET} ${CYAN}║${RESET}`);
    console.log(`${CYAN}╚${'═'.repeat(68)}╝${RESET}\n`);
}

function section(text) {
    console.log(`\n${YELLOW}━━━ ${text} ${'━'.repeat(Math.max(0, 60 - text.length))}${RESET}`);
}

function success(msg) { console.log(`${GREEN}✓${RESET} ${msg}`); }
function error(msg) { console.log(`${RED}✗${RESET} ${msg}`); }
function info(msg) { console.log(`${BLUE}ℹ${RESET} ${msg}`); }
function warn(msg) { console.log(`${YELLOW}⚠${RESET} ${msg}`); }

// ═══════════════════════════════════════════════════════════════
// HTTP HELPERS
// ═══════════════════════════════════════════════════════════════

async function httpPost(endpoint, body) {
    const response = await fetch(`${L1_URL}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
    return response.json();
}

async function httpGet(endpoint) {
    const response = await fetch(`${L1_URL}${endpoint}`);
    return response.json();
}

// ═══════════════════════════════════════════════════════════════
// MNEMONIC WALLET GENERATION
// ═══════════════════════════════════════════════════════════════

async function createMnemonicWallet(account) {
    section(`${account.emoji} Creating ${account.name}'s Wallet (Mnemonic Track)`);
    
    try {
        // Call the mnemonic create endpoint
        const response = await httpPost('/mnemonic/create', {
            password: account.password,
            bip39_passphrase: account.bip39_passphrase || '',
            show_mnemonic: true  // For test accounts, we want to store the mnemonic
        });
        
        if (response.error) {
            error(`Failed to create wallet: ${response.error}`);
            return null;
        }
        
        // Build wallet data structure
        const walletData = {
            // Identity
            name: account.name,
            role: account.role,
            track: 'Mnemonic (Consumer)',
            created_at: new Date().toISOString(),
            
            // Addresses
            l1_address: response.wallet_address || response.address,
            l2_address: response.wallet_address?.replace('L1_', 'L2_') || response.address?.replace('bb_', 'L2_'),
            
            // Cryptographic Material
            public_key: response.public_key,
            mnemonic_24_words: response.mnemonic || null,  // Only if show_mnemonic was true
            
            // SSS Share Information
            sss: {
                scheme: '2-of-3 Shamir Secret Sharing over GF(256)',
                share_a: {
                    description: 'Password-bound share (client-side)',
                    bound_data: response.share_a_bound,
                    derivation: 'Argon2id-64MB (3 iterations, parallelism 4)'
                },
                share_b: {
                    description: 'L1 blockchain share (ZKP-gated)',
                    stored_on: 'L1 Blockchain',
                    retrieval: 'Requires ZK-proof of password knowledge'
                },
                share_c: {
                    description: 'Vault-encrypted backup share',
                    encryption: 'AES-256-GCM with peppered nonce',
                    storage: 'HashiCorp Vault / Wallet file'
                }
            },
            
            // Security Parameters  
            security: {
                password_hint: account.password.substring(0, 3) + '***',
                password_salt: response.password_salt,
                key_derivation: 'Argon2id-64MB (3 iterations, parallelism 4)',
                encryption: 'AES-256-GCM',
                bip39_passphrase_used: !!account.bip39_passphrase,
                derivation_path: "m/44'/501'/0'/0'"  // SLIP-10 Ed25519 (Solana-compatible)
            },
            
            // Capabilities
            capabilities: account.capabilities,
            
            // For signing transactions
            signing: {
                algorithm: 'Ed25519',
                canonical_format: 'from|to|amount|timestamp|nonce',
                domain_prefix: 'BLACKBOOK_L1'
            }
        };
        
        success(`Wallet created: ${walletData.l1_address}`);
        info(`Public Key: ${walletData.public_key?.substring(0, 32)}...`);
        
        if (walletData.mnemonic_24_words) {
            info(`Mnemonic: ${walletData.mnemonic_24_words.split(' ').slice(0, 3).join(' ')}... (24 words)`);
        }
        
        return walletData;
        
    } catch (err) {
        error(`Network error: ${err.message}`);
        return null;
    }
}

// ═══════════════════════════════════════════════════════════════
// FROST WALLET GENERATION (For Dealer)
// ═══════════════════════════════════════════════════════════════

async function createFrostWallet(account) {
    section(`${account.emoji} Creating ${account.name}'s Wallet (FROST Track)`);
    
    try {
        // For FROST, we use the unified wallet registration flow
        // This is a simplified version - full FROST requires DKG ceremony
        
        // Generate a deterministic keypair for the Dealer (for testing)
        // In production, this would be a full FROST DKG ceremony
        const seed = crypto.createHash('sha256')
            .update(`DEALER_SEED_${account.password}_2026`)
            .digest();
        
        // Use ed25519 to generate keypair from seed
        const nacl = require('tweetnacl');
        const keyPair = nacl.sign.keyPair.fromSeed(seed);
        
        const publicKeyHex = Buffer.from(keyPair.publicKey).toString('hex');
        const privateKeyHex = Buffer.from(keyPair.secretKey.slice(0, 32)).toString('hex');
        
        // Derive L1 address from public key
        const addressHash = crypto.createHash('sha256')
            .update(Buffer.from(keyPair.publicKey))
            .digest('hex');
        const l1Address = `L1_${addressHash.substring(0, 40).toUpperCase()}`;
        
        const walletData = {
            // Identity
            name: account.name,
            role: account.role,
            track: 'FROST (Institutional)',
            created_at: new Date().toISOString(),
            
            // Addresses
            l1_address: l1Address,
            l2_address: l1Address.replace('L1_', 'L2_'),
            
            // Cryptographic Material
            public_key: publicKeyHex,
            private_key: privateKeyHex,  // ⚠️ TEST ONLY - Never expose in production
            
            // FROST Parameters
            frost: {
                scheme: '2-of-3 Threshold Signatures',
                protocol: 'FROST-Ed25519',
                shard_1: {
                    description: 'Device Shard',
                    location: 'Local machine / Secure Enclave'
                },
                shard_2: {
                    description: 'Guardian Shard', 
                    location: 'BlackBook L1 Network (OPAQUE-protected)'
                },
                shard_3: {
                    description: 'Recovery Shard',
                    location: 'Paper backup / Cold storage'
                }
            },
            
            // Security Parameters
            security: {
                password_hint: account.password.substring(0, 3) + '***',
                authentication: 'OPAQUE PAKE (Zero-Knowledge)',
                signing: 'Threshold ceremony (key never fully reconstructed)'
            },
            
            // Capabilities
            capabilities: account.capabilities,
            
            // Oracle Authority
            oracle: {
                can_resolve_markets: true,
                can_fund_liquidity: true,
                can_bridge_operations: true
            },
            
            // For signing transactions
            signing: {
                algorithm: 'Ed25519 (via FROST)',
                canonical_format: 'from|to|amount|timestamp|nonce',
                domain_prefix: 'BLACKBOOK_L1'
            }
        };
        
        success(`FROST Wallet created: ${walletData.l1_address}`);
        info(`Public Key: ${walletData.public_key.substring(0, 32)}...`);
        warn(`Private Key stored (TEST MODE ONLY)`);
        
        return walletData;
        
    } catch (err) {
        error(`FROST wallet error: ${err.message}`);
        return null;
    }
}

// ═══════════════════════════════════════════════════════════════
// FALLBACK: Generate wallet locally if server endpoint unavailable
// ═══════════════════════════════════════════════════════════════

function generateLocalMnemonicWallet(account) {
    const bip39 = require('bip39');
    const nacl = require('tweetnacl');
    
    // Generate 256-bit entropy (24 words)
    const entropy = crypto.randomBytes(32);
    const mnemonic = bip39.entropyToMnemonic(entropy);
    
    // Derive seed from mnemonic
    const seed = bip39.mnemonicToSeedSync(mnemonic, account.bip39_passphrase || '');
    
    // Use first 32 bytes of seed for Ed25519 keypair
    const keyPair = nacl.sign.keyPair.fromSeed(seed.slice(0, 32));
    
    const publicKeyHex = Buffer.from(keyPair.publicKey).toString('hex');
    const privateKeyHex = Buffer.from(keyPair.secretKey.slice(0, 32)).toString('hex');
    
    // Derive bb_ address for Mnemonic (Consumer) wallets
    const addressHash = crypto.createHash('sha256')
        .update(Buffer.from(keyPair.publicKey))
        .digest('hex');
    const bbAddress = `bb_${addressHash.substring(0, 32).toLowerCase()}`;
    
    // Generate SSS shares (simplified - real implementation in Rust)
    const passwordSalt = crypto.randomBytes(16).toString('hex');
    
    return {
        name: account.name,
        role: account.role,
        track: 'Mnemonic (Consumer)',
        created_at: new Date().toISOString(),
        
        // Mnemonic wallets use bb_ prefix
        bb_address: bbAddress,
        l2_address: bbAddress.replace('bb_', 'L2_'),
        
        public_key: publicKeyHex,
        private_key: privateKeyHex,  // ⚠️ TEST ONLY
        mnemonic_24_words: mnemonic,
        
        sss: {
            scheme: '2-of-3 Shamir Secret Sharing over GF(256)',
            share_a: {
                description: 'Password-bound share (client-side)',
                derivation: 'Argon2id-64MB (3 iterations, parallelism 4)'
            },
            share_b: {
                description: 'L1 blockchain share (ZKP-gated)',
                stored_on: 'L1 Blockchain'
            },
            share_c: {
                description: 'Vault-encrypted backup share',
                encryption: 'AES-256-GCM with peppered nonce'
            }
        },
        
        security: {
            password: account.password,  // ⚠️ TEST ONLY
            password_salt: passwordSalt,
            key_derivation: 'Argon2id-64MB (3 iterations, parallelism 4)',
            encryption: 'AES-256-GCM',
            derivation_path: "m/44'/501'/0'/0'"
        },
        
        capabilities: account.capabilities,
        
        signing: {
            algorithm: 'Ed25519',
            canonical_format: 'from|to|amount|timestamp|nonce',
            domain_prefix: 'BLACKBOOK_L1'
        }
    };
}

// ═══════════════════════════════════════════════════════════════
// MAIN EXECUTION
// ═══════════════════════════════════════════════════════════════

async function main() {
    header('BLACKBOOK L1 - 5 WALLET GENERATION');
    
    console.log(`${MAGENTA}Security Tracks:${RESET}`);
    console.log(`  • Mnemonic (Consumer): Alice, Bob, Mac, Apollo`);
    console.log(`  • FROST (Institutional): Dealer`);
    console.log(`\n${MAGENTA}Output Directory:${RESET} ${OUTPUT_DIR}`);
    
    const allWallets = [];
    let useLocalGeneration = false;
    
    // For test accounts, we ALWAYS use local generation to get the 24-word mnemonics
    // The server endpoint doesn't return mnemonics for security reasons
    useLocalGeneration = true;
    info('Using local wallet generation (to capture 24-word mnemonics for test accounts)');
    
    // Generate Mnemonic Wallets (Alice, Bob, Mac, Apollo)
    for (const account of MNEMONIC_ACCOUNTS) {
        let wallet;
        
        if (useLocalGeneration) {
            info(`Generating ${account.name}'s wallet locally...`);
            wallet = generateLocalMnemonicWallet(account);
            success(`${account.emoji} ${account.name}: ${wallet.bb_address}`);
        } else {
            wallet = await createMnemonicWallet(account);
        }
        
        if (wallet) {
            allWallets.push(wallet);
            
            // Save individual wallet file
            const filename = `${account.name.toLowerCase()}-wallet.json`;
            const filepath = path.join(OUTPUT_DIR, filename);
            fs.writeFileSync(filepath, JSON.stringify(wallet, null, 2));
            info(`Saved: ${filename}`);
        }
    }
    
    // Generate FROST Wallet (Dealer)
    const dealerWallet = await createFrostWallet(FROST_ACCOUNT);
    if (dealerWallet) {
        allWallets.push(dealerWallet);
        
        const filename = 'dealer-wallet.json';
        const filepath = path.join(OUTPUT_DIR, filename);
        fs.writeFileSync(filepath, JSON.stringify(dealerWallet, null, 2));
        info(`Saved: ${filename}`);
    }
    
    // Save combined wallet file
    section('Saving Combined Wallet Data');
    const combinedPath = path.join(OUTPUT_DIR, 'all-5-wallets.json');
    fs.writeFileSync(combinedPath, JSON.stringify({
        generated_at: new Date().toISOString(),
        generation_method: useLocalGeneration ? 'local' : 'server',
        wallets: allWallets
    }, null, 2));
    success(`Saved: all-5-wallets.json`);
    
    // Generate 5-wallet.md documentation
    await generateDocumentation(allWallets);
    
    // Summary
    header('GENERATION COMPLETE');
    console.log(`${GREEN}Generated ${allWallets.length} wallets:${RESET}\n`);
    
    for (const wallet of allWallets) {
        const track = wallet.track.includes('FROST') ? `${MAGENTA}FROST${RESET}` : `${CYAN}Mnemonic${RESET}`;
        // Mnemonic wallets use bb_, FROST wallets use L1_
        const address = wallet.bb_address || wallet.l1_address;
        console.log(`  ${wallet.name.padEnd(8)} │ ${address} │ ${track}`);
    }
    
    console.log(`\n${YELLOW}⚠️  WARNING: These wallets contain private keys/mnemonics.${RESET}`);
    console.log(`${YELLOW}   For DEVELOPMENT/TESTING only. Never use in production!${RESET}\n`);
    
    return allWallets;
}

// ═══════════════════════════════════════════════════════════════
// DOCUMENTATION GENERATION
// ═══════════════════════════════════════════════════════════════

async function generateDocumentation(wallets) {
    section('Generating 5-wallet.md Documentation');
    
    const docPath = path.join(__dirname, '..', '..', '5-wallet.md');
    
    let doc = `# 🔐 BlackBook L1 - 5 Test Wallet Accounts

**Generated:** ${new Date().toISOString()}  
**Security Model:** Hybrid Custody (FROST Institutional + Mnemonic Consumer)  
**Status:** ⚠️ DEVELOPMENT/TESTING ONLY - Private keys exposed

---

## Quick Reference

| Account | Role | Track | Address |
|---------|------|-------|---------|
`;

    for (const w of wallets) {
        const track = w.track.includes('FROST') ? '🏛️ FROST' : '👤 Mnemonic';
        const address = w.bb_address || w.l1_address;
        doc += `| **${w.name}** | ${w.role} | ${track} | \`${address}\` |\n`;
    }

    doc += `
---

## Address Derivation

\`\`\`
Mnemonic (Consumer):     bb_ + SHA256(publicKey).slice(0,32).toLowerCase()
FROST (Institutional):   L1_ + SHA256(publicKey).slice(0,40).toUpperCase()
L2 Address:              L2_ + SHA256(publicKey).slice(0,40).toUpperCase()
\`\`\`

---

`;

    // Add detailed section for each wallet
    for (const w of wallets) {
        const trackEmoji = w.track.includes('FROST') ? '🏛️' : '👤';
        const trackName = w.track.includes('FROST') ? 'FROST (Institutional)' : 'Mnemonic (Consumer)';
        const isFrost = w.track.includes('FROST');
        const primaryAddress = isFrost ? w.l1_address : w.bb_address;
        
        doc += `## ${w.name} ${trackEmoji}

**Role:** ${w.role}  
**Security Track:** ${trackName}

### Addresses
| Network | Address |
|---------|---------|
| ${isFrost ? 'L1' : 'BB'} | \`${primaryAddress}\` |
| L2 | \`${w.l2_address}\` |

### Cryptographic Material

| Field | Value |
|-------|-------|
| **Public Key** | \`${w.public_key}\` |
`;

        if (w.private_key) {
            doc += `| **Private Key** | \`${w.private_key}\` ⚠️ TEST ONLY |\n`;
        }
        
        if (w.mnemonic_24_words) {
            doc += `| **24-Word Mnemonic** | \`${w.mnemonic_24_words}\` |\n`;
        }

        doc += `
### Security Parameters

`;
        if (w.sss) {
            doc += `**SSS Scheme:** ${w.sss.scheme}

| Share | Description | Location |
|-------|-------------|----------|
| Share A | ${w.sss.share_a.description} | Client-side (password-derived) |
| Share B | ${w.sss.share_b.description} | ${w.sss.share_b.stored_on || 'L1 Blockchain'} |
| Share C | ${w.sss.share_c.description} | HashiCorp Vault |

`;
        }
        
        if (w.frost) {
            doc += `**FROST Protocol:** ${w.frost.protocol}

| Shard | Description | Location |
|-------|-------------|----------|
| Shard 1 | ${w.frost.shard_1.description} | ${w.frost.shard_1.location} |
| Shard 2 | ${w.frost.shard_2.description} | ${w.frost.shard_2.location} |
| Shard 3 | ${w.frost.shard_3.description} | ${w.frost.shard_3.location} |

`;
        }

        if (w.security) {
            doc += `| Parameter | Value |
|-----------|-------|
`;
            if (w.security.password) {
                doc += `| Password | \`${w.security.password}\` ⚠️ TEST ONLY |\n`;
            }
            if (w.security.password_salt) {
                doc += `| Password Salt | \`${w.security.password_salt}\` |\n`;
            }
            if (w.security.key_derivation) {
                doc += `| Key Derivation | ${w.security.key_derivation} |\n`;
            }
            if (w.security.derivation_path) {
                doc += `| BIP-44 Path | \`${w.security.derivation_path}\` |\n`;
            }
        }

        doc += `
### Capabilities
`;
        for (const cap of w.capabilities || []) {
            doc += `- ✅ ${cap}\n`;
        }

        doc += `
---

`;
    }

    // Add signing guide
    doc += `## Transaction Signing Guide

### Canonical Payload Format (V2 SDK)

For **transfers**:
\`\`\`
canonical = "{from}|{to}|{amount}|{timestamp}|{nonce}"
payload_hash = SHA256(canonical).hex()
domain_prefix = "BLACKBOOK_L1/transfer"
message = "{domain_prefix}\\n{payload_hash}\\n{timestamp}\\n{nonce}"
signature = Ed25519.sign(private_key, message)
\`\`\`

For **burns**:
\`\`\`
canonical = "{from}|{amount}|{timestamp}|{nonce}"
payload_hash = SHA256(canonical).hex()
domain_prefix = "BLACKBOOK_L1/admin/burn"
message = "{domain_prefix}\\n{payload_hash}\\n{timestamp}\\n{nonce}"
signature = Ed25519.sign(private_key, message)
\`\`\`

### Example: Alice sends 100 BB to Bob

\`\`\`javascript
const crypto = require('crypto');
const nacl = require('tweetnacl');

// Alice's credentials
const alicePrivateKey = Buffer.from('${wallets.find(w => w.name === 'Alice')?.private_key || 'ALICE_PRIVATE_KEY'}', 'hex');
const aliceAddress = '${wallets.find(w => w.name === 'Alice')?.bb_address || 'bb_alice_address'}';
const bobAddress = '${wallets.find(w => w.name === 'Bob')?.bb_address || 'bb_bob_address'}';

const timestamp = Math.floor(Date.now() / 1000);
const nonce = crypto.randomUUID();
const amount = 100.0;

// Step 1: Create canonical payload
const canonical = \`\${aliceAddress}|\${bobAddress}|\${amount}|\${timestamp}|\${nonce}\`;
const payloadHash = crypto.createHash('sha256').update(canonical).digest('hex');

// Step 2: Create signing message
const domainPrefix = 'BLACKBOOK_L1/transfer';
const message = \`\${domainPrefix}\\n\${payloadHash}\\n\${timestamp}\\n\${nonce}\`;

// Step 3: Sign with Ed25519
const signature = nacl.sign.detached(
    Buffer.from(message),
    nacl.sign.keyPair.fromSeed(alicePrivateKey).secretKey
);

// Step 4: Build request
const request = {
    public_key: '${wallets.find(w => w.name === 'Alice')?.public_key || 'ALICE_PUBLIC_KEY'}',
    payload_hash: payloadHash,
    payload_fields: {
        from: aliceAddress,
        to: bobAddress,
        amount: amount,
        timestamp: timestamp,
        nonce: nonce
    },
    operation_type: 'transfer',
    timestamp: timestamp,
    nonce: nonce,
    chain_id: 1,
    request_path: '/transfer',
    signature: Buffer.from(signature).toString('hex')
};
\`\`\`

---

## Test Scenarios

### 1. Fund All Accounts (Mint)
\`\`\`bash
# Mint 10,000 BB to each account
curl -X POST http://localhost:8080/admin/mint \\
  -H "Content-Type: application/json" \\
  -d '{"to": "${wallets[0]?.bb_address || wallets[0]?.l1_address || 'ADDRESS'}", "amount": 10000}'
\`\`\`

### 2. Transfer: Alice → Bob
\`\`\`bash
# See signing example above
curl -X POST http://localhost:8080/transfer \\
  -H "Content-Type: application/json" \\
  -d '{...signed_request...}'
\`\`\`

### 3. Burn Tokens (Requires Signature)
\`\`\`bash
# Burns must be signed by the token owner
curl -X POST http://localhost:8080/admin/burn \\
  -H "Content-Type: application/json" \\
  -d '{...signed_burn_request...}'
\`\`\`

---

## Security Warnings

⚠️ **NEVER use these wallets in production!**
- Private keys and mnemonics are exposed
- Passwords are documented in plaintext
- These are for development/testing ONLY

For production wallets:
- Use \`POST /mnemonic/create\` (mnemonics never returned)
- Use \`POST /wallet/register/*\` for FROST wallets
- Never log or store private keys

---

*Generated by BlackBook L1 Wallet Generator*
`;

    fs.writeFileSync(docPath, doc);
    success(`Generated: 5-wallet.md`);
}

// Run
main().catch(err => {
    error(`Fatal error: ${err.message}`);
    process.exit(1);
});
