/**
 * ========================================================================
 * APOLLO SUPABASE SYNC TEST
 * ========================================================================
 * 
 * Test script to:
 * 1. Create Apollo user in Supabase Auth
 * 2. Store Apollo's wallet credentials in user_vault
 * 3. Verify Apollo can "login" (decrypt wallet with password)
 * 4. Test that Apollo's L1 balance/transactions are accessible
 */

import { createClient } from '@supabase/supabase-js';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ANSI colors
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const CYAN = '\x1b[36m';
const YELLOW = '\x1b[33m';
const RESET = '\x1b[0m';

// Load .env
const envPath = path.join(__dirname, '..', '..', '..', '.env');
const envContent = await fs.readFile(envPath, 'utf-8');
const env = {};
envContent.split('\n').forEach(line => {
    const trimmedLine = line.trim();
    if (!trimmedLine || trimmedLine.startsWith('#')) return;
    
    const eqIndex = trimmedLine.indexOf('=');
    if (eqIndex > 0) {
        const key = trimmedLine.substring(0, eqIndex).trim();
        const value = trimmedLine.substring(eqIndex + 1).trim();
        // Only set if key doesn't exist yet (first occurrence wins, unless it's concatenated)
        if (!env[key] || env[key].length < 50) {
            env[key] = value;
        }
    }
});

const SUPABASE_URL = env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = env.SUPABASE_SERVICE_ROLE_KEY;
const L1_URL = 'http://localhost:8080';

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    console.error(`${RED}✗ Missing Supabase credentials in .env${RESET}`);
    console.error(`  SUPABASE_URL: ${SUPABASE_URL ? 'Found' : 'Missing'}`);
    console.error(`  SUPABASE_SERVICE_ROLE_KEY: ${SUPABASE_SERVICE_ROLE_KEY ? 'Found' : 'Missing'}`);
    process.exit(1);
}

// Apollo credentials
const APOLLO_EMAIL = 'apollo@blackbook.test';
const APOLLO_PASSWORD = 'apollo_secure_password_2026';
const APOLLO_USERNAME = 'apollo';

// Supabase client (service role for setup)
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: {
        autoRefreshToken: false,
        persistSession: false
    }
});

console.log(`\n${CYAN}╔══════════════════════════════════════════════════════════════════╗${RESET}`);
console.log(`${CYAN}║          🚀 APOLLO SUPABASE SYNC TEST                            ║${RESET}`);
console.log(`${CYAN}╚══════════════════════════════════════════════════════════════════╝${RESET}\n`);

// ============================================================================
// STEP 1: Load Apollo's wallet data
// ============================================================================

console.log(`${YELLOW}STEP 1: Loading Apollo's wallet data...${RESET}`);
const walletPath = path.join(__dirname, 'apollo-wallet-data.json');
const apolloWallet = JSON.parse(await fs.readFile(walletPath, 'utf-8'));

console.log(`${GREEN}✓${RESET} Wallet loaded: ${apolloWallet.address}`);
console.log(`${GREEN}✓${RESET} Root pubkey: ${apolloWallet.rootPubkey.substring(0, 16)}...`);
console.log(`${GREEN}✓${RESET} Op pubkey: ${apolloWallet.opPubkey.substring(0, 16)}...`);

// ============================================================================
// STEP 2: Create/Get Apollo user in Supabase Auth
// ============================================================================

console.log(`\n${YELLOW}STEP 2: Creating Apollo user in Supabase Auth...${RESET}`);

let apolloUser;

// Try to create user
const { data: newUser, error: createError } = await supabase.auth.admin.createUser({
    email: APOLLO_EMAIL,
    password: APOLLO_PASSWORD,
    email_confirm: true,
    user_metadata: { username: APOLLO_USERNAME }
});

if (createError) {
    if (createError.message.includes('already registered')) {
        console.log(`${YELLOW}⚠${RESET}  User already exists, fetching...`);
        
        // Get existing user
        const { data: users } = await supabase.auth.admin.listUsers();
        apolloUser = users.users.find(u => u.email === APOLLO_EMAIL);
        
        if (!apolloUser) {
            throw new Error('User exists but could not fetch');
        }
    } else {
        throw createError;
    }
} else {
    apolloUser = newUser.user;
}

console.log(`${GREEN}✓${RESET} User ID: ${apolloUser.id}`);
console.log(`${GREEN}✓${RESET} Email: ${apolloUser.email}`);

// ============================================================================
// STEP 3: Store username in public.profiles
// ============================================================================

console.log(`\n${YELLOW}STEP 3: Storing username in public.profiles...${RESET}`);

const { data: profile, error: profileError } = await supabase
    .from('profiles')
    .upsert({
        id: apolloUser.id,
        username: APOLLO_USERNAME
    }, { onConflict: 'id' })
    .select()
    .single();

if (profileError) {
    throw new Error(`Failed to create profile: ${profileError.message}`);
}

console.log(`${GREEN}✓${RESET} Username stored: @${profile.username}`);

// ============================================================================
// STEP 4: Store encrypted wallet in user_vault
// ============================================================================

console.log(`\n${YELLOW}STEP 4: Storing encrypted wallet in user_vault...${RESET}`);

const vaultData = {
    id: apolloUser.id,
    address: apolloWallet.address,
    root_pubkey: apolloWallet.rootPubkey,
    op_pubkey: apolloWallet.opPubkey,
    salt: apolloWallet.salt,
    encrypted_op_key: apolloWallet.encryptedOpKey,
    algo_kdf: apolloWallet.keyDerivation || 'PBKDF2-SHA256-300k',
    algo_enc: apolloWallet.encryption || 'AES-256-GCM'
};

const { data: vault, error: vaultError } = await supabase
    .from('user_vault')
    .upsert(vaultData, { onConflict: 'id' })
    .select()
    .single();

if (vaultError) {
    throw new Error(`Failed to create vault: ${vaultError.message}`);
}

console.log(`${GREEN}✓${RESET} Vault created for address: ${vault.address}`);
console.log(`${GREEN}✓${RESET} Salt: ${vault.salt.substring(0, 16)}...`);
console.log(`${GREEN}✓${RESET} Encrypted op key stored (${JSON.stringify(vault.encrypted_op_key).length} bytes)`);

// ============================================================================
// STEP 5: Simulate frontend login (decrypt wallet with password)
// ============================================================================

console.log(`\n${YELLOW}STEP 5: Testing login (decrypt wallet with password)...${RESET}`);

// Import crypto functions
const crypto = await import('crypto');
const nacl = (await import('tweetnacl')).default;

// Derive encryption key from password + salt
function deriveEncryptionKey(password, saltHex) {
    return crypto.pbkdf2Sync(password, Buffer.from(saltHex, 'hex'), 300000, 32, 'sha256');
}

// Decrypt AES-256-GCM
function decryptKey(encryptedData, encryptionKey) {
    const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        encryptionKey,
        Buffer.from(encryptedData.iv, 'hex')
    );
    decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
    
    let decrypted = decipher.update(encryptedData.encrypted, 'hex');
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    
    return decrypted;
}

// Derive key and decrypt
const encryptionKey = deriveEncryptionKey(APOLLO_PASSWORD, vault.salt);
const decryptedOpKey = decryptKey(vault.encrypted_op_key, encryptionKey);

console.log(`${GREEN}✓${RESET} Password correct - operational key decrypted!`);
console.log(`${GREEN}✓${RESET} Decrypted key length: ${decryptedOpKey.length} bytes`);

// Verify we got the right key by deriving public key
const opKeyPair = nacl.sign.keyPair.fromSeed(decryptedOpKey);
const derivedPubkey = Buffer.from(opKeyPair.publicKey).toString('hex');

if (derivedPubkey === vault.op_pubkey) {
    console.log(`${GREEN}✓${RESET} Public key verification passed!`);
} else {
    throw new Error('Public key mismatch - decryption failed');
}

// ============================================================================
// STEP 6: Check Apollo's L1 balance
// ============================================================================

console.log(`\n${YELLOW}STEP 6: Checking Apollo's L1 balance...${RESET}`);

const balanceRes = await fetch(`${L1_URL}/balance/${vault.address}`);
const balanceData = await balanceRes.json();

console.log(`${GREEN}✓${RESET} Current balance: ${balanceData.balance} BB`);

// ============================================================================
// STEP 7: Get Apollo's transaction history
// ============================================================================

console.log(`\n${YELLOW}STEP 7: Fetching transaction history...${RESET}`);

const txRes = await fetch(`${L1_URL}/transactions`);
const txData = await txRes.json();

// Filter Apollo's transactions
const apolloTxs = txData.transactions?.filter(tx => 
    tx.from === vault.address || tx.to === vault.address
) || [];

console.log(`${GREEN}✓${RESET} Found ${apolloTxs.length} transactions`);

if (apolloTxs.length > 0) {
    console.log('\n  Recent transactions:');
    apolloTxs.slice(0, 5).forEach((tx, i) => {
        const type = tx.type || 'transfer';
        const amount = tx.amount || 0;
        const direction = tx.from === vault.address ? 'OUT' : 'IN';
        console.log(`  ${i + 1}. ${type.toUpperCase()} - ${direction} ${amount} BB`);
    });
}

// ============================================================================
// FINAL SUMMARY
// ============================================================================

console.log(`\n${CYAN}╔══════════════════════════════════════════════════════════════════╗${RESET}`);
console.log(`${CYAN}║                    ✅ SYNC COMPLETE!                             ║${RESET}`);
console.log(`${CYAN}╚══════════════════════════════════════════════════════════════════╝${RESET}\n`);

console.log(`${GREEN}SUPABASE SYNC RESULTS:${RESET}`);
console.log(`═══════════════════════════════════════════════════════════════════`);
console.log(`User ID:          ${apolloUser.id}`);
console.log(`Email:            ${APOLLO_EMAIL}`);
console.log(`Password:         ${APOLLO_PASSWORD}`);
console.log(`Username:         @${APOLLO_USERNAME}`);
console.log(`Wallet Address:   ${vault.address}`);
console.log(`L1 Balance:       ${balanceData.balance} BB`);
console.log(`Transactions:     ${apolloTxs.length} total`);
console.log(`═══════════════════════════════════════════════════════════════════\n`);

console.log(`${GREEN}FRONTEND-READY DATA:${RESET}`);
console.log(`  ✓ Username stored in public.profiles (searchable)`);
console.log(`  ✓ Encrypted wallet stored in user_vault (owner-only)`);
console.log(`  ✓ Login tested successfully (password decrypts wallet)`);
console.log(`  ✓ L1 balance accessible: ${balanceData.balance} BB`);
console.log(`  ✓ Transaction history accessible: ${apolloTxs.length} txs`);

console.log(`\n${GREEN}NEXT STEPS:${RESET}`);
console.log(`  → Build frontend login page`);
console.log(`  → User enters email + password`);
console.log(`  → Fetch vault data from Supabase`);
console.log(`  → Decrypt operational key client-side`);
console.log(`  → Sign transactions with decrypted key`);
console.log(`  → Display balance and transaction history\n`);
