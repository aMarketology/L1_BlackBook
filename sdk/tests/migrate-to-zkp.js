/**
 * Migrate Legacy Wallets to ZKP Format
 * 
 * This script migrates existing wallets (Alice, Bob, Apollo, Mac) from the old
 * PBKDF2/BIP39 format to the new ZKP + SSS non-custodial format.
 * 
 * Migration Process:
 * 1. Load legacy wallet with password
 * 2. Decrypt and recover original private key
 * 3. Generate new ZK-commitment
 * 4. Split key into 3 SSS shares (A/B/C)
 * 5. Register Share B on L1
 * 6. Store Share C (encrypted) for Supabase
 * 7. Save new wallet format
 */

const fs = require('fs');
const path = require('path');
const {
  ZKPWallet,
  migrateLegacyWallet,
  generateKeypair,
  deriveAddress,
} = require('../zkp-wallet-sdk');

// Configuration
const TEST_PEPPER = process.env.SHARE_C_PEPPER || 'TEST_PEPPER_SECRET_DO_NOT_USE_IN_PRODUCTION';
const L1_API_URL = process.env.L1_API_URL || 'http://localhost:3030';

// Test account passwords (for migration)
const TEST_PASSWORDS = {
  apollo: 'ApolloPassword123!',
  alice: 'AlicePassword123!',
  bob: 'BobPassword123!',
  mac: 'MacPassword123!',
  dealer: 'DealerPassword123!',
};

// =============================================================================
// MIGRATION FUNCTIONS
// =============================================================================

/**
 * Migrate a single legacy wallet
 */
async function migrateWallet(name, legacyWalletPath, password) {
  console.log(`\n🔄 Migrating ${name}...`);
  
  try {
    // Load legacy wallet
    const legacyData = JSON.parse(fs.readFileSync(legacyWalletPath, 'utf8'));
    console.log(`   📂 Loaded legacy wallet: ${legacyData.address}`);
    console.log(`   🔑 Key derivation: ${legacyData.keyDerivation}`);
    
    // Migrate to ZKP format
    console.log(`   ⚙️  Migrating to ZKP format...`);
    const migratedData = await migrateLegacyWallet(legacyData, password, TEST_PEPPER);
    
    console.log(`   ✅ Migration successful!`);
    console.log(`      Address: ${migratedData.wallet.address}`);
    console.log(`      ZK-Commitment: ${migratedData.wallet.zkCommitment.substring(0, 16)}...`);
    console.log(`      Share A: Derived from password (not stored)`);
    console.log(`      Share B: ${migratedData.shareB.y.substring(0, 16)}... (x=${migratedData.shareB.x})`);
    console.log(`      Share C: ${migratedData.shareCEncrypted.encrypted.substring(0, 16)}... (encrypted)`);
    
    // Save migrated wallet
    const outputPath = path.join(path.dirname(legacyWalletPath), `${name.toLowerCase()}-zkp-wallet.json`);
    const outputData = {
      ...migratedData.wallet,
      shareCEncrypted: migratedData.shareCEncrypted,
      _note: "Share A derived from password. Share B on L1. Share C here (encrypted).",
      _migration: {
        from: legacyData.keyDerivation,
        to: migratedData.wallet.keyDerivation,
        date: new Date().toISOString(),
      }
    };
    
    fs.writeFileSync(outputPath, JSON.stringify(outputData, null, 2));
    console.log(`   💾 Saved to: ${outputPath}`);
    
    // Register on L1
    console.log(`   📡 Registering on L1...`);
    const registered = await registerOnL1(migratedData);
    
    if (registered) {
      console.log(`   ✅ ${name} successfully migrated and registered!`);
    } else {
      console.log(`   ⚠️  ${name} migrated locally but L1 registration failed (L1 may not be running)`);
    }
    
    return migratedData;
    
  } catch (error) {
    console.error(`   ❌ Migration failed: ${error.message}`);
    throw error;
  }
}

/**
 * Register migrated wallet on L1
 */
async function registerOnL1(migratedData) {
  const { wallet, shareB } = migratedData;
  
  const now = Math.floor(Date.now() / 1000);
  const registrationData = {
    address: wallet.address,
    pubkey: wallet.pubkey,
    zk_commitment: wallet.zkCommitment,
    salt: wallet.salt,
    share_b: shareB,
    registered_at: now,
    key_derivation: wallet.keyDerivation,
    sss: wallet.sss,
  };
  
  try {
    const fetch = require('node-fetch');
    const response = await fetch(`${L1_API_URL}/auth/zkp-register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(registrationData),
    });
    
    const result = await response.json();
    
    if (result.success) {
      console.log(`      ✓ Share B registered on L1`);
      return true;
    } else {
      console.error(`      ✗ L1 registration failed: ${result.error}`);
      return false;
    }
  } catch (error) {
    console.error(`      ✗ L1 connection failed: ${error.message}`);
    return false;
  }
}

/**
 * Create a brand new ZKP wallet (not migration, fresh creation)
 */
async function createNewZKPWallet(name, password) {
  console.log(`\n🆕 Creating new ZKP wallet for ${name}...`);
  
  try {
    const walletData = await ZKPWallet.create(name.toLowerCase(), password, TEST_PEPPER);
    
    console.log(`   ✅ Wallet created!`);
    console.log(`      Address: ${walletData.wallet.address}`);
    console.log(`      Public Key: ${walletData.wallet.pubkey.substring(0, 16)}...`);
    console.log(`      ZK-Commitment: ${walletData.wallet.zkCommitment.substring(0, 16)}...`);
    
    // Save wallet
    const outputPath = path.join(__dirname, `${name.toLowerCase()}-zkp-wallet.json`);
    const outputData = {
      ...walletData.wallet,
      shareCEncrypted: walletData.shareCEncrypted,
      _note: "Share A derived from password. Share B on L1. Share C here (encrypted).",
    };
    
    fs.writeFileSync(outputPath, JSON.stringify(outputData, null, 2));
    console.log(`   💾 Saved to: ${outputPath}`);
    
    // Register on L1
    console.log(`   📡 Registering on L1...`);
    const registered = await registerOnL1(walletData);
    
    if (registered) {
      console.log(`   ✅ ${name} successfully created and registered!`);
    }
    
    return walletData;
    
  } catch (error) {
    console.error(`   ❌ Creation failed: ${error.message}`);
    throw error;
  }
}

/**
 * Test a migrated wallet login
 */
async function testWalletLogin(name, walletPath, password) {
  console.log(`\n🧪 Testing ${name} login...`);
  
  try {
    // Load wallet
    const walletData = JSON.parse(fs.readFileSync(walletPath, 'utf8'));
    
    // Fetch Share B from L1
    const fetch = require('node-fetch');
    const commitment = walletData.zkCommitment;
    const salt = walletData.salt;
    
    // Generate ZK-proof
    const { generateZKCommitment, generateZKProof, deriveShareA } = require('../zkp-wallet-sdk');
    const crypto = require('crypto');
    
    const nonce = crypto.randomBytes(16).toString('hex');
    const proof = generateZKProof(name.toLowerCase(), password, salt, commitment, nonce);
    
    console.log(`   🔐 Generated ZK-proof`);
    
    // Login request
    const loginRequest = {
      address: walletData.address,
      zk_proof: proof,
      nonce: nonce,
    };
    
    const response = await fetch(`${L1_API_URL}/auth/zkp-login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(loginRequest),
    });
    
    const result = await response.json();
    
    if (result.success) {
      console.log(`   ✅ Login successful!`);
      console.log(`      Share B received: ${result.share_b.y.substring(0, 16)}...`);
      
      // Reconstruct key with Share A + Share B
      const { sssReconstruct } = require('../zkp-wallet-sdk');
      const shareA = await deriveShareA(password, Buffer.from(salt, 'hex'));
      const shares = [
        { x: 1, y: shareA.toString('hex') },
        result.share_b,
      ];
      
      const reconstructedSecret = sssReconstruct(shares);
      console.log(`   🔑 Key reconstructed: ${reconstructedSecret.toString('hex').substring(0, 16)}...`);
      
      // Verify keypair matches
      const keypair = generateKeypair(reconstructedSecret);
      if (keypair.publicKey === walletData.pubkey) {
        console.log(`   ✅ Keypair verification passed!`);
      } else {
        console.log(`   ❌ Keypair mismatch!`);
      }
      
      return true;
    } else {
      console.log(`   ❌ Login failed: ${result.error}`);
      return false;
    }
    
  } catch (error) {
    console.error(`   ❌ Test failed: ${error.message}`);
    return false;
  }
}

// =============================================================================
// MAIN MIGRATION SCRIPT
// =============================================================================

async function main() {
  console.log('╔═══════════════════════════════════════════════════════════╗');
  console.log('║   BlackBook L1 - Wallet Migration to ZKP Format         ║');
  console.log('║   Legacy PBKDF2/BIP39 → ZKP + SSS + Argon2id            ║');
  console.log('╚═══════════════════════════════════════════════════════════╝');
  
  const migratedWallets = [];
  
  // Apollo wallet (if exists)
  const apolloPath = path.join(__dirname, 'apollo', 'apollo-wallet-data.json');
  if (fs.existsSync(apolloPath)) {
    try {
      const apollo = await migrateWallet('Apollo', apolloPath, TEST_PASSWORDS.apollo);
      migratedWallets.push({ name: 'Apollo', data: apollo });
    } catch (error) {
      console.error(`Apollo migration failed: ${error.message}`);
    }
  } else {
    console.log(`\n⚠️  Apollo wallet not found at ${apolloPath}`);
  }
  
  // Create new ZKP wallets for Alice, Bob, Dealer (they don't have legacy wallets)
  console.log('\n' + '='.repeat(60));
  console.log('Creating NEW ZKP wallets for test accounts...');
  console.log('='.repeat(60));
  
  try {
    const alice = await createNewZKPWallet('Alice', TEST_PASSWORDS.alice);
    migratedWallets.push({ name: 'Alice', data: alice });
  } catch (error) {
    console.error(`Alice creation failed: ${error.message}`);
  }
  
  try {
    const bob = await createNewZKPWallet('Bob', TEST_PASSWORDS.bob);
    migratedWallets.push({ name: 'Bob', data: bob });
  } catch (error) {
    console.error(`Bob creation failed: ${error.message}`);
  }
  
  try {
    const dealer = await createNewZKPWallet('Dealer', TEST_PASSWORDS.dealer);
    migratedWallets.push({ name: 'Dealer', data: dealer });
  } catch (error) {
    console.error(`Dealer creation failed: ${error.message}`);
  }
  
  // Summary
  console.log('\n' + '='.repeat(60));
  console.log('📊 Migration Summary');
  console.log('='.repeat(60));
  console.log(`Total wallets processed: ${migratedWallets.length}`);
  
  migratedWallets.forEach(({ name, data }) => {
    console.log(`\n${name}:`);
    console.log(`  Address: ${data.wallet.address}`);
    console.log(`  Key Derivation: ${data.wallet.keyDerivation}`);
    console.log(`  SSS: ${data.wallet.sss}`);
    console.log(`  Password: ${TEST_PASSWORDS[name.toLowerCase()]}`);
  });
  
  // Test logins (if L1 is running)
  console.log('\n' + '='.repeat(60));
  console.log('🧪 Testing Logins (requires L1 running)');
  console.log('='.repeat(60));
  
  for (const { name, data } of migratedWallets) {
    const walletPath = path.join(__dirname, `${name.toLowerCase()}-zkp-wallet.json`);
    if (fs.existsSync(walletPath)) {
      await testWalletLogin(name, walletPath, TEST_PASSWORDS[name.toLowerCase()]);
    }
  }
  
  console.log('\n✅ Migration complete!');
  console.log('\n💡 Next steps:');
  console.log('   1. Start L1 server: cargo run');
  console.log('   2. Test wallets with: node sdk/tests/test-zkp-integration.js');
  console.log('   3. Update frontend to use new ZKP auth flow');
}

// Run migration
if (require.main === module) {
  main().catch(error => {
    console.error('\n❌ Migration failed:', error);
    process.exit(1);
  });
}

module.exports = {
  migrateWallet,
  createNewZKPWallet,
  testWalletLogin,
};
