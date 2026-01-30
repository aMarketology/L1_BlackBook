/**
 * Create ZKP Wallets for Test Accounts
 * 
 * This script creates fresh ZKP wallets for Alice, Bob, Apollo, and Dealer
 * and registers them on the L1 server.
 */

const fs = require('fs');
const path = require('path');
const { ZKPWallet } = require('../zkp-wallet-sdk');

// Configuration
const TEST_PEPPER = process.env.SHARE_C_PEPPER || 'TEST_PEPPER_SECRET_DO_NOT_USE_IN_PRODUCTION';
const L1_API_URL = process.env.L1_API_URL || 'http://localhost:3030';

// Test account passwords
const WALLETS = [
  { name: 'Alice', username: 'alice', password: 'AlicePassword123!' },
  { name: 'Bob', username: 'bob', password: 'BobPassword123!' },
  { name: 'Apollo', username: 'apollo', password: 'ApolloPassword123!' },
  { name: 'Dealer', username: 'dealer', password: 'DealerPassword123!' },
];

async function createAndRegisterWallet(name, username, password) {
  console.log(`\n🔐 Creating ${name}'s ZKP wallet...`);
  
  try {
    // Create wallet
    const walletData = await ZKPWallet.create(username, password, TEST_PEPPER);
    
    console.log(`   ✅ Wallet created!`);
    console.log(`      Address: ${walletData.wallet.address}`);
    console.log(`      Public Key: ${walletData.wallet.pubkey.substring(0, 16)}...`);
    console.log(`      ZK-Commitment: ${walletData.wallet.zkCommitment.substring(0, 16)}...`);
    
    // Save wallet locally
    const outputPath = path.join(__dirname, `${username}-zkp-wallet.json`);
    const outputData = {
      ...walletData.wallet,
      shareCEncrypted: walletData.shareCEncrypted,
      _password: password, // TESTING ONLY - never store passwords in production!
      _note: "Share A derived from password. Share B on L1. Share C here (encrypted).",
    };
    
    fs.writeFileSync(outputPath, JSON.stringify(outputData, null, 2));
    console.log(`   💾 Saved to: ${outputPath}`);
    
    // Register on L1
    console.log(`   📡 Registering on L1...`);
    
    const now = Math.floor(Date.now() / 1000);
    const registrationData = {
      address: walletData.wallet.address,
      pubkey: walletData.wallet.pubkey,
      zk_commitment: walletData.wallet.zkCommitment,
      salt: walletData.wallet.salt,
      share_b: walletData.shareB,
      registered_at: now,
      key_derivation: walletData.wallet.keyDerivation,
      sss: walletData.wallet.sss,
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
        console.log(`      ✅ Registered on L1!`);
        console.log(`      Share B stored on-chain`);
      } else {
        console.error(`      ❌ Registration failed: ${result.error}`);
      }
    } catch (error) {
      console.error(`      ❌ L1 connection failed: ${error.message}`);
      console.log(`      ⚠️  Start L1 server with: cargo run`);
    }
    
    return walletData;
    
  } catch (error) {
    console.error(`   ❌ Failed: ${error.message}`);
    throw error;
  }
}

async function main() {
  console.log('╔═══════════════════════════════════════════════════════════╗');
  console.log('║   BlackBook L1 - Create ZKP Test Wallets                ║');
  console.log('╚═══════════════════════════════════════════════════════════╝');
  
  const createdWallets = [];
  
  for (const { name, username, password } of WALLETS) {
    try {
      const wallet = await createAndRegisterWallet(name, username, password);
      createdWallets.push({ name, username, password, wallet });
    } catch (error) {
      console.error(`${name} creation failed:`, error.message);
    }
  }
  
  // Summary
  console.log('\n' + '='.repeat(60));
  console.log('📊 Summary');
  console.log('='.repeat(60));
  console.log(`Created ${createdWallets.length} wallets:\n`);
  
  createdWallets.forEach(({ name, username, password, wallet }) => {
    console.log(`${name}:`);
    console.log(`  Username: ${username}`);
    console.log(`  Password: ${password}`);
    console.log(`  Address: ${wallet.wallet.address}`);
    console.log(`  File: sdk/tests/${username}-zkp-wallet.json\n`);
  });
  
  console.log('✅ All wallets created!');
  console.log('\n💡 Next steps:');
  console.log('   1. Ensure L1 server is running: cargo run');
  console.log('   2. Run integration tests: node sdk/tests/test-zkp-integration.js');
}

if (require.main === module) {
  main().catch(error => {
    console.error('\n❌ Failed:', error);
    process.exit(1);
  });
}

module.exports = { createAndRegisterWallet };
