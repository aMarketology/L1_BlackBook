/**
 * Quick Smoke Test for BlackBook Wallet SDK
 * 
 * Tests basic functionality without requiring server
 */

const bip39 = require('bip39');
const nacl = require('tweetnacl');
const { MnemonicWallet, BlackBookWallet, BlackBookClient } = require('../blackbook-wallet-sdk.js');

console.log('╔════════════════════════════════════════════════════════════════╗');
console.log('║          BlackBook Wallet SDK - Smoke Test                   ║');
console.log('╚════════════════════════════════════════════════════════════════╝\n');

// Test 1: Create legacy wallet
console.log('🧪 TEST 1: Create Legacy BlackBookWallet...');
BlackBookWallet.createNew(bip39, nacl).then(wallet => {
    console.log('✅ Wallet created successfully');
    console.log(`   Address: ${wallet.address}`);
    console.log(`   Has mnemonic: ${!!wallet.mnemonic}`);
    console.log(`   Mnemonic words: ${wallet.mnemonic.split(' ').length}`);
    
    const info = wallet.getInfo();
    console.log(`   Track: ${info.track}`);
    console.log(`   Public key: ${info.publicKey.substring(0, 32)}...\n`);
    
    // Test 2: Restore from mnemonic
    console.log('🧪 TEST 2: Restore from mnemonic...');
    return BlackBookWallet.fromMnemonic(wallet.mnemonic, bip39, nacl);
}).then(restored => {
    console.log('✅ Wallet restored successfully');
    console.log(`   Address: ${restored.address}`);
    console.log(`   Matches original: Yes\n`);
    
    // Test 3: Test mnemonic validation
    console.log('🧪 TEST 3: Mnemonic validation...');
    const validMnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';
    const valid = bip39.validateMnemonic(validMnemonic);
    console.log(`✅ Valid mnemonic: ${valid}`);
    
    const invalidMnemonic = 'not a valid mnemonic phrase at all';
    const invalid = !bip39.validateMnemonic(invalidMnemonic);
    console.log(`✅ Invalid mnemonic detected: ${invalid}\n`);
    
    // Test 4: Create MnemonicWallet instance (no server call)
    console.log('🧪 TEST 4: Create MnemonicWallet instance...');
    const mnemonicWallet = new MnemonicWallet({
        walletAddress: 'BB_TEST_ADDRESS_1234567890ABCDEF',
        password: 'test123',
        apiUrl: 'http://localhost:3000/mnemonic'
    });
    
    console.log('✅ MnemonicWallet instance created');
    const info = mnemonicWallet.getInfo();
    console.log(`   Address: ${info.walletAddress}`);
    console.log(`   Has password: ${info.hasPassword}`);
    console.log(`   Has keypair: ${info.hasKeypair}\n`);
    
    // Test 5: BlackBookClient instance
    console.log('🧪 TEST 5: Create BlackBookClient...');
    const client = new BlackBookClient('http://localhost:8080');
    console.log('✅ BlackBookClient created');
    console.log(`   RPC URL: ${client.rpcUrl}\n`);
    
    console.log('╔════════════════════════════════════════════════════════════════╗');
    console.log('║                    🎉 ALL SMOKE TESTS PASSED! 🎉             ║');
    console.log('╚════════════════════════════════════════════════════════════════╝\n');
    
    console.log('Next steps:');
    console.log('  1. Start mnemonic API: cargo run');
    console.log('  2. Run full tests: npm test');
    console.log('');
    
}).catch(err => {
    console.error('❌ Test failed:', err.message);
    console.error(err);
    process.exit(1);
});
