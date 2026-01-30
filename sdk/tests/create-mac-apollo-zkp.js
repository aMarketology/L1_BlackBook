#!/usr/bin/env node

/**
 * Create ZKP Wallets for Mac and Apollo
 * Uses passwords from existing wallet documentation
 */

const fs = require('fs');
const path = require('path');
const { ZKPWallet } = require('../zkp-wallet-sdk.js');

// Colors for terminal output
const colors = {
    reset: '\x1b[0m',
    bright: '\x1b[1m',
    green: '\x1b[32m',
    red: '\x1b[31m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    cyan: '\x1b[36m',
};

// Passwords from documentation
const PASSWORDS = {
    mac: 'MacSecurePassword2026!',      // From macwallet.txt
    apollo: 'apollo_secure_password_2026'  // From apollo.txt
};

// L1 Server URL
const L1_URL = 'http://localhost:3030';

/**
 * Create a new ZKP wallet and register on L1
 */
async function createAndRegisterWallet(name, password) {
    console.log(`\n${colors.cyan}🔐 Creating ZKP wallet for ${name}...${colors.reset}`);
    
    try {
        // Create wallet (username, password, optional pepper)
        const result = await ZKPWallet.create(name.toLowerCase(), password);
        
        console.log(`   ${colors.green}✓${colors.reset} Wallet created!`);
        console.log(`   ${colors.bright}Address:${colors.reset} ${result.wallet.address}`);
        console.log(`   ${colors.bright}Public Key:${colors.reset} ${result.wallet.pubkey}`);
        
        // Save wallet data
        const walletData = {
            version: result.wallet.version,
            address: result.wallet.address,
            pubkey: result.wallet.pubkey,
            zkCommitment: result.wallet.zkCommitment,
            salt: result.wallet.salt,
            shareCEncrypted: result.shareCEncrypted,
            keyDerivation: result.wallet.keyDerivation,
            encryption: result.wallet.encryption,
            sss: result.wallet.sss,
            created: result.wallet.created,
            name: name
        };
        
        const filename = `${name.toLowerCase()}-zkp-wallet.json`;
        const filepath = path.join(__dirname, filename);
        fs.writeFileSync(filepath, JSON.stringify(walletData, null, 2));
        console.log(`   ${colors.green}💾 Saved to:${colors.reset} ${filename}`);
        
        // Register on L1
        try {
            const fetch = require('node-fetch');
            
            const registerPayload = {
                address: result.wallet.address,
                pubkey: result.wallet.pubkey,
                zkCommitment: result.wallet.zkCommitment,
                shareB: result.shareB
            };
            
            const response = await fetch(`${L1_URL}/auth/zkp-register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(registerPayload)
            });
            
            if (response.ok) {
                const result = await response.json();
                console.log(`   ${colors.green}✓ Registered on L1${colors.reset}`);
                return { success: true, wallet: walletData, password };
            } else {
                const error = await response.text();
                console.log(`   ${colors.yellow}⚠ L1 registration failed:${colors.reset} ${error}`);
                return { success: false, wallet: walletData, password, error };
            }
        } catch (err) {
            console.log(`   ${colors.yellow}⚠ L1 connection failed:${colors.reset} ${err.message}`);
            return { success: false, wallet: walletData, password, error: err.message };
        }
        
    } catch (error) {
        console.log(`   ${colors.red}✗ Failed:${colors.reset} ${error.message}`);
        return { success: false, error: error.message };
    }
}

/**
 * Test wallet login
 */
async function testWalletLogin(name, walletData, password) {
    console.log(`\n${colors.cyan}🧪 Testing ${name} login...${colors.reset}`);
    
    try {
        // For testing, we need Share B - in production this comes from L1 after ZK-proof
        // For now, we'll just verify the wallet data is valid by checking fields
        if (walletData.address && walletData.pubkey && walletData.shareCEncrypted && walletData.salt) {
            console.log(`   ${colors.green}✓ Wallet data valid${colors.reset}`);
            console.log(`   ${colors.bright}Address:${colors.reset} ${walletData.address}`);
            return true;
        } else {
            console.log(`   ${colors.red}✗ Wallet data incomplete${colors.reset}`);
            return false;
        }
    } catch (error) {
        console.log(`   ${colors.red}✗ Validation failed:${colors.reset} ${error.message}`);
        return false;
    }
}

/**
 * Main execution
 */
async function main() {
    console.log(`${colors.bright}╔═══════════════════════════════════════════════════════════╗${colors.reset}`);
    console.log(`${colors.bright}║   BlackBook L1 - Create Mac & Apollo ZKP Wallets        ║${colors.reset}`);
    console.log(`${colors.bright}╚═══════════════════════════════════════════════════════════╝${colors.reset}`);
    console.log(`\nL1 Server: ${colors.cyan}${L1_URL}${colors.reset}`);
    
    const results = {};
    
    // Create Mac wallet
    results.mac = await createAndRegisterWallet('Mac', PASSWORDS.mac);
    
    // Create Apollo wallet
    results.apollo = await createAndRegisterWallet('Apollo', PASSWORDS.apollo);
    
    // Test logins
    console.log(`\n${colors.bright}═══════════════════════════════════════════════════════════${colors.reset}`);
    console.log(`${colors.bright}🧪 Testing Wallet Logins${colors.reset}`);
    console.log(`${colors.bright}═══════════════════════════════════════════════════════════${colors.reset}`);
    
    if (results.mac.wallet) {
        await testWalletLogin('Mac', results.mac.wallet, results.mac.password);
    }
    
    if (results.apollo.wallet) {
        await testWalletLogin('Apollo', results.apollo.wallet, results.apollo.password);
    }
    
    // Summary
    console.log(`\n${colors.bright}╔═══════════════════════════════════════════════════════════╗${colors.reset}`);
    console.log(`${colors.bright}║                    📊 SUMMARY                             ║${colors.reset}`);
    console.log(`${colors.bright}╚═══════════════════════════════════════════════════════════╝${colors.reset}`);
    
    if (results.mac.wallet) {
        console.log(`\n${colors.green}✓ Mac Wallet${colors.reset}`);
        console.log(`  Address:  ${results.mac.wallet.address}`);
        console.log(`  Password: ${results.mac.password}`);
        console.log(`  L1 Status: ${results.mac.success ? colors.green + 'Registered' + colors.reset : colors.yellow + 'Local Only' + colors.reset}`);
    }
    
    if (results.apollo.wallet) {
        console.log(`\n${colors.green}✓ Apollo Wallet${colors.reset}`);
        console.log(`  Address:  ${results.apollo.wallet.address}`);
        console.log(`  Password: ${results.apollo.password}`);
        console.log(`  L1 Status: ${results.apollo.success ? colors.green + 'Registered' + colors.reset : colors.yellow + 'Local Only' + colors.reset}`);
    }
    
    // Export credentials for integration tests
    const credentials = {
        mac: {
            address: results.mac.wallet?.address,
            password: results.mac.password,
            file: 'mac-zkp-wallet.json'
        },
        apollo: {
            address: results.apollo.wallet?.address,
            password: results.apollo.password,
            file: 'apollo-zkp-wallet.json'
        }
    };
    
    fs.writeFileSync(
        path.join(__dirname, 'mac-apollo-credentials.json'),
        JSON.stringify(credentials, null, 2)
    );
    
    console.log(`\n${colors.green}💾 Credentials saved to: mac-apollo-credentials.json${colors.reset}`);
    console.log(`\n${colors.bright}Next step: Run integration tests with all wallets${colors.reset}`);
}

main().catch(console.error);
