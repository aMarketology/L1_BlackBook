import { UnifiedWallet, CHAIN_ID_L1, CHAIN_ID_L2 } from '../sdk/unified-wallet-sdk.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// Load .env manually since we are in a module
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const envPath = path.resolve(__dirname, '../.env');
if (fs.existsSync(envPath)) {
    const envConfig = fs.readFileSync(envPath, 'utf8');
    envConfig.split('\n').forEach(line => {
        const [key, value] = line.split('=');
        if (key && value) {
            process.env[key.trim()] = value.trim();
        }
    });
}

const ADMIN_URL = 'http://localhost:8080/admin/mint';

async function mint(address, amount) {
    console.log(`💰 Minting ${amount} BB to ${address}...`);
    const response = await fetch(ADMIN_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ to: address, amount: amount })
    });
    const data = await response.json();
    if (data.success) {
        console.log(`   ✅ Minted! Tx: ${data.transaction.id}`);
    } else {
        console.error(`   ❌ Mint failed: ${data.error}`);
    }
    return data.success;
}

async function runTest() {
    console.log('🚀 STARTING DEALER INTEGRATION TEST');
    console.log('===================================');

    // 1. Connect Alice
    console.log('\n👤 Connecting Alice...');
    const alice = await UnifiedWallet.connect('alice');
    console.log(`   Address: ${alice.address}`);
    console.log(`   Balance: ${alice.balance} BB`);

    // 2. Connect Dealer
    console.log('\n🃏 Connecting Dealer...');
    // Ensure private key is available
    if (!process.env.DEALER_PRIVATE_KEY) {
        console.error('❌ DEALER_PRIVATE_KEY not found in .env');
        process.exit(1);
    }
    const dealer = await UnifiedWallet.connect('dealer');
    console.log(`   Address: ${dealer.address}`);
    console.log(`   Balance: ${dealer.balance} BB`);

    // 3. Mint funds
    await mint(alice.address, 1000);
    await mint(dealer.address, 10000);

    // Refresh balances
    await alice.refresh();
    await dealer.refresh();
    console.log(`\n💰 Alice Balance: ${alice.balance} BB`);
    console.log(`💰 Dealer Balance: ${dealer.balance} BB`);

    // 4. Alice sends to Dealer (Bet)
    console.log('\n🎲 Alice placing bet (Transfer to Dealer)...');
    try {
        const betAmount = 50;
        const result = await alice.transfer(dealer.address, betAmount);
        console.log(`   ✅ Transfer successful! Tx: ${result.transaction_id}`);
    } catch (e) {
        console.error(`   ❌ Transfer failed: ${e.message}`);
        process.exit(1);
    }

    // 5. Dealer sends to Alice (Win)
    console.log('\n🏆 Dealer paying out (Transfer to Alice)...');
    try {
        const winAmount = 100; // 2x payout
        const result = await dealer.transfer(alice.address, winAmount);
        console.log(`   ✅ Payout successful! Tx: ${result.transaction_id}`);
    } catch (e) {
        console.error(`   ❌ Payout failed: ${e.message}`);
        process.exit(1);
    }

    // 6. Final Balances
    await alice.refresh();
    await dealer.refresh();
    console.log('\n📊 FINAL BALANCES:');
    console.log(`   Alice:  ${alice.balance} BB`);
    console.log(`   Dealer: ${dealer.balance} BB`);
    
    console.log('\n✅ TEST COMPLETED SUCCESSFULLY');
}

runTest().catch(console.error);
