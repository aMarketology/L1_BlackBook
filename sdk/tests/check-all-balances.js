/**
 * BlackBook L1 - Check All Account Balances
 * Displays balances for all 5 test accounts
 */

const L1_API_URL = 'http://localhost:8080';

// All 5 accounts
const accounts = [
    {
        name: 'Alice (Legacy)',
        address: 'L1_52882D768C0F3E7932AAD1813CF8B19058D507A8',
        type: 'Ed25519 Legacy'
    },
    {
        name: 'Bob (Legacy)',
        address: 'L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433',
        type: 'Ed25519 Legacy'
    },
    {
        name: 'Mac (ZKP)',
        address: 'L1_0CEB3CEC6F37F2C72CDE35231EB7A0B86AC169D5',
        type: 'ZKP Wallet v2.0'
    },
    {
        name: 'Apollo (ZKP)',
        address: 'L1_CDCFA0999FB34AD2AD226D1552B37CF9C677D342',
        type: 'ZKP Wallet v2.0'
    },
    {
        name: 'Dealer',
        address: 'L1_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D',
        type: 'Oracle/Market Maker'
    }
];

/**
 * Get balance for an address
 */
async function getBalance(address) {
    try {
        const response = await fetch(`${L1_API_URL}/balance/${address}`);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        const data = await response.json();
        return data.balance || 0;
    } catch (error) {
        return null;
    }
}

/**
 * Main function
 */
async function main() {
    console.log('\n' + '='.repeat(80));
    console.log('💰 BLACKBOOK L1 - ALL ACCOUNT BALANCES');
    console.log('='.repeat(80));
    
    let totalBalance = 0;
    const balances = [];
    
    console.log('\n');
    
    for (const account of accounts) {
        const balance = await getBalance(account.address);
        
        if (balance !== null) {
            totalBalance += balance;
            balances.push({ ...account, balance });
            
            console.log(`┌${'─'.repeat(78)}┐`);
            console.log(`│ ${account.name.padEnd(30)} │ ${account.type.padEnd(40)} │`);
            console.log(`├${'─'.repeat(78)}┤`);
            console.log(`│ Address: ${account.address.padEnd(60)} │`);
            console.log(`│ Balance: ${balance.toLocaleString().padStart(15)} BB${' '.repeat(43)} │`);
            console.log(`└${'─'.repeat(78)}┘\n`);
        } else {
            console.log(`❌ Error fetching balance for ${account.name}`);
        }
    }
    
    console.log('='.repeat(80));
    console.log(`📊 TOTAL BALANCE ACROSS ALL 5 ACCOUNTS: ${totalBalance.toLocaleString()} BB`);
    console.log('='.repeat(80));
    
    // Distribution analysis
    console.log('\n📈 BALANCE DISTRIBUTION:\n');
    
    balances.sort((a, b) => b.balance - a.balance);
    
    for (let i = 0; i < balances.length; i++) {
        const account = balances[i];
        const percentage = totalBalance > 0 ? (account.balance / totalBalance * 100).toFixed(2) : 0;
        const barLength = Math.floor(percentage / 2);
        const bar = '█'.repeat(barLength) + '░'.repeat(50 - barLength);
        
        console.log(`${(i + 1)}. ${account.name.padEnd(20)} ${account.balance.toLocaleString().padStart(12)} BB  [${bar}] ${percentage}%`);
    }
    
    console.log('\n' + '='.repeat(80) + '\n');
}

// Run
main().catch(error => {
    console.error('\n❌ Error:', error.message);
    process.exit(1);
});
