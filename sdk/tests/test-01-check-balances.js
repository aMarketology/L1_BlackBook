/**
 * TEST 1: Check Balances for All 5 Wallets
 * Apollo, Mac, Alice, Bob, Dealer
 */

const L1_API_URL = 'http://localhost:8080';

const wallets = {
    alice: {
        name: 'Alice',
        address: 'L1_52882D768C0F3E7932AAD1813CF8B19058D507A8',
        type: 'Legacy Ed25519'
    },
    bob: {
        name: 'Bob',
        address: 'L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433',
        type: 'Legacy Ed25519'
    },
    mac: {
        name: 'Mac',
        address: 'L1_94B3C863E068096596CE80F04C2233B72AE11790',
        type: 'ZKP Vault (AES-GCM)'
    },
    apollo: {
        name: 'Apollo',
        address: 'L1_47597088CDD24661AAA867D44CBBF6519635338C',
        type: 'ZKP Vault (SSS 2-of-3)'
    },
    dealer: {
        name: 'Dealer',
        address: 'L1_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D',
        type: 'Legacy Ed25519'
    }
};

async function getBalance(address) {
    try {
        const response = await fetch(`${L1_API_URL}/balance/${address}`);
        if (!response.ok) return null;
        const data = await response.json();
        return data.balance || 0;
    } catch (error) {
        return null;
    }
}

async function main() {
    console.log('\n' + '='.repeat(80));
    console.log('TEST 1: CHECK BALANCES - ALL 5 WALLETS');
    console.log('='.repeat(80));
    console.log('Wallets: Apollo, Mac, Alice, Bob, Dealer\n');
    
    let total = 0;
    const balances = [];
    
    for (const [key, wallet] of Object.entries(wallets)) {
        const balance = await getBalance(wallet.address);
        if (balance !== null) {
            total += balance;
            balances.push({ ...wallet, balance });
        }
    }
    
    // Display table
    console.log('┌────────────┬──────────────────────────────────────────────┬──────────────────────┬───────────────┐');
    console.log('│   Wallet   │                   Address                    │         Type         │    Balance    │');
    console.log('├────────────┼──────────────────────────────────────────────┼──────────────────────┼───────────────┤');
    
    for (const wallet of balances) {
        const nameCol = wallet.name.padEnd(10);
        const addressCol = wallet.address.padEnd(44);
        const typeCol = wallet.type.padEnd(20);
        const balanceCol = (wallet.balance.toLocaleString() + ' BB').padStart(13);
        console.log(`│ ${nameCol} │ ${addressCol} │ ${typeCol} │ ${balanceCol} │`);
    }
    
    console.log('├────────────┴──────────────────────────────────────────────┴──────────────────────┼───────────────┤');
    console.log(`│ TOTAL BALANCE                                                                    │ ${(total.toLocaleString() + ' BB').padStart(13)} │`);
    console.log('└──────────────────────────────────────────────────────────────────────────────────┴───────────────┘');
    
    // Distribution analysis
    console.log('\n📊 Distribution Analysis:');
    for (const wallet of balances) {
        const percentage = total > 0 ? (wallet.balance / total * 100).toFixed(2) : 0;
        const barLength = Math.floor(percentage / 2);
        const bar = '█'.repeat(barLength) + '░'.repeat(50 - barLength);
        console.log(`${wallet.name.padEnd(10)} ${bar} ${percentage}%`);
    }
    
    console.log('\n✅ TEST 1 COMPLETE\n');
}

main().catch(error => {
    console.error('\n❌ Test failed:', error);
    process.exit(1);
});
