/**
 * TEST 0: Mint Initial Funds
 * Give all 5 wallets starting balances with varying amounts
 */

const L1_API_URL = 'http://localhost:8080';

const wallets = {
    alice: {
        name: 'Alice',
        address: 'L1_52882D768C0F3E7932AAD1813CF8B19058D507A8',
        mintAmount: 20000
    },
    bob: {
        name: 'Bob',
        address: 'L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433',
        mintAmount: 15000
    },
    mac: {
        name: 'Mac',
        address: 'L1_94B3C863E068096596CE80F04C2233B72AE11790',
        mintAmount: 10000
    },
    apollo: {
        name: 'Apollo',
        address: 'L1_47597088CDD24661AAA867D44CBBF6519635338C',
        mintAmount: 12000
    },
    dealer: {
        name: 'Dealer',
        address: 'L1_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D',
        mintAmount: 5000
    }
};

async function mintTokens(wallet, amount) {
    const requestBody = {
        to: wallet.address,
        amount: amount
    };
    
    const response = await fetch(`${L1_API_URL}/admin/mint`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody)
    });
    
    console.log(`   Response Status: ${response.status} ${response.statusText}`);
    
    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
        const result = await response.json();
        return result;
    } else {
        const text = await response.text();
        console.log(`   Response Text:`, text.substring(0, 200));
        return { success: false, error: text };
    }
}

async function main() {
    console.log('\n' + '='.repeat(80));
    console.log('TEST 0: MINT INITIAL FUNDS');
    console.log('='.repeat(80));
    console.log('Minting varying amounts to all 5 wallets\n');
    
    let totalMinted = 0;
    let successCount = 0;
    
    for (const [key, wallet] of Object.entries(wallets)) {
        console.log(`💰 Minting ${wallet.mintAmount.toLocaleString()} BB to ${wallet.name}...`);
        let result = await mintTokens(wallet, wallet.mintAmount);
        if (result.success !== false) {
            console.log(`   ✅ SUCCESS - Balance: ${result.balance} BB\n`);
            totalMinted += wallet.mintAmount;
            successCount++;
        } else {
            console.log(`   ❌ FAILED - ${result.error}\n`);
        }
        await new Promise(r => setTimeout(r, 300));
    }
    
    console.log('='.repeat(80));
    console.log(`✅ TEST 0 COMPLETE`);
    console.log(`   Wallets Funded: ${successCount}/5`);
    console.log(`   Total Minted: ${totalMinted.toLocaleString()} BB`);
    console.log('='.repeat(80) + '\n');
}

main().catch(error => {
    console.error('\n❌ Test failed:', error);
    process.exit(1);
});
