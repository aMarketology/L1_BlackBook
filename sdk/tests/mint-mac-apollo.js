/**
 * Mint tokens to Mac and Apollo ZKP wallets
 */

const L1_API_URL = 'http://localhost:8080';

const wallets = [
    {
        name: 'Mac (ZKP)',
        address: 'L1_0CEB3CEC6F37F2C72CDE35231EB7A0B86AC169D5',
        mintAmount: 25000
    },
    {
        name: 'Apollo (ZKP)',
        address: 'L1_CDCFA0999FB34AD2AD226D1552B37CF9C677D342',
        mintAmount: 25000
    }
];

async function mintTokens(wallet) {
    console.log(`\n💰 Minting ${wallet.mintAmount.toLocaleString()} BB to ${wallet.name}...`);
    console.log(`   Address: ${wallet.address}`);
    
    const requestBody = {
        to: wallet.address,
        amount: wallet.mintAmount
    };
    
    try {
        const response = await fetch(`${L1_API_URL}/admin/mint`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestBody)
        });
        
        console.log(`   Response Status: ${response.status} ${response.statusText}`);
        
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            const result = await response.json();
            if (result.balance !== undefined) {
                console.log(`   ✅ SUCCESS - New Balance: ${result.balance.toLocaleString()} BB`);
                return true;
            } else {
                console.log(`   ❌ FAILED - ${JSON.stringify(result)}`);
                return false;
            }
        } else {
            const text = await response.text();
            console.log(`   ❌ FAILED - ${text.substring(0, 200)}`);
            return false;
        }
    } catch (error) {
        console.log(`   ❌ ERROR - ${error.message}`);
        return false;
    }
}

async function main() {
    console.log('\n' + '='.repeat(70));
    console.log('  MINTING TOKENS TO MAC AND APOLLO');
    console.log('='.repeat(70));
    
    let successCount = 0;
    let totalMinted = 0;
    
    for (const wallet of wallets) {
        const success = await mintTokens(wallet);
        if (success) {
            successCount++;
            totalMinted += wallet.mintAmount;
        }
        // Small delay between mints
        await new Promise(r => setTimeout(r, 500));
    }
    
    console.log('\n' + '='.repeat(70));
    console.log(`✅ MINTING COMPLETE`);
    console.log(`   Wallets Funded: ${successCount}/${wallets.length}`);
    console.log(`   Total Minted: ${totalMinted.toLocaleString()} BB`);
    console.log('='.repeat(70) + '\n');
    
    // Show updated balances
    console.log('Checking updated balances...\n');
    for (const wallet of wallets) {
        try {
            const response = await fetch(`${L1_API_URL}/balance/${wallet.address}`);
            if (response.ok) {
                const data = await response.json();
                console.log(`${wallet.name.padEnd(15)} Balance: ${(data.balance || 0).toLocaleString().padStart(10)} BB`);
            }
        } catch (error) {
            console.log(`${wallet.name.padEnd(15)} Balance: Error fetching`);
        }
    }
    console.log('');
}

main().catch(error => {
    console.error('\n❌ Script failed:', error);
    process.exit(1);
});
