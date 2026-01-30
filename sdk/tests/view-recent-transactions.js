/**
 * BlackBook L1 - View Recent Transactions
 * Displays the most recent transactions from the ledger
 */

const L1_API_URL = 'http://localhost:8080';

// Accounts for easy lookup
const accountNames = {
    'L1_52882D768C0F3E7932AAD1813CF8B19058D507A8': 'Alice (Legacy)',
    'L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433': 'Bob (Legacy)',
    'L1_40B59B2AE14FC3404E40477B557F6F5ED1FAC9DA': 'Alice (ZKP)',
    'L1_83474EAA6FEB5F10A673BC3F4ADC51F611EB4372': 'Bob (ZKP)',
    'L1_0CEB3CEC6F37F2C72CDE35231EB7A0B86AC169D5': 'Mac (ZKP)',
    'L1_CDCFA0999FB34AD2AD226D1552B37CF9C677D342': 'Apollo (ZKP)',
    'L1_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D': 'Dealer'
};

function formatAddress(address) {
    return accountNames[address] || address;
}

function formatTimestamp(timestamp) {
    // Handle both unix seconds and milliseconds
    const ts = timestamp > 9999999999 ? timestamp : timestamp * 1000;
    const date = new Date(ts);
    return date.toLocaleString();
}

async function viewTransactions(count = 20) {
    try {
        console.log('\n' + '='.repeat(100));
        console.log('📋 BLACKBOOK L1 - RECENT TRANSACTIONS');
        console.log('='.repeat(100));
        
        const response = await fetch(`${L1_API_URL}/transactions?limit=${count}`);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        const data = await response.json();
        const transactions = data.transactions || [];
        
        console.log(`\nTotal Transactions in System: ${data.count || 0}`);
        console.log(`Showing: Most recent ${transactions.length}\n`);
        console.log('='.repeat(100));
        
        // Sort by timestamp descending (most recent first)
        transactions.sort((a, b) => b.timestamp - a.timestamp);
        
        for (let i = 0; i < transactions.length; i++) {
            const tx = transactions[i];
            const num = i + 1;
            
            console.log(`\n${num}. Transaction Type: ${tx.tx_type.toUpperCase()}`);
            console.log(`   TX ID: ${tx.tx_id}`);
            console.log(`   Time: ${formatTimestamp(tx.timestamp)}`);
            console.log(`   From: ${formatAddress(tx.from_address)}`);
            console.log(`   To:   ${formatAddress(tx.to_address)}`);
            console.log(`   Amount: ${tx.amount.toLocaleString()} tokens`);
            console.log(`   Status: ${tx.status}`);
            
            if (tx.signature) {
                console.log(`   Signature: ${tx.signature.substring(0, 20)}...`);
            }
            
            if (tx.metadata && Object.keys(tx.metadata).length > 0) {
                console.log(`   Metadata:`);
                for (const [key, value] of Object.entries(tx.metadata)) {
                    if (key === 'payload_hash' || key === 'nonce') {
                        console.log(`     ${key}: ${value.substring(0, 16)}...`);
                    } else {
                        console.log(`     ${key}: ${value}`);
                    }
                }
            }
            
            console.log(`   ${'─'.repeat(98)}`);
        }
        
        console.log('\n' + '='.repeat(100) + '\n');
        
    } catch (error) {
        console.error('❌ Error fetching transactions:', error.message);
    }
}

// Get count from command line or default to 20
const count = parseInt(process.argv[2]) || 20;
viewTransactions(count);
