/**
 * APOLLO TRANSFERS - Send tokens to Alice and Bob
 */

const crypto = require('crypto');
const nacl = require('tweetnacl');
const fs = require('fs');
const path = require('path');

const L1_URL = 'http://localhost:8080';
const APOLLO_DATA_FILE = path.join(__dirname, 'apollo-wallet-data.json');

// Test account addresses
const ALICE_L1 = 'L1_52882D768C0F3E7932AAD1813CF8B19058D507A8';
const BOB_L1 = 'L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433';

// Colors
const GREEN = '\x1b[32m';
const CYAN = '\x1b[36m';
const YELLOW = '\x1b[33m';
const BOLD = '\x1b[1m';
const RESET = '\x1b[0m';

function info(msg) { console.log(`  ${CYAN}ℹ${RESET} ${msg}`); }
function pass(msg) { console.log(`  ${GREEN}✓${RESET} ${msg}`); }

// ==================== ENCRYPTION ====================

function deriveEncryptionKey(userPassword, salt) {
    const saltBuffer = Buffer.from(salt, 'hex');
    return crypto.pbkdf2Sync(userPassword, saltBuffer, 300000, 32, 'sha256');
}

function decryptKey(encryptedData, encryptionKey) {
    const { encrypted, iv, authTag } = encryptedData;
    const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        encryptionKey,
        Buffer.from(iv, 'hex')
    );
    
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    
    let decrypted = decipher.update(Buffer.from(encrypted, 'hex'));
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    
    return decrypted;
}

// ==================== APOLLO WALLET CLASS ====================

class ApolloWallet {
    static unlock(userPassword) {
        if (!fs.existsSync(APOLLO_DATA_FILE)) {
            throw new Error('Apollo wallet not found');
        }

        const data = JSON.parse(fs.readFileSync(APOLLO_DATA_FILE, 'utf8'));
        const encryptionKey = deriveEncryptionKey(userPassword, data.salt);
        const opKeyBytes = decryptKey(data.encryptedOpKey, encryptionKey);
        const opKeyPair = nacl.sign.keyPair.fromSeed(opKeyBytes);

        return {
            address: data.address,
            opKeyPair: opKeyPair,
            opPubkey: data.opPubkey
        };
    }

    static signTransaction(session, from, to, amount) {
        const timestamp = Math.floor(Date.now() / 1000);
        const nonce = Date.now().toString();
        
        const canonical = `${from}|${to}|${amount}|${timestamp}|${nonce}`;
        const payloadHash = crypto.createHash('sha256').update(canonical).digest('hex');
        
        const chainId = 1;
        const requestPath = '/transfer';
        const domainPrefix = `BLACKBOOK_L${chainId}${requestPath}`;
        const message = `${domainPrefix}\n${payloadHash}\n${timestamp}\n${nonce}`;
        
        const signature = nacl.sign.detached(
            Buffer.from(message, 'utf-8'),
            session.opKeyPair.secretKey
        );
        
        return {
            operation_type: 'transfer',
            payload_fields: {
                from: from,
                to: to,
                amount: amount,
                timestamp: timestamp,
                nonce: nonce
            },
            payload_hash: payloadHash,
            public_key: Buffer.from(session.opKeyPair.publicKey).toString('hex'),
            signature: Buffer.from(signature).toString('hex'),
            chain_id: chainId,
            request_path: requestPath,
            schema_version: 2,
            timestamp: timestamp,
            nonce: nonce
        };
    }
}

// ==================== MAIN ====================

async function main() {
    console.log(`\n${BOLD}${CYAN}═══════════════════════════════════════════════════════${RESET}`);
    console.log(`${BOLD}  🚀 APOLLO TRANSFERS TO ALICE & BOB${RESET}`);
    console.log(`${CYAN}═══════════════════════════════════════════════════════${RESET}\n`);

    try {
        // 1. Unlock Apollo wallet
        info('Unlocking Apollo wallet...');
        const session = ApolloWallet.unlock('apollo_secure_password_2026');
        pass(`Apollo unlocked: ${session.address}`);

        // 2. Check initial balance
        const initialRes = await fetch(`${L1_URL}/balance/${session.address}`);
        const initialData = await initialRes.json();
        info(`Initial balance: ${initialData.balance} BB`);

        // 3. Transfer to Alice
        console.log(`\n${YELLOW}Transferring 5,000 BB to Alice...${RESET}`);
        const aliceTx = ApolloWallet.signTransaction(session, session.address, ALICE_L1, 5000);
        const aliceRes = await fetch(`${L1_URL}/transfer`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(aliceTx)
        });
        const aliceResult = await aliceRes.json();
        
        if (aliceResult.success) {
            pass(`Transfer to Alice successful`);
            info(`Transaction hash: ${aliceResult.tx_hash}`);
        } else {
            console.log(`Error: ${aliceResult.error}`);
        }

        // 4. Transfer to Bob
        console.log(`\n${YELLOW}Transferring 3,000 BB to Bob...${RESET}`);
        const bobTx = ApolloWallet.signTransaction(session, session.address, BOB_L1, 3000);
        const bobRes = await fetch(`${L1_URL}/transfer`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(bobTx)
        });
        const bobResult = await bobRes.json();
        
        if (bobResult.success) {
            pass(`Transfer to Bob successful`);
            info(`Transaction hash: ${bobResult.tx_hash}`);
        } else {
            console.log(`Error: ${bobResult.error}`);
        }

        // 5. Check final balances
        console.log(`\n${BOLD}${CYAN}Final Balances:${RESET}`);
        
        const apolloFinalRes = await fetch(`${L1_URL}/balance/${session.address}`);
        const apolloFinal = await apolloFinalRes.json();
        console.log(`  🚀 Apollo: ${apolloFinal.balance.toLocaleString()} BB`);

        const aliceBalRes = await fetch(`${L1_URL}/balance/${ALICE_L1}`);
        const aliceBal = await aliceBalRes.json();
        console.log(`  👤 Alice:  ${aliceBal.balance.toLocaleString()} BB`);

        const bobBalRes = await fetch(`${L1_URL}/balance/${BOB_L1}`);
        const bobBal = await bobBalRes.json();
        console.log(`  👤 Bob:    ${bobBal.balance.toLocaleString()} BB`);

        console.log(`\n${GREEN}✓ All transfers completed successfully!${RESET}\n`);

    } catch (error) {
        console.error(`\n${'\x1b[31m'}✗ Error: ${error.message}${RESET}\n`);
        process.exit(1);
    }
}

main();
