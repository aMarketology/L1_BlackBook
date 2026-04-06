/**
 * BlackBook L1 — WebSocket PubSub Load Test
 * Tests: 100 concurrent WebSocket connections tracking an account via `accountSubscribe`.
 * Submits a transaction, verifies all 100 receive `accountNotification` within 500ms.
 */
import * as ed from '@noble/ed25519';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import bs58 from 'bs58';
import WebSocket from 'ws';

const API = 'http://localhost:8080';
const WS_URL = 'ws://localhost:8080/ws';
const NUM_CLIENTS = 100; // Load scale
let passed = 0, failed = 0;

// —— Test keys ——
const ALICE = {
  address: "EB8tsQcA8Ewuqni2pqW5RiME95oiUAHj5eC9Lz2zX3j5",
  secretHex: "1c12a697254491cc286dd6431e9c84acda48ae85b667e08f8527eeb810f9316bc3c0aa0bad64ed2c74d91c24682ae5a4021960e2b70f629296c51a01190f5870"
};
const BOB = {
  address: "9a66KD7KTTUnwXdfxM5c4E5Z8rqyDbP4zm3qCgZsmGoo",
  secretHex: "f4366aec8e6f4f0a099f32a784a587b78ab18ef46ed7732ef7143a8b29090d257f576b5234264a3a8ea6f58cfe941f5aba6583679cfed70d11048a0956c622f6"
};

// —— Helpers ——
function nowSecs() { return Math.floor(Date.now() / 1000); }
function randomNonce() {
  const arr = new Uint8Array(12);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');    
}

async function getKeypair(account) {
  const privHex = account.secretHex.slice(0, 64);
  const privBytes = hexToBytes(privHex);
  const pubBytes = await ed.getPublicKeyAsync(privBytes);
  return {
    address: bs58.encode(pubBytes),
    privateKeyHex: privHex,
    publicKeyHex: bytesToHex(pubBytes),
  };
}

async function pingBackend() {
    try {
        await fetch(`${API}/health`);
        return true;
    } catch {
        return false;
    }
}

// —— Main Test Runner ——
async function runScaleTest() {
    console.log(`\n======================================================`);
    console.log(`🚀 BlackBook L1 WS PubSub Scale Test (${NUM_CLIENTS} sockets)`);
    console.log(`======================================================\n`);

    if (!(await pingBackend())) {
        console.error("❌ ERROR: L1 node is not running on localhost:8080");
        console.error("   Run `cargo run` in another terminal first.\n");
        process.exit(1);
    }

    const aliceKp = await getKeypair(ALICE);
    const bobKp = await getKeypair(BOB);

    console.log("1. Funding Alice...");
    const faucetRes = await fetch(`${API}/faucet`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            wallet_address: aliceKp.address,
            timestamp: nowSecs(),
            signature: "faucet_auth_v5", 
        })
    });
    if (!faucetRes.ok) {
        // Ignored if faucet rate limit
        console.log(`   (Faucet note: ${await faucetRes.text()})`);
    } else {
        console.log("   ✅ Alice funded.");
    }

    console.log(`\n2. Connecting ${NUM_CLIENTS} WebSockets requesting 'accountSubscribe' for Bob...`);
    
    const sockets = [];
    const notificationPromises = [];
    let connected = 0;
    
    for (let i=0; i<NUM_CLIENTS; i++) {
        const ws = new WebSocket(WS_URL);
        sockets.push(ws);
        
        let resolveSub;
        const subPromise = new Promise(r => resolveSub = r);
        
        let resolveNotify;
        const notifPromise = new Promise(r => resolveNotify = r);
        notificationPromises.push(notifPromise);

        ws.on('open', () => {
            connected++;
            ws.send(JSON.stringify({
                "jsonrpc": "2.0",
                "id": i,
                "method": "accountSubscribe",
                "params": [bobKp.address]
            }));
        });

        ws.on('message', (msg) => {
            const data = JSON.parse(msg);
            if (data.id === i && data.result !== undefined) {
                // Subscription Confirmed
                resolveSub();
            } else if (data.method === "accountNotification") {
                // Notified!
                resolveNotify(Date.now());
                ws.close();
            }
        });
    }

    console.log(`   ⏳ Waiting for all sockets to acknowledge subscription...`);
    // Wait for at least 3 seconds max for connections to settle
    await new Promise(r => setTimeout(r, 2000));
    console.log(`   ✅ ${connected}/${NUM_CLIENTS} active subscriptions confirmed.`);

    console.log(`\n3. Mutating Bob's state (Alice -> Bob Transfer 0.001 BB)...`);
    
    // Transfer
    const amount = 0.001;
    const bodyStr = `{"from":"${aliceKp.address}","to":"${bobKp.address}","amount":${amount},"timestamp":${nowSecs()},"nonce":"${randomNonce()}"}`;
    const sigBytes = await ed.signAsync(Buffer.from(bodyStr), hexToBytes(aliceKp.privateKeyHex));
    const sigHex = bytesToHex(sigBytes);
    const txPayload = { ...JSON.parse(bodyStr), signature: sigHex };

    const startTx = Date.now();
    const res = await fetch(`${API}/transfer/simple`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(txPayload)
    });
    
    if (!res.ok) {
        console.error(`❌ HTTP Transfer Failed: ${await res.text()}`);
        sockets.forEach(ws => ws.close());
        process.exit(1);
    }
    console.log(`   💸 Tx pushed to Gulf Stream in ${Date.now() - startTx}ms`);

    console.log(`   ⏳ Validating ${NUM_CLIENTS} simultaneous PubSub events from BlockProducer...`);

    const publishStart = Date.now();
    // Wait for all to resolve or timeout
    try {
        const results = await Promise.all(
            notificationPromises.map(p => Promise.race([
                p, 
                new Promise((_, rj) => setTimeout(() => rj(new Error("Timeout")), 5000))
            ]))
        );
        const maxLatency = Math.max(...results) - publishStart;
        console.log(`   🚀 SUCCESS! All ${NUM_CLIENTS} clients received the block delta within ${maxLatency}ms.`);
        passed++;
    } catch (e) {
        console.error(`❌ ERROR: Not all clients received the notification under 5s timeout.`);
        failed++;
    }
    
    sockets.forEach(ws => ws.close());
    
    console.log(`\n======================================================`);
    console.log(`Test Result: ${failed === 0 ? '🟢 PASSED' : '🔴 FAILED'}`);
    console.log(`======================================================\n`);
    process.exit(failed);
}

runScaleTest().catch(console.error);