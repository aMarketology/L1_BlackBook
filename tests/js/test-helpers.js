/**
 * Shared test helpers aligned with blackbook-wallet-sdk.js
 */

export function generateNonce() {
  return crypto.randomUUID();
}

/**
 * Create signed transfer using SDK's simple format
 * Matches blackbook-wallet-sdk.js transferSimple() method
 */
export async function createSignedTransferSimple(from, to, amount, keyPair) {
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = generateNonce();
  const payload = JSON.stringify({ to, amount });
  
  // Sign: chain_id byte + payload + newline + timestamp + newline + nonce
  const chainIdByte = new Uint8Array([0x01]); // CHAIN_ID_L1
  const payloadBytes = new TextEncoder().encode(payload);
  const timestampBytes = new TextEncoder().encode(`\n${timestamp}\n`);
  const nonceBytes = new TextEncoder().encode(nonce);
  
  // Concatenate all parts
  const message = new Uint8Array(
    chainIdByte.length + payloadBytes.length + timestampBytes.length + nonceBytes.length
  );
  let offset = 0;
  message.set(chainIdByte, offset); offset += chainIdByte.length;
  message.set(payloadBytes, offset); offset += payloadBytes.length;
  message.set(timestampBytes, offset); offset += timestampBytes.length;
  message.set(nonceBytes, offset);
  
  // Sign with Ed25519
  const nacl = await import('tweetnacl');
  const signature = nacl.default.sign.detached(message, keyPair.secretKey);
  
  function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }
  
  return {
    public_key: bytesToHex(keyPair.publicKey),
    wallet_address: from,
    payload: payload,
    timestamp: timestamp,
    nonce: nonce,
    chain_id: 1,
    schema_version: 1,
    signature: bytesToHex(signature)
  };
}
