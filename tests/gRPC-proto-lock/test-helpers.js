/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * gRPC/PROTO TEST HELPERS
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Shared utilities for testing L1-L2 token locking via gRPC and HTTP REST endpoints.
 */

import nacl from 'tweetnacl';
import crypto from 'crypto';

// Configuration
export const CONFIG = {
  L1_HTTP_URL: 'http://localhost:8080',
  L1_GRPC_URL: 'localhost:50051', // gRPC endpoint (if available)
  TIMEOUT: 5000,
};

// Test accounts
export const TEST_ACCOUNTS = {
  ALICE: {
    seed: '5DB4B525FB40D6EA6BFD24094C2BC24984BAC433FFC5F31CABE597BE18AA8F83',
    address: 'L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433',
  },
  BOB: {
    seed: 'C9F4C8C76DE4F9E58A4B3B5AA22C88D4E5D6F7E8A9B0C1D2E3F4A5B6C7D8E9F0',
    address: 'L1_C0E349153CBC75E9529B5F1963205CAB783463C6',
  },
  DEALER: {
    seed: '0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF',
    address: 'L1_52882D768C0F3E7932AAD1813CF8B19058D507A8',
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// CRYPTO UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

export function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function generateNonce() {
  return crypto.randomUUID();
}

export function generateSessionId() {
  return crypto.randomUUID();
}

// ═══════════════════════════════════════════════════════════════════════════
// HTTP REST API (Current L1 implementation uses HTTP)
// ═══════════════════════════════════════════════════════════════════════════

export async function httpGet(endpoint) {
  const response = await fetch(`${CONFIG.L1_HTTP_URL}${endpoint}`, {
    method: 'GET',
    headers: { 'Content-Type': 'application/json' },
  });
  return await response.json();
}

export async function httpPost(endpoint, body) {
  const response = await fetch(`${CONFIG.L1_HTTP_URL}${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return await response.json();
}

// ═══════════════════════════════════════════════════════════════════════════
// L1 BALANCE QUERIES
// ═══════════════════════════════════════════════════════════════════════════

export async function getBalance(address) {
  const response = await httpGet(`/balance/${address}`);
  return {
    available: response.balance ?? response.available ?? 0,
    locked: response.locked ?? 0,
    total: (response.balance ?? response.available ?? 0) + (response.locked ?? 0),
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// L2 SESSION MANAGEMENT (via HTTP REST - simulating gRPC)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Lock tokens for L2 session (simulates gRPC LockTokensRequest)
 */
export async function lockTokens(walletAddress, amount, sessionId = null) {
  const session_id = sessionId ?? generateSessionId();
  
  const response = await httpPost('/credit/open', {
    wallet: walletAddress,
    amount: amount,
    session_id: session_id,
  });
  
  return {
    success: response.status === 'success' || response.success === true,
    session_id: session_id,
    locked_amount: amount,
    response: response,
  };
}

/**
 * Settle L2 session and release tokens (simulates gRPC SettleSessionRequest)
 */
export async function settleSession(sessionId, pnl) {
  const response = await httpPost('/credit/settle', {
    session_id: sessionId,
    pnl: pnl,
  });
  
  return {
    success: response.status === 'success' || response.success === true,
    final_balance: response.new_balance ?? response.balance ?? 0,
    response: response,
  };
}

/**
 * Query session status (simulates gRPC QuerySessionRequest)
 */
export async function querySession(sessionId) {
  try {
    const response = await httpGet(`/credit/status/${sessionId}`);
    return {
      exists: true,
      active: response.active ?? false,
      locked_amount: response.locked_amount ?? 0,
      wallet: response.wallet ?? null,
      response: response,
    };
  } catch (err) {
    return {
      exists: false,
      error: err.message,
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// TEST RESULT TRACKING
// ═══════════════════════════════════════════════════════════════════════════

export class TestResults {
  constructor() {
    this.passed = 0;
    this.failed = 0;
    this.skipped = 0;
    this.failures = [];
    this.startTime = Date.now();
  }

  pass(testName) {
    this.passed++;
    console.log(`   ✅ ${testName}`);
  }

  fail(testName, error) {
    this.failed++;
    this.failures.push({ test: testName, error: error?.message || error });
    console.log(`   ❌ ${testName}: ${error?.message || error}`);
  }

  skip(testName, reason) {
    this.skipped++;
    console.log(`   ⏭️  ${testName}: ${reason}`);
  }

  summary() {
    const duration = ((Date.now() - this.startTime) / 1000).toFixed(2);
    
    console.log('\n═════════════════════════════════════════════════════════════');
    console.log('TEST SUMMARY');
    console.log('═════════════════════════════════════════════════════════════');
    console.log(`   ✅ Passed:  ${this.passed}`);
    console.log(`   ❌ Failed:  ${this.failed}`);
    console.log(`   ⏭️  Skipped: ${this.skipped}`);
    console.log(`   ⏱️  Duration: ${duration}s`);

    if (this.failures.length > 0) {
      console.log('\n   FAILURES:');
      this.failures.forEach((f, i) => {
        console.log(`   ${i + 1}. ${f.test}: ${f.error}`);
      });
    }
    
    console.log('═════════════════════════════════════════════════════════════\n');
    
    return this.failed === 0;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// PROTO MESSAGE VALIDATION (for future gRPC implementation)
// ═══════════════════════════════════════════════════════════════════════════

export function validateLockTokensRequest(request) {
  const errors = [];
  
  if (!request.wallet_address || typeof request.wallet_address !== 'string') {
    errors.push('Missing or invalid wallet_address');
  }
  
  if (typeof request.amount !== 'number' || request.amount <= 0) {
    errors.push('Amount must be positive number');
  }
  
  if (!request.session_id || typeof request.session_id !== 'string') {
    errors.push('Missing or invalid session_id');
  }
  
  return { valid: errors.length === 0, errors };
}

export function validateSettleSessionRequest(request) {
  const errors = [];
  
  if (!request.session_id || typeof request.session_id !== 'string') {
    errors.push('Missing or invalid session_id');
  }
  
  if (typeof request.pnl !== 'number') {
    errors.push('PNL must be a number');
  }
  
  return { valid: errors.length === 0, errors };
}
