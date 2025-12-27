#!/usr/bin/env node
// Quick test of credit approve

const L1_URL = 'http://localhost:8080';

async function test() {
  const res = await fetch(`${L1_URL}/auth/test-accounts`);
  const accounts = await res.json();
  const alice = accounts.alice;
  
  console.log('Alice:', alice.address);
  console.log('Balance:', alice.l1_available, 'BB');
  
  // Try a simple balance check first
  const balRes = await fetch(`${L1_URL}/balance/${alice.address}`);
  const balData = await balRes.json();
  console.log('Balance check:', balData);
}

test().catch(console.error);
