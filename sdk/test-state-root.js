#!/usr/bin/env node
// Test L2 State Root Submission to L1

const L1_URL = 'http://localhost:8080';

async function testStateRootSubmission() {
  console.log('\n🧪 Testing L2 State Root Submission to L1\n');
  
  // Submit first state root (genesis)
  const submission1 = {
    state_root: '0000000000000000000000000000000000000000000000000000000000000001',
    block_height: 1,
    timestamp: Math.floor(Date.now() / 1000),
    tx_count: 10,
    prev_state_root: '0000000000000000000000000000000000000000000000000000000000000000', // Genesis prev
    signature: null
  };
  
  console.log('📤 Submitting State Root #1 (Genesis)');
  console.log('   Payload:', JSON.stringify(submission1, null, 2));
  
  const res1 = await fetch(`${L1_URL}/l2/state_root`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(submission1)
  });
  
  const data1 = await res1.json();
  console.log('\n📥 Response:', JSON.stringify(data1, null, 2));
  
  if (data1.success) {
    console.log('\n✅ State root #1 anchored successfully!');
    console.log(`   L2 Block: ${data1.anchored.l2_block_height}`);
    console.log(`   L1 Block: ${data1.anchored.l1_block_height}`);
    console.log(`   Challenge period ends: ${data1.anchored.challenge_period_ends}`);
    
    // Submit second state root
    console.log('\n📤 Submitting State Root #2');
    const submission2 = {
      state_root: '0000000000000000000000000000000000000000000000000000000000000002',
      block_height: 2,
      timestamp: Math.floor(Date.now() / 1000),
      tx_count: 5,
      prev_state_root: submission1.state_root, // Link to previous
      signature: null
    };
    
    const res2 = await fetch(`${L1_URL}/l2/state_root`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(submission2)
    });
    
    const data2 = await res2.json();
    console.log('📥 Response:', JSON.stringify(data2, null, 2));
    
    if (data2.success) {
      console.log('\n✅ State root #2 anchored successfully!');
    } else {
      console.log('\n❌ State root #2 failed:', data2.error);
    }
    
    // Get latest state
    console.log('\n📊 Getting Latest State Root');
    const latestRes = await fetch(`${L1_URL}/l2/state_root/latest`);
    const latest = await latestRes.json();
    console.log('📥 Latest:', JSON.stringify(latest, null, 2));
    
  } else {
    console.log('\n❌ State root #1 failed:', data1.error);
  }
}

testStateRootSubmission().catch(console.error);
