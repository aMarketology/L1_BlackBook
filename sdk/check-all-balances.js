/**
 * Check L1 and L2 Balances for All Test Accounts
 * 
 * Queries:
 * - L1 (http://localhost:8080)
 * - L2 (http://localhost:1234)
 * 
 * For accounts: Alice, Bob, Dealer
 */

const L1_URL = "http://localhost:8080";
const L2_URL = "http://localhost:1234";

// Test accounts (matching main_v2.rs seed_test_accounts)
const ACCOUNTS = {
  ALICE: {
    name: "Alice",
    l1: "L1_52882D768C0F3E7932AAD1813CF8B19058D507A8",
    l2: "L2_52882D768C0F3E7932AAD1813CF8B19058D507A8"
  },
  BOB: {
    name: "Bob",
    l1: "L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433",
    l2: "L2_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433"
  },
  DEALER: {
    name: "Dealer",
    l1: "L1_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D",
    l2: "L2_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D"
  }
};

async function getL1Balance(address) {
  try {
    const response = await fetch(`${L1_URL}/balance/${address}`);
    if (!response.ok) return null;
    const data = await response.json();
    return data.balance || 0;
  } catch (error) {
    return null;
  }
}

async function getL2Balance(address) {
  try {
    const response = await fetch(`${L2_URL}/balance/${address}`);
    if (!response.ok) return null;
    const data = await response.json();
    return data.balance || 0;
  } catch (error) {
    return null;
  }
}

async function checkAllBalances() {
  console.log("\n═══════════════════════════════════════════════════════════════════");
  console.log("                    ACCOUNT BALANCE CHECK");
  console.log("═══════════════════════════════════════════════════════════════════");
  console.log(`   L1: ${L1_URL}`);
  console.log(`   L2: ${L2_URL}`);
  console.log("═══════════════════════════════════════════════════════════════════\n");

  const results = [];

  for (const [key, account] of Object.entries(ACCOUNTS)) {
    console.log(`📊 Checking ${account.name}...`);
    
    const l1Balance = await getL1Balance(account.l1);
    const l2Balance = await getL2Balance(account.l2);
    
    results.push({
      name: account.name,
      l1: l1Balance,
      l2: l2Balance,
      total: (l1Balance || 0) + (l2Balance || 0)
    });
    
    const l1Status = l1Balance === null ? "❌ L1 offline" : `${l1Balance} $BC`;
    const l2Status = l2Balance === null ? "❌ L2 offline" : `${l2Balance} $BB`;
    
    console.log(`   L1 ($BC): ${l1Status}`);
    console.log(`   L2 ($BB): ${l2Status}`);
    console.log();
  }

  // Summary table
  console.log("═══════════════════════════════════════════════════════════════════");
  console.log("                        SUMMARY TABLE");
  console.log("═══════════════════════════════════════════════════════════════════");
  console.log("  Account  │  L1 ($BC)  │  L2 ($BB)  │  Total Power");
  console.log("───────────┼────────────┼────────────┼──────────────────");
  
  results.forEach(r => {
    const name = r.name.padEnd(8);
    const l1 = r.l1 === null ? "offline".padStart(10) : String(r.l1).padStart(10);
    const l2 = r.l2 === null ? "offline".padStart(10) : String(r.l2).padStart(10);
    const total = r.l1 === null || r.l2 === null ? "N/A".padStart(10) : String(r.total).padStart(10);
    console.log(`  ${name} │ ${l1} │ ${l2} │ ${total}`);
  });
  
  console.log("═══════════════════════════════════════════════════════════════════\n");
  
  // Checks
  const allOnline = results.every(r => r.l1 !== null && r.l2 !== null);
  if (!allOnline) {
    console.log("⚠️  Warning: Some servers are offline");
  }
  
  const anyZero = results.some(r => r.l1 === 0 && r.l2 === 0);
  if (anyZero) {
    console.log("💡 Tip: Some accounts have 0 balance on both layers");
    console.log("   Run: Invoke-RestMethod -Uri \"http://localhost:8080/admin/mint\" -Method POST -ContentType \"application/json\" -Body '{\"to\": \"<address>\", \"amount\": 10000}'");
  }
}

// Run the check
checkAllBalances().catch(console.error);
