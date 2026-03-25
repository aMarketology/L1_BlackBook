/**
 * BlackBook Bridge — L1 Relayer Script
 *
 * Watches for UsdcDeposited events on the BlackbookBridge BSC contract,
 * verifies that the BlackBook L1 has minted BB (via the L1 REST API),
 * then calls ackDeposit() on-chain to create an auditable treasury trail.
 *
 * Run:
 *   npm run relayer
 *
 * Requires in L1_BlackBook/.env:
 *   BSC_BRIDGE_CONTRACT          — deployed contract address
 *   BSC_OPERATOR_PRIVATE_KEY     — operator wallet key (signs ackDeposit txs)
 *   BSC_RPC_URL                  — BSC JSON-RPC endpoint
 *   L1_API_URL                   — BlackBook L1 HTTP API (default: localhost:8080)
 */

import { ethers } from "ethers";
import axios from "axios";
import * as path from "path";
import * as dotenv from "dotenv";

dotenv.config({ path: path.join(__dirname, "../../../.env") });

// ── Config ────────────────────────────────────────────────────────────────────
const BRIDGE_ADDRESS = process.env.BSC_BRIDGE_CONTRACT     ?? "";
const OPERATOR_KEY   = process.env.BSC_OPERATOR_PRIVATE_KEY ?? "";
const BSC_RPC_URL    = process.env.BSC_RPC_URL             ?? "https://bsc-dataseed.binance.org/";
const L1_API_URL     = process.env.L1_API_URL              ?? "http://localhost:8080";
const POLL_MS        = 15_000; // 15 s between scans
const START_BLOCKS_BACK = 1_000; // scan this many blocks on cold start

// ── Minimal ABI (only what the relayer needs) ─────────────────────────────────
const BRIDGE_ABI = [
  "event  UsdcDeposited(address indexed depositor, string l1Wallet, address indexed token, uint256 amount, uint256 depositIndex)",
  "function depositCount() view returns (uint256)",
  "function deposits(uint256) view returns (address depositor, string l1Wallet, address token, uint256 amount, uint256 createdAt, bool bbMinted, uint64 l1MintSlot)",
  "function ackDeposit(uint256 depositIndex, uint64 l1MintSlot)",
];

// ── L1 API helpers ────────────────────────────────────────────────────────────

async function getL1Slot(): Promise<number> {
  try {
    const r = await axios.get(`${L1_API_URL}/health`, { timeout: 5_000 });
    return (r.data?.poh_clock?.current_slot as number) ?? 0;
  } catch {
    return 0;
  }
}

/** Returns "approved" | "pending" | "not_found" */
async function getDepositStatus(txHash: string): Promise<string> {
  try {
    const r = await axios.get(`${L1_API_URL}/deposit/status/${txHash}`, { timeout: 5_000 });
    return (r.data?.status as string) ?? "not_found";
  } catch {
    return "not_found";
  }
}

// ── Main loop ─────────────────────────────────────────────────────────────────

async function main() {
  if (!BRIDGE_ADDRESS || !OPERATOR_KEY) {
    console.error("❌  Set BSC_BRIDGE_CONTRACT and BSC_OPERATOR_PRIVATE_KEY in .env");
    process.exit(1);
  }

  const provider = new ethers.JsonRpcProvider(BSC_RPC_URL);
  const wallet   = new ethers.Wallet(OPERATOR_KEY, provider);
  const bridge   = new ethers.Contract(BRIDGE_ADDRESS, BRIDGE_ABI, wallet);

  console.log("⛓️   BlackBook Bridge relayer started");
  console.log(`    Contract : ${BRIDGE_ADDRESS}`);
  console.log(`    Operator : ${wallet.address}`);
  console.log(`    L1 API   : ${L1_API_URL}`);

  let lastBlock = Math.max(0, (await provider.getBlockNumber()) - START_BLOCKS_BACK);

  while (true) {
    try {
      await tick(provider, bridge, lastBlock);
      lastBlock = await provider.getBlockNumber();
    } catch (e) {
      console.error("Relayer tick error:", e);
    }
    await sleep(POLL_MS);
  }
}

async function tick(
  provider: ethers.JsonRpcProvider,
  bridge: ethers.Contract,
  fromBlock: number,
) {
  const toBlock = await provider.getBlockNumber();
  if (toBlock <= fromBlock) return;

  // Fetch all new UsdcDeposited events in the block range
  const filter = bridge.filters["UsdcDeposited"]();
  const events = await bridge.queryFilter(filter, fromBlock + 1, toBlock);

  if (events.length > 0) {
    console.log(`⛓️   Found ${events.length} UsdcDeposited event(s) [${fromBlock + 1}–${toBlock}]`);
  }

  for (const raw of events) {
    const ev = raw as ethers.EventLog;
    const txHash       = ev.transactionHash.toLowerCase();
    const depositIndex = ev.args[4] as bigint;
    const l1Wallet     = ev.args[1] as string;

    // Check if already acked on-chain
    const dep = await bridge["deposits"](depositIndex);
    if (dep.bbMinted) continue;

    // Ask L1 whether BB was minted for this tx
    const status = await getDepositStatus(txHash);
    if (status !== "approved") {
      console.log(`⏳  Deposit #${depositIndex} (${l1Wallet.slice(0, 8)}…): BB not yet minted on L1 (status=${status}) — will retry`);
      continue;
    }

    // BB was minted — call ackDeposit to close the loop on-chain
    const l1Slot = await getL1Slot();
    console.log(`📝  Ack deposit #${depositIndex} (tx=${txHash.slice(0, 18)}… l1Slot=${l1Slot})`);

    try {
      const tx = await bridge["ackDeposit"](depositIndex, l1Slot);
      const receipt = await tx.wait();
      console.log(`✅  ackDeposit confirmed in ${receipt?.hash}`);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      // "already acknowledged" is not a real failure — the watcher and relayer
      // may overlap on the same event.
      if (msg.includes("already acknowledged")) {
        console.log(`ℹ️   Deposit #${depositIndex} was already acked — skipping`);
      } else {
        console.error(`❌  ackDeposit failed for #${depositIndex}:`, msg);
      }
    }
  }
}

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

main().catch(console.error);
