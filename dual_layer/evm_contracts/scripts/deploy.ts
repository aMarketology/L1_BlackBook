import { ethers } from "hardhat";
import * as path from "path";
import * as fs from "fs";
import * as dotenv from "dotenv";

dotenv.config({ path: path.join(__dirname, "../../../.env") });

// ── BSC mainnet BEP-20 token addresses ───────────────────────────────────────
const TOKENS: Record<string, { usdc: string; usdt: string }> = {
  bsc:        {
    usdc: "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d", // Binance-Peg USD Coin
    usdt: "0x55d398326f99059fF775485246999027B3197955", // Binance-Peg BSC-USD
  },
  bscTestnet: {
    usdc: "0x64544969ed7EBf5f083679233325356EbE738930", // USDC mock on testnet
    usdt: "0x337610d27c682E347C9cD60BD4b3b107C9d34dDd", // USDT mock on testnet
  },
  hardhat: {
    usdc: "", // will be overridden by the mock deploy path
    usdt: "",
  },
};

async function main() {
  const network = (await ethers.provider.getNetwork()).name;
  console.log(`\n🚀 Deploying BlackbookBridge to network: ${network}`);

  const [deployer] = await ethers.getSigners();
  console.log(`   Deployer  : ${deployer.address}`);
  console.log(`   Balance   : ${ethers.formatEther(await ethers.provider.getBalance(deployer))} BNB`);

  // Operator defaults to the deployer — override via BSC_OPERATOR_ADDRESS env var
  const operatorAddress = process.env.BSC_OPERATOR_ADDRESS || deployer.address;
  console.log(`   Operator  : ${operatorAddress}`);

  let usdcAddress: string;
  let usdtAddress: string;

  if (network === "hardhat" || network === "localhost") {
    // On local Hardhat network, deploy mock tokens first
    console.log("\n📦 Deploying mock tokens for local testing...");
    const MockERC20 = await ethers.getContractFactory("MockERC20");
    const mockUsdc = await MockERC20.deploy("USD Coin", "USDC");
    const mockUsdt = await MockERC20.deploy("Tether USD", "USDT");
    await mockUsdc.waitForDeployment();
    await mockUsdt.waitForDeployment();
    usdcAddress = await mockUsdc.getAddress();
    usdtAddress = await mockUsdt.getAddress();
    console.log(`   MockUSDC  : ${usdcAddress}`);
    console.log(`   MockUSDT  : ${usdtAddress}`);
  } else {
    const tokens = TOKENS[network] ?? TOKENS.bsc;
    usdcAddress = tokens.usdc;
    usdtAddress = tokens.usdt;
    console.log(`   USDC      : ${usdcAddress}`);
    console.log(`   USDT      : ${usdtAddress}`);
  }

  // ── Deploy bridge ────────────────────────────────────────────────────────
  console.log("\n📝 Deploying BlackbookBridge...");
  const Bridge = await ethers.getContractFactory("BlackbookBridge");
  const bridge = await Bridge.deploy(usdcAddress, usdtAddress, operatorAddress);
  await bridge.waitForDeployment();

  const bridgeAddress = await bridge.getAddress();
  const deployTx = bridge.deploymentTransaction()!;

  console.log(`\n✅ BlackbookBridge deployed!`);
  console.log(`   Address   : ${bridgeAddress}`);
  console.log(`   Tx hash   : ${deployTx.hash}`);
  console.log(`   Gas used  : ${(await deployTx.wait())?.gasUsed.toString()}`);

  // ── Print next steps ─────────────────────────────────────────────────────
  console.log(`\n📋 Next steps:`);
  console.log(`   1. Add to L1_BlackBook/.env:`);
  console.log(`      BSC_BRIDGE_CONTRACT=${bridgeAddress}`);
  console.log(`      BSC_OPERATOR_PRIVATE_KEY=<your_operator_key>`);
  console.log(`   2. Verify on BSCScan:`);
  console.log(`      cd evm_contracts && npx hardhat verify --network ${network} ${bridgeAddress} ${usdcAddress} ${usdtAddress} ${operatorAddress}`);
  console.log(`   3. Start the relayer to call ackDeposit after L1 mints:`);
  console.log(`      npm run relayer`);

  // ── Persist deploy info to a JSON file for the relayer ───────────────────
  const deployInfo = {
    network,
    bridgeAddress,
    usdcAddress,
    usdtAddress,
    operatorAddress,
    deployedAt: new Date().toISOString(),
    txHash: deployTx.hash,
  };
  const outPath = path.join(__dirname, "../deployments", `${network}.json`);
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(deployInfo, null, 2));
  console.log(`\n💾 Deploy info saved to: evm_contracts/deployments/${network}.json`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
