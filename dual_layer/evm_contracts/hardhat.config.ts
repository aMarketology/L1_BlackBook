import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import * as dotenv from "dotenv";
import * as path from "path";

// Load the root .env (L1_BlackBook/.env) so BSC keys are available
dotenv.config({ path: path.join(__dirname, "../../.env") });

const BSC_DEPLOYER_KEY = process.env.BSC_DEPLOYER_PRIVATE_KEY;
const accounts = BSC_DEPLOYER_KEY ? [BSC_DEPLOYER_KEY] : [];

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: { enabled: true, runs: 200 },
      // Enable via-ir for better stack depth handling on complex functions
      viaIR: false,
    },
  },

  networks: {
    hardhat: {},

    bscTestnet: {
      url:      "https://data-seed-prebsc-1-s1.binance.org:8545/",
      chainId:  97,
      accounts,
      gasPrice: 10_000_000_000, // 10 gwei
    },

    bsc: {
      url:      process.env.BSC_RPC_URL ?? "https://bsc-dataseed.binance.org/",
      chainId:  56,
      accounts,
      gasPrice: 3_000_000_000,  // 3 gwei — BSC mainnet baseline
    },
  },

  etherscan: {
    apiKey: {
      // Get a free key at https://bscscan.com/myapikey
      bscTestnet: process.env.BSCSCAN_API_KEY ?? "",
      bsc:        process.env.BSCSCAN_API_KEY ?? "",
    },
  },

  gasReporter: {
    enabled:  process.env.REPORT_GAS === "true",
    currency: "USD",
  },

  paths: {
    sources:   "./contracts",
    tests:     "./test",
    cache:     "./cache",
    artifacts: "./artifacts",
  },
};

export default config;
