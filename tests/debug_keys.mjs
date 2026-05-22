import * as ed from "@noble/ed25519";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import bs58 from "bs58";

const ALICE_SECRET = "1c12a697254491cc286dd6431e9c84acda48ae85b667e08f8527eeb810f9316bc3c0aa0bad64ed2c74d91c24682ae5a4021960e2b70f629296c51a01190f5870";
const ALICE_ADDR   = "EB8tsQcA8Ewuqni2pqW5RiME95oiUAHj5eC9Lz2zX3j5";

// Decode address to raw bytes
const addrBytes = bs58.decode(ALICE_ADDR);
console.log("Address decoded:   ", bytesToHex(addrBytes));
console.log("Secret last 32:    ", ALICE_SECRET.slice(64));
console.log("Match:             ", bytesToHex(addrBytes) === ALICE_SECRET.slice(64));

// Derive public key from first 32 bytes (seed)
const seed = hexToBytes(ALICE_SECRET.slice(0, 64));
const pub  = await ed.getPublicKeyAsync(seed);
console.log("Derived pubkey:    ", bytesToHex(pub));
console.log("Keypair OK:        ", bytesToHex(pub) === bytesToHex(addrBytes));

// Test signing
const msg = `FAUCET:${ALICE_ADDR}:0.100000:1716123456:testnonce`;
const sig = await ed.signAsync(new TextEncoder().encode(msg), seed);
const ok  = await ed.verifyAsync(sig, new TextEncoder().encode(msg), pub);
console.log("Sign+verify OK:    ", ok);
console.log("Signature (hex):   ", bytesToHex(sig).slice(0, 32) + "...");
