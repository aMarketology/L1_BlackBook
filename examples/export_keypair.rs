/// Reconstruct a BlackBook wallet's Ed25519 keypair from its BIP-39 mnemonic.
/// Exports in two formats:
///   1. Solana CLI JSON byte array (importable with `solana-keygen`)
///   2. Base58-encoded 64-byte keypair (importable into Nightly / Phantom / Backpack)
///
/// Usage:
///   cargo run --example export_keypair
///
/// This uses the SAME derivation path as src/wallet_unified/handlers.rs:
///   mnemonic → BIP-39 seed (passphrase="") → first 32 bytes → Ed25519 keypair

use bip39::Mnemonic;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use std::str::FromStr;

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║         BlackBook Keypair Export (Nightly / Phantom)        ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // ═══════════════════════════════════════════════════════════════
    // WALLET MNEMONICS — paste the mnemonic for the wallet you want
    // ═══════════════════════════════════════════════════════════════
    
    let wallets: Vec<(&str, &str)> = vec![
        ("Max", "length dog melody small surround arch floor eight machine hungry split member bike unknown verb mandate cancel lazy dance upper soon second notice drum"),
    ];

    for (name, mnemonic_str) in &wallets {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("  Wallet: {}", name);
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        // 1. Parse mnemonic
        let mnemonic = Mnemonic::from_str(mnemonic_str)
            .expect("Invalid mnemonic");

        // 2. Derive BIP-39 seed with empty passphrase (matches handlers.rs)
        let bip39_seed = mnemonic.to_seed("");
        let seed_32: [u8; 32] = bip39_seed[..32].try_into().unwrap();

        // 3. Create Ed25519 keypair (same as handlers.rs)
        let signing_key = Ed25519SigningKey::from_bytes(&seed_32);
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();
        let address = bs58::encode(&pub_bytes).into_string();

        // 4. Build 64-byte keypair: [32-byte secret seed | 32-byte public key]
        //    This is the standard Solana keypair format.
        let mut keypair_64 = [0u8; 64];
        keypair_64[..32].copy_from_slice(&seed_32);
        keypair_64[32..].copy_from_slice(&pub_bytes);

        // 5. Export formats
        let keypair_base58 = bs58::encode(&keypair_64).into_string();
        let keypair_json: Vec<u8> = keypair_64.to_vec();

        println!("  Address:        {}", address);
        println!();
        println!("  ┌─ BASE58 PRIVATE KEY (paste into Nightly → Import → Private Key)");
        println!("  │");
        println!("  │  {}", keypair_base58);
        println!("  │");
        println!("  └─────────────────────────────────────────────────────");
        println!();
        println!("  ┌─ JSON BYTE ARRAY (save as id.json → solana-keygen verify)");
        println!("  │");
        println!("  │  {:?}", keypair_json);
        println!("  │");
        println!("  └─────────────────────────────────────────────────────");

        // 6. Also write the JSON file for solana CLI compatibility
        let json_filename = format!("real_wallets/{}_keypair.json", name);
        let json_content = serde_json::to_string(&keypair_json).unwrap();
        match std::fs::write(&json_filename, &json_content) {
            Ok(_) => println!("\n  ✅ Saved: {}", json_filename),
            Err(e) => println!("\n  ⚠️  Could not save {}: {}", json_filename, e),
        }

        println!();
    }

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  HOW TO IMPORT INTO NIGHTLY:                               ║");
    println!("║  1. Open Nightly extension                                 ║");
    println!("║  2. Settings → Import Account → Private Key                ║");
    println!("║  3. Paste the BASE58 key above                             ║");
    println!("║  4. Set network to custom RPC: http://localhost:8899       ║");
    println!("║     (or your public URL)                                   ║");
    println!("║  5. Your BB balance will show as SOL (same lamport scale)  ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
}
