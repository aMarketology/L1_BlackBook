This document outlines the architecture for the BlackBook Wallet, a next-generation, S+ Tier security system designed to bridge the gap between "Anywhere Login" convenience and "Deep Vault" security.
The guiding principle of this system is that no single breach (neither Supabase, nor the Rust L1, nor the user's phone) can lead to a total loss of funds.

📖 BlackBook Wallet: The 3-Shard "Anywhere Access" Blueprint
1. Executive Summary
The BlackBook Wallet utilizes a 2-of-3 Shamir Secret Sharing (SSS) scheme on a 24-word (256-bit) entropy. To provide a seamless user experience, the system links the wallet's local security to the user's Supabase Password. An independent PIN-Pepper sits outside the shard system to act as a physical "Circuit Breaker" for high-value transactions.

2. The Three Shards (A, B, and C)
A 24-word mnemonic is generated at signup, converted to a 32-byte secret, and split into three cryptographic fragments.
Shard A: The "Local Possession" Shard
Storage: The user’s device (Browser IndexedDB or Mobile Keychain).
Protection: Encrypted with the Supabase Password + Local Salt.
Role: Ensures that transactions can only be signed by a physical device the user has previously authorized.
Shard B: The "Network Identity" Shard
Storage: Rust Layer 1 Server (PostgreSQL/RedB).
Protection: Gated by a Supabase JWT and the System Pepper.
Role: The "Daily Partner." It is fetched instantly upon login. It allows the user to access their funds from any device without needing to carry a physical seed phrase.
Shard C: The "Institutional Recovery" Shard
Storage: Supabase Vault (pgsodium).
Protection: Gated by Supabase 2FA (Email/SMS/TOTP).
Role: The "Break Glass" shard. It is only used for Password Resets or New Device Syncs.

3. The Pepper/PIN: The External Circuit Breaker
Unlike the shards, the Pepper is a variable encryption layer applied to Shard B on the Rust server. It does not contain key material; it acts as a lock.
Low-Value Gate: For "usual" transactions (amounts under a user-defined threshold to known addresses), Shard B is unlocked using a System Pepper hidden in the Rust server’s environment. This feels "instant" to the user.
High-Value Gate: For "unusual" transactions (large amounts or new addresses), the Rust server sends a PIN-Encrypted version of Shard B.
The PIN: The user provides a 4-digit code. This code never touches the server. It is used on the client device to "un-pepper" Shard B. This prevents "Invisible Theft" via a hacked Supabase account.

4. Key Workflows
A. Normal Transaction Signing
User initiates a send.
App checks the amount against the Threshold Logic.
If Low: App fetches Shard B via JWT and unlocks Shard A with the Supabase Password.
If High: App prompts for PIN → Un-peppers Shard B → Unlocks Shard A.
Shards A + B combine to sign; the key is then Zeroized (wiped) from RAM.
B. Password Change & Re-Encryption
When a user changes their Supabase password, Shard A (which is encrypted with the old password) becomes a "dead" file.
The user enters their New Password.
The app uses the Current Session (or 2FA) to fetch Shard B and Shard C.
The app reconstructs the key, creates a New Shard A, and encrypts it with the New Password.
This ensures the wallet password and Supabase password stay perfectly in sync.
C. New Device Sync (The Anywhere Login)
User logs in on a new laptop (Supabase JWT obtained).
User passes 2FA (Shard C fetched).
App fetches Shard B from the Rust server.
App combines B + C to rebuild the key and generates a Local Shard A for the new laptop.

5. Security Matrix (Breach Scenarios)
Breach Scenario
Attacker Gains
Result
User Phone Stolen
Shard A
SAFE. Attacker needs Supabase Password to unlock Shard A.
Supabase DB Leaked
Shard C + Salt
SAFE. Attacker needs Shard A (Device) or Shard B (Rust JWT).
Rust L1 Hacked
Shard B
SAFE. Attacker needs Shard A or Shard C.
Email Hijacked
Shard C + B
SAFE (Partially). Attacker can reset password, but cannot bypass the PIN-Pepper for large transfers.


6. Implementation Logic (The Code)
The "Threshold Check" (Rust)
This logic determines if the server should demand the PIN-encrypted version of the shard.
Rust
pub async fn fetch_shard_b(
    claims: SupabaseClaims,
    tx_amount: u64,
    db: DbPool
) -> HttpResponse {
    let user_config = db.get_user_config(claims.sub).await;

    if tx_amount > user_config.pin_threshold {
        // Return Shard B encrypted with the User's PIN
        let peppered_shard = db.get_pin_encrypted_shard(claims.sub).await;
        return HttpResponse::Ok().json(peppered_shard);
    } else {
        // Return Shard B unlocked by System Pepper
        let standard_shard = db.get_standard_shard(claims.sub).await;
        return HttpResponse::Ok().json(standard_shard);
    }
}

The "Re-Encryption" (Express/JS)
This ensures that Shard A stays valid after a password update.
JavaScript
async function handlePasswordChange(newPassword) {
    // 1. Fetch Recovery Shards
    const shardB = await fetchShardB(); // Via JWT
    const shardC = await fetchShardC(); // Via 2FA

    // 2. Reconstruct Entropy
    const masterEntropy = Shamir.combine([shardB, shardC]);

    // 3. Re-encrypt Shard A with the NEW password
    const newShardA = encrypt(masterEntropy.getPart(0), newPassword);
    
    // 4. Update Local Storage
    localStorage.setItem('shard_a', newShardA);
    
    // 5. Cleanup
    masterEntropy.zeroize();
}


7. Conclusion
The BlackBook Wallet system provides Institutional Grade Security without the Institutional friction. By separating the user's "Identity" (Supabase) from their "Wealth" (The Shards and PIN), we ensure that the user is always in control, even if their devices or passwords are lost.
