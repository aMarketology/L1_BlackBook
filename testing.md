

🧪 Stage 1: The Cryptographic "Sanity" Tests (Unit Level)
Before involving the database, verify the math works in pure Rust.
Shamir 2-of-3 Roundtrip:
The Test: Take a dummy seed, split it into A, B, and C. Recombine (A+B), (B+C), and (A+C).
Verification: Ensure all three pairs yield the exact same original seed.
Negative Test: Ensure any single shard (A alone) reveals zero information about the seed.
AES-GCM "Pepper" Integrity:
The Test: Encrypt Shard B with your SERVER_MASTER_KEY and a random nonce. Decrypt it back.
Verification: If the decrypted bytes don't match the original, your nonce handling or Tag (GCM authentication tag) is broken.

🧪 Stage 2: The "Vault Connection" Tests (Integration Level)
Now, test if your Rust Layer 1 can actually talk to Supabase.
The "Triple-Write" Verification:
Action: Call your create_wallet endpoint.
Verification: Open your Supabase Dashboard.
Check public.user_vault: Are encrypted_shard_a_blob, encrypted_shard_b_blob, and shard_b_nonce populated?
Check vault.secrets (via SQL): Use SELECT * FROM vault.decrypted_secrets to see if Shard C exists and matches the ID.
The JWT Bouncer:
Action: Attempt to call get_shard_b with an expired or fake JWT.
Verification: Rust should return a 401 Unauthorized and must not attempt to query the database.

🧪 Stage 3: The "Disaster Simulation" (System Level)
This is where you prove the system is "Enterprise Ready" by simulating failures.
Scenario
Simulated Failure
Success Criteria
Lost Phone
Delete local Shard A.
User triggers recovery. System uses B (from user_vault) and C (from vault.secrets) to rebuild A.
Forgotten PW
User resets Supabase PW.
User logs in. Old Shard A fails to decrypt. Recovery flow re-seeds Shard A with the new password.
Server Hack
Attacker steals user_vault.
Attacker has Shard B but cannot get Shard A (user password missing) and cannot get Shard C (requires 2FA/Vault).


