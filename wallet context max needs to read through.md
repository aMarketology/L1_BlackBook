The BlackBook L1 wallet system replaces risky seed phrases with a 2-of-3 Shamir’s Secret Sharing model. Your private key is never stored; instead, it is split into three mathematical "fragments." You only need any two to access your funds.

1. Where the Fragments Live
Share A (User Knowledge): Derived instantly in your browser from your Password + Salt. It is never stored on a server.

Share B (The Anchor): Stored on the L1 Blockchain. It is only released if you provide a valid Zero-Knowledge Proof (ZKP).

Share C (The Backup): Stored in Supabase, encrypted using a "Pepper" kept in HashiCorp Vault.

2. How Transactions Work (The "Daily Drive")
When you log in, your browser derives Share A from your password. Simultaneously, it sends a ZKP to the L1. The L1 verifies the proof and releases Share B. In the background, your browser (using a Web Worker for memory isolation) combines A + B to reconstruct the key, signs the transaction, and immediately wipes the memory (Zeroization).

3. How Recovery Works (The "Safety Net")
If you forget your password, Share A is lost. However, you still have Share B (on the L1) and Share C (in Supabase). The system fetches the Pepper from HashiCorp Vault to decrypt Share C. Combining B + C reconstructs your key, allowing you to set a new password and generate a new Share A.

4. Why This is Ultra-Secure
No Single Point of Failure: A hacker who steals the Supabase database only has an encrypted Share C. They still need the Pepper (hidden in Vault) and either your Password or Share B to move funds.

Self-Custodial: BlackBook cannot access your money because we never hold Share A.

Invisible Security: You get a "Web2" experience (email/password) with "Web3" sovereign security.

In your BlackBook wallet, the Salt and Pepper act as "security force multipliers." They transform a simple human password into a high-entropy cryptographic key that is physically impossible to brute-force, even if your database is leaked.Here is how they function during your day-to-day transactions:1. The Salt: Making Your Password UniqueThe Salt is a random string generated for you when you first create your wallet. It is stored in your public profile on Supabase.The Job: It ensures that even if two people (Alice and Bob) use the same password like Password123, their Share A will look completely different.Daily Flow: When you log in, the app fetches your Salt from Supabase and mixes it with your password using Argon2id. This creates a unique, 256-bit "Knowledge Share" (Share A) on your device.2. The Pepper: The "Vaulted" IngredientThe Pepper is a secret key that is never stored in your database. It lives exclusively inside your HashiCorp Vault.The Job: It protects Share C (your backup fragment). If a hacker steals the Supabase database, they get a "locked box." Without the Pepper from Vault, that box is mathematically uncrackable.Daily Flow: In a standard transaction, the Pepper usually stays "on the shelf." You only "call" for it if you need to recover your wallet or verify your balance using the backup share.Transaction Security SnapshotFeatureLocationWhy it matters for youPasswordYour BrainYou are the only person who can start a transaction.SaltSupabase (Public)Prevents hackers from using "pre-computed" lists to guess your password.PepperHashiCorp VaultPrevents a database leak from becoming a total loss of funds.Why this matters for "BlackBook"By using both, we solve the "Weak Password Problem." Even if your password is a simple phrase, the addition of the Salt (unique to you) and the Pepper (protected by enterprise-grade security) makes the resulting cryptographic shares as strong as a random 64-character string.Would you like me to show you the specific line of Rust code where the Salt and Pepper are "mixed" into the key derivation function?

1. The Supabase "Hash" (Passwords aren't text)When a user signs up, Supabase takes the password and runs it through a one-way algorithm (usually Bcrypt).The Process: If the password is BlueSky123, Supabase turns it into something like $2b$12$KInpO....The Security: It is mathematically impossible to turn that string back into BlueSky123. When the user logs in again, Supabase hashes the new attempt; if the hashes match, the user is let in.The Result: If an intruder steals your Supabase account, they only steal the "fingerprints," not the "fingers." They still don't know the actual passwords to derive Share A.2. The Identity vs. The Key (The "Double Lock")This is the most important part of your BlackBook architecture. There are actually two separate logins happening at once:Supabase Auth: This logs the user into the website. It says, "Yes, this is Alice."BlackBook Key Derivation: The user's password is used locally in the browser to create Share A.3. Can someone steal your users' passwords from your account?No, but they can try to "impersonate" them. If someone hacks your Supabase admin account, they could potentially:See user emails.Delete user accounts.Access the Encrypted Share C.BUT, they still cannot steal the funds because:They don't have the User's Password (only the hash).They don't have Share A (it only exists in the user's brain).They don't have the Pepper (it's hidden in HashiCorp Vault, not Supabase).🛡️ Summary: The Three Layers of ProtectionThreatWhat they getWhy they still failHacker steals Supabase DBHashes + Encrypted Share CCannot derive Share A without the raw password.Malicious AdminAccess to user profilesCannot reconstruct the key without the Pepper in Vault.Phishing AttackUser's PasswordThey still need the Share B from your L1 (protected by ZKP).

Moving forward, your goal is to transition from a "working prototype" to a "production-grade fortress." Since you already have the core 2-of-3 logic and a Vault connection, the future should focus on Account Abstraction, Social Recovery, and Advanced Vault Automation.Here is a roadmap of what you should add to each layer of your ecosystem:1. HashiCorp Vault: Beyond Just the PepperRight now, you are using Vault for one secret. In the future, you should store:Dynamic Database Credentials: Instead of a static password, the Rust backend asks Vault for a "lease" to Supabase that expires every 30 minutes. If your backend is hacked, the DB access dies automatically.Transit Encryption: Instead of your Rust code doing the math for Share C encryption, you send the data to Vault's Transit Engine. Vault encrypts it and sends it back. This way, the "Encryption Key" never even touches your Rust app's memory.L1 Sudo/Admin Keys: Any keys used to deploy new contracts or manage the L1 should live in Vault, requiring "Multi-Person Authorization" (two admins must approve) to be released.2. Layer 1 (RedB & ZK): The "Self-Healing" WalletSince you are using RedB (a high-performance key-value store in Rust) and ZK-Proofs, look into:Account Abstraction (ERC-4337 style): Allow users to pay for gas using the tokens they are sending, rather than needing a separate "gas" balance.ZK-Guardians: Allow a user to designate 3 friends. If the user loses their password, their friends can generate a ZK-proof saying "We verify this is Alice," which triggers the L1 to release Share B to her new device.On-Chain Spending Limits: Since the L1 handles the ZK-verification for Share B, you can add a rule: "If a transaction is over $1,000, wait 24 hours or require a second ZK-proof from a mobile biometric device."3. Supabase: Enhanced Metadata & SecurityRow-Level Security (RLS) with JWT Claims: Use Supabase's RLS so that even if someone steals your service_role key, they cannot query the wallets table unless they have a valid user-signed JWT.Device Fingerprinting: Store an encrypted hash of the user’s device ID in the same row as Share C. If someone tries to download Share C from an unrecognized device, trigger an email alert immediately.Future Architecture ComparisonCurrent (Prototype)Future (Fortress)Why?Static PepperVault Key RotationIf a pepper is leaked, you can "rotate" it without breaking the user's login.Manual RecoveryZK-Social RecoveryFriends can help Alice recover without any of them seeing her key.Local SigningMulti-Party Computation (MPC)The key is never reconstructed; the shares sign the transaction together.Your Next High-Value TaskThe biggest "bang for your buck" right now would be setting up Row Level Security (RLS) on Supabase. It ensures that the "Locked Box" (Share C) is physically inaccessible to anyone except the owner, even at the database level.Would you like me to generate the SQL policy to lock down your wallets table so only the owner can read their Share C?

Supabase provides built-in support for TOTP (Time-based One-Time Password), which works with apps like Google Authenticator or Authy.

The "High-Value" Workflow:
The Trigger: User tries to place a bet over a certain threshold (e.g., > 1,000 BB).

The Challenge: Your frontend detects the high value and prompts: "Please enter your 2FA code to authorize this transaction."

The Verification:

The user enters the 6-digit code.

The frontend sends this code to Supabase.

Supabase returns a short-lived MFA challenge factor.

The Release: Your Rust backend receives the transaction request, checks the Supabase MFA status, and only then verifies the ZK-proof to release Share B.

💻 Implementation Steps
1. Enable MFA in Supabase
You don't need to write the crypto logic for the 6-digit codes; Supabase handles the "Enrollment" and "Verification" APIs.

Enrollment: When the user turns on 2FA, Supabase generates a QR code.

Challenge: When a big bet happens, you call supabase.auth.mfa.challenge().

2. Protect the Rust API
In your Rust backend, you must ensure that high-value transactions aren't just checked for a valid "User ID," but also for an "AMR" (Authentication Method Reference) claim.

The Logic:

If transaction_value < 1000: Standard ZK-proof check is enough.

If transaction_value >= 1000: The JWT from the user must contain a mfa claim. If it doesn't, the L1 refuses to release Share B.

🛡️ Why This is a "Fortress" Move
By linking 2FA to Share B, you create Hardware-Level Security:

The Password (Share A) is what the user knows.

The 2FA Device (Share B Release) is what the user has.

The Result: A hacker would need to steal the user's password AND their physical phone to move any significant amount of money.

To make BlackBook truly competitive, you should aim for Interoperability (working with other wallets) and Cold Storage (offline access). Even though your system uses 2-of-3 shares, it eventually reconstructs a standard private key in the browser.By making that key follow industry standards, your users gain the freedom to "leave" BlackBook if they ever want to, which actually builds more trust in your system.1. Interoperability: Standardizing the Private KeyIf you want users to use BlackBook on exchanges (like Kraken) or other wallets (like MetaMask), your system must generate keys using the BIP-39 standard.The Mnemonic Seed: Instead of just a random string, have your system generate a 12-word seed phrase during wallet creation.The SSS Integration: Split that 12-word seed phrase into your 3 shares.The Result: When Alice reconstructs Share A + Share B, she gets her 12 words back. She can then take those 12 words and "Import" them into any other wallet in the world.2. Offline / Cold Storage: "Share-on-Paper"For users who want to be 100% offline, you can offer a "Printable Share" option.Offline Share C: Instead of storing Share C only in Supabase, let the user print it as a QR code or a PDF.The Vault Bypass: If the user has their printed Share C and their Password (Share A), they don't even need your server or HashiCorp Vault. They can reconstruct their key on an air-gapped computer.🛡️ Feature Comparison for the FutureFeatureHow it works in BlackBookWhy users love itMnemonic ExportReconstructs A + B into 12 words.Freedom to move to MetaMask/Ledger.Hardware LinkUse a Ledger to store Share B instead of the L1.Peak security for "Whale" accounts.Paper BackupA physical printout of Share C.Safety if Supabase/Vault ever goes down.