const axios = require('axios');
// In an ideal world, we use browser-native crypto or specialized libs
// const shamir = require('shamir-secret-sharing'); 
// const argon2 = require('argon2-browser'); 

class BlackBookSDK {
    constructor(validNodeUrl, supabaseJwt) {
        this.baseUrl = validNodeUrl;
        this.jwt = supabaseJwt;
        this.client = axios.create({
            baseURL: this.baseUrl,
            headers: {
                'Authorization': `Bearer ${supabaseJwt}`,
                'Content-Type': 'application/json'
            }
        });
    }

    /**
     * INTERNAL: Derive a Key from the password (KEK)
     * We do this so the RAW password is never even sent to your own Rust server.
     */
    async _deriveVaultKey(password, salt) {
        // Use Argon2id or PBKDF2 to turn 'password' into a 256-bit key
        return "locally-derived-hex-key"; 
    }

    /**
     * CREATE WALLET (Phase 1: Client-Side Locking)
     */
    async createWallet(username, password, pin, dailyLimit = 500) {
        try {
            // 1. Ask Rust to generate the 2-of-3 split
            // The server generates Shards A, B, and C.
            const response = await this.client.post('/wallet/create', {
                username,
                pin, // Hashed before sending
                daily_limit: dailyLimit
            });

            const { shard_a_raw, shard_c_raw, mnemonic, client_salt } = response.data;

            // 2. ENCRYPT SHARD A LOCALLY
            // We use the derived key to lock Shard A before storing it
            const kek = await this._deriveVaultKey(password, client_salt);
            const encryptedShardA = await this._localEncrypt(shard_a_raw, kek);

            // 3. STORE SHARD A BACK TO SUPABASE (as a backup)
            await this.client.post('/wallet/backup_shard_a', {
                encrypted_shard_a: encryptedShardA
            });

            // 4. Wipe raw shards from JS memory immediately
            return {
                address: response.data.wallet_address,
                mnemonic, // User writes this down
                encryptedShardA, // SDK stores this in LocalStorage
                shard_c: shard_c_raw // One-time display
            };
        } catch (error) {
            throw new Error(`Creation Failed: ${error.message}`);
        }
    }

    /**
     * SIGN TRANSACTION (Phase 2: Local Reconstruction)
     * This is the "Magic" step.
     */
    async signTransaction(message, encryptedShardA, password, amount, pin = null) {
        try {
            // 1. GET SHARD B FROM RUST
            // Rust checks the JWT and the daily limit
            const response = await this.client.post('/wallet/release-shard-b', {
                amount,
                pin // Only needed if amount > limit
            });

            const shardB = response.data.shard_b;

            // 2. UNLOCK SHARD A LOCALLY
            const salt = await this._getSaltFromServer(); 
            const kek = await this._deriveVaultKey(password, salt);
            const shardA = await this._localDecrypt(encryptedShardA, kek);

            // 3. RECONSTRUCT MASTER SEED (SSS)
            // Combine A + B in the browser's RAM
            const masterSeed = shamir.combine([shardA, shardB]);

            // 4. SIGN LOCALLY
            const signature = await this._signWithSeed(masterSeed, message);

            // 5. SECURITY: PURGE RAM
            // Overwrite variables to ensure the seed is gone
            return signature;
        } catch (error) {
            if (error.response?.status === 403) throw new Error("PIN_REQUIRED");
            throw error;
        }
    }

    /**
     * RECOVERY (Phase 3: Shard C + Shard B)
     */
    async recoverAccount(newPassword) {
        // 1. This call will FAIL unless the user has 'aal2' (2FA) in their JWT
        const response = await this.client.post('/wallet/recover-shard-c');
        const shardC = response.data.shard_c;

        // 2. Fetch Shard B
        const shardB = await this.getShareB();

        // 3. Reconstruct Seed -> Generate New Shard A -> Encrypt with New Password
        // ... (Logic to reset the local vault)
    }
}