# Supabase Integration Explained (`src/supabase.rs`)

This document provides a detailed breakdown of the `src/supabase.rs` module, which handles all interactions between the **L1 Rust Server** and the **Supabase Backend**.

---

## 1. Overview

The `SupabaseManager` struct serves as the bridge for your Hybrid Custody architecture. It does not use a direct PostgreSQL connection. Instead, it interacts with Supabase via its **REST API** (`/rest/v1/...`) and **Auth API** (`/auth/v1/...`).

**Key Responsibilities:**
1.  **Authentication**: Verifying JWT tokens from the frontend.
2.  **User Vault (Shard B)**: Storing the server-encrypted shard.
3.  **User Vault (Shard A)**: Backing up the user-encrypted shard (sync).
4.  **Bouncer Logic**: Verifying PINs against stored Argon2 hashes.

---

## 2. Core Structure

```rust
#[derive(Clone)]
pub struct SupabaseManager {
    jwks_cache: JwksCache,      //  Public keys to verify JWT signatures
    master_key: Vec<u8>,        //  SERVER_MASTER_KEY (from .env) used to encrypt Shard B
    project_id: String,         //  Supabase Project ID (e.g., "wnddtgujssdovnszoitf")
    client: Client,             //  Reqwest HTTP Client for making API calls
    supabase_url: String,       //  Base URL (https://[project].supabase.co)
    service_role_key: String,   //  Super-admin API key for backend operations
}
```

---

## 3. Initialization (`new`)

When the server starts, it loads critical secrets from the environment variables (injection via `.env` or PowerShell).

```rust
pub fn new() -> Self {
    // Loads: SERVER_MASTER_KEY, SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY
    // Initializes the HTTP client and JWKS cache for token verification.
}
```

---

## 4. Key Functions

### A. Authentication: `verify_user`
> "Are you who you say you are?"

*   **Input**: `Authorization` header ("Bearer eyJ...").
*   **Action**: 
    1.  Parses the JWT.
    2.  Verifies the signature using Supabase's public keys (`jwks_cache`).
    3.  Checks if the `iss` (Issuer) matches your `project_id`.
*   **Output**: Returns the User ID (`sub`) if valid.

### B. Shard B Fetch: `fetch_encrypted_shard_b`
> "Get the Cloud Shard."

*   **Endpoint**: `GET /rest/v1/user_vault`
*   **Query**: `?id=eq.{user_id}&select=encrypted_shard_b_blob`
*   **Security**: Uses `service_role_key` to bypass Row Level Security (RLS) if necessary, though ideally RLS allows the service role full access.
*   **Return**: Returns the raw hex-decoded bytes of Shard B (still encrypted with Master Key).

### C. Shard B Storage: `store_encrypted_shard_b`
> "Save the Cloud Shard."

*   **Endpoint**: `POST /rest/v1/user_vault`
*   **Header**: `Prefer: resolution=merge-duplicates` (This enables **UPSERT** behavior).
*   **Mechanism**: If the row exists, updates it; otherwise, creates it.
*   **Data Stored**:
    *   `encrypted_shard_b_blob`: The core asset.
    *   `pin_hash`: Stored for PIN verification logic (the "Bouncer").
    *   `root_pubkey`: Your wallet's identity.

### D. Shard A Storage: `store_encrypted_shard_a`
> "Sync the User Shard (Backup)."

*   **Endpoint**: `POST /rest/v1/user_vault`
*   **Mechanism**: UPSERT (Merge).
*   **Data Stored**:
    *   `encrypted_shard_a_blob`: Encrypted by the **User's Password** (client-side). The server cannot read this.
    *   `client_salt`: Extracted from the blob (format: `salt:nonce:ciphertext`). essential for checking password matches on new devices.

### E. The Bouncer: `verify_pin`
> "Can I spend this?"

*   **Action**: Verifies a transaction PIN.
*   **Library**: `argon2` (Rust crate).
*   **Logic**:
    1.  Takes the stored hash from the database (e.g., `$argon2id$v=19...`).
    2.  Hashes the `raw_pin` provided in the request.
    3.  If they match, returns `Ok(())`, allowing the transaction to proceed (and Shard B to be decrypted).

---

## 5. Security Model (Hybrid Custody)

This code enables a **2-of-3 Threshold Signature Scheme**:

1.  **Shard A (User)**: Stored in `user_vault` but **User Encrypted**. Supabase sees garbage.
2.  **Shard B (Server)**: Stored in `user_vault` but **Server Encrypted**. Supabase sees garbage.
3.  **Shard C (Recovery)**: Stored offline (JSON) or in HashiCorp Vault.

**Why this is specific with Supabase:**
By treating Supabase as a "Dumb Storage" layer and keeping the keys (Password for A, Master Key for B) on the Client and L1 Server respectively, we achieve **Zero Trust** storage. Even if Supabase is compromised, the attacker gets only encrypted blobs they cannot read.
