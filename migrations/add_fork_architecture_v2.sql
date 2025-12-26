-- ═══════════════════════════════════════════════════════════════
-- FORK ARCHITECTURE V2 - Add V2 columns to user_vaults table
-- ═══════════════════════════════════════════════════════════════
-- 
-- Fork Architecture splits the password into two keys:
--   - auth_key: SHA256 hash sent to server (for authentication)
--   - vault_key: Argon2id key kept client-side (for vault decryption)
-- 
-- The server stores bcrypt(auth_key) and can verify user identity,
-- but CANNOT decrypt the vault (requires vault_key which is never sent).
-- ═══════════════════════════════════════════════════════════════

-- Add V2 Fork Architecture columns to user_vaults table
ALTER TABLE public.user_vaults
  ADD COLUMN IF NOT EXISTS auth_key_hash text NULL,      -- bcrypt(auth_key) for authentication
  ADD COLUMN IF NOT EXISTS auth_salt text NULL,          -- Salt for auth_key derivation (public)
  ADD COLUMN IF NOT EXISTS fork_version integer NULL DEFAULT 1;  -- 1 = V1 legacy, 2 = Fork Architecture

-- Add comment to explain the columns
COMMENT ON COLUMN public.user_vaults.auth_key_hash IS 'Bcrypt hash of auth_key for V2 Fork Architecture authentication. V1 users have NULL.';
COMMENT ON COLUMN public.user_vaults.auth_salt IS 'Public salt used for auth_key derivation. Client fetches this before login to derive auth_key from password.';
COMMENT ON COLUMN public.user_vaults.fork_version IS 'Vault security version: 1 = V1 legacy (single key), 2 = V2 Fork Architecture (auth_key + vault_key split)';

-- Add comment explaining V1 vs V2 vault_salt usage
COMMENT ON COLUMN public.user_vaults.vault_salt IS 'V1: Used for both auth and vault encryption. V2: Empty (vault_salt embedded in encrypted_blob AAD).';
COMMENT ON COLUMN public.user_vaults.encrypted_blob IS 'AES-256-GCM encrypted vault. V2: vault_salt embedded in AAD. V1: vault_salt in separate column.';

-- Create index on fork_version for faster queries
CREATE INDEX IF NOT EXISTS idx_user_vaults_fork_version ON public.user_vaults USING btree (fork_version) TABLESPACE pg_default;

-- ═══════════════════════════════════════════════════════════════
-- SECURITY NOTES
-- ═══════════════════════════════════════════════════════════════
-- 
-- V1 (Legacy) Security Model:
--   - vault_salt column stores salt
--   - Same password used for auth and vault decryption
--   - Server could theoretically brute-force vault if DB compromised
-- 
-- V2 (Fork Architecture) Security Model:
--   - auth_salt column stores salt for authentication
--   - vault_salt embedded in encrypted_blob AAD (not in column)
--   - Different keys for auth (SHA256) and vault (Argon2id)
--   - Server CANNOT decrypt vault even with full DB access
-- 
-- Migration Path:
--   - V1 users can login normally
--   - On first V2 SDK login, client prompts for migration
--   - Client re-encrypts vault with fork architecture
--   - fork_version updated to 2
-- ═══════════════════════════════════════════════════════════════
