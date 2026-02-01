/**
 * BlackBook L1 - HashiCorp Vault Client
 * 
 * Secure on-demand pepper retrieval using AppRole authentication.
 * The pepper is NEVER stored in environment variables or the filesystem.
 * 
 * Architecture:
 * 1. Server starts → Authenticates to Vault with AppRole credentials
 * 2. Vault issues short-lived token (1-4 hours TTL)
 * 3. Server fetches pepper on-demand when needed for Share C encryption
 * 4. Token automatically refreshes before expiry
 * 5. Pepper is cached in memory for performance (never written to disk)
 * 
 * Security Benefits:
 * - No pepper in .env files or config files
 * - Vault audit logs all pepper access attempts
 * - Token-based auth with automatic expiry
 * - Network-isolated secret storage
 * - Encrypted at rest and in transit (TLS)
 * 
 * @version 1.0.0
 * @license MIT
 */

const vault = require('node-vault');

class VaultClient {
  constructor(options = {}) {
    this.vaultAddr = options.vaultAddr || process.env.VAULT_ADDR || 'http://127.0.0.1:8200';
    this.roleId = options.roleId || process.env.VAULT_ROLE_ID;
    this.secretId = options.secretId || process.env.VAULT_SECRET_ID;
    
    this.client = null;
    this.token = null;
    this.tokenExpiry = null;
    this.pepperCache = null;
    this.pepperCacheTime = null;
    this.pepperCacheTTL = options.pepperCacheTTL || 5 * 60 * 1000; // 5 minutes default
    
    // Validate configuration
    if (!this.roleId || !this.secretId) {
      throw new Error('Vault credentials not provided. Set VAULT_ROLE_ID and VAULT_SECRET_ID');
    }
  }

  /**
   * Initialize Vault client and authenticate
   */
  async initialize() {
    if (this.client && this.isTokenValid()) {
      return; // Already initialized and token is valid
    }

    console.log('🔐 Initializing Vault client...');
    
    // Create Vault client
    this.client = vault({
      apiVersion: 'v1',
      endpoint: this.vaultAddr,
      requestOptions: {
        timeout: 5000
      }
    });

    // Authenticate with AppRole
    await this.authenticate();
    
    console.log('✅ Vault authentication successful');
  }

  /**
   * Authenticate to Vault using AppRole
   */
  async authenticate() {
    try {
      const result = await this.client.approleLogin({
        role_id: this.roleId,
        secret_id: this.secretId
      });

      this.token = result.auth.client_token;
      this.client.token = this.token;
      
      // Calculate token expiry (use lease_duration from Vault response)
      const leaseDuration = result.auth.lease_duration;
      this.tokenExpiry = Date.now() + (leaseDuration * 1000);
      
      console.log(`🎫 Vault token acquired (expires in ${leaseDuration}s)`);
    } catch (error) {
      console.error('❌ Vault authentication failed:', error.message);
      throw new Error(`Vault auth failed: ${error.message}`);
    }
  }

  /**
   * Check if current token is still valid
   */
  isTokenValid() {
    if (!this.token || !this.tokenExpiry) {
      return false;
    }
    
    // Consider token invalid 5 minutes before actual expiry (safety margin)
    const safetyMargin = 5 * 60 * 1000;
    return Date.now() < (this.tokenExpiry - safetyMargin);
  }

  /**
   * Refresh token if needed
   */
  async ensureValidToken() {
    if (!this.isTokenValid()) {
      console.log('🔄 Token expired, re-authenticating...');
      await this.authenticate();
    }
  }

  /**
   * Get pepper from Vault (with caching)
   * 
   * @returns {Promise<string>} The pepper secret
   */
  async getPepper() {
    // Check cache first
    if (this.pepperCache && this.pepperCacheTime) {
      const age = Date.now() - this.pepperCacheTime;
      if (age < this.pepperCacheTTL) {
        return this.pepperCache;
      }
    }

    // Ensure client is initialized and token is valid
    await this.initialize();
    await this.ensureValidToken();

    try {
      // Read pepper from Vault KV v2 store
      const result = await this.client.read('blackbook/data/pepper');
      
      if (!result || !result.data || !result.data.data || !result.data.data.value) {
        throw new Error('Pepper not found in Vault or invalid format');
      }

      const pepper = result.data.data.value;
      
      // Cache the pepper
      this.pepperCache = pepper;
      this.pepperCacheTime = Date.now();
      
      return pepper;
    } catch (error) {
      console.error('❌ Failed to retrieve pepper from Vault:', error.message);
      throw new Error(`Vault pepper retrieval failed: ${error.message}`);
    }
  }

  /**
   * Clear the in-memory pepper cache
   * Call this for security reasons when shutting down
   */
  clearCache() {
    if (this.pepperCache) {
      // Attempt to zeroize the string (not perfect in JS, but better than nothing)
      this.pepperCache = null;
    }
    this.pepperCacheTime = null;
  }

  /**
   * Get health status of Vault connection
   */
  async healthCheck() {
    try {
      await this.initialize();
      const health = await this.client.health();
      return {
        status: 'healthy',
        initialized: health.initialized,
        sealed: health.sealed,
        tokenValid: this.isTokenValid()
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        error: error.message
      };
    }
  }

  /**
   * Revoke current token (logout)
   */
  async revoke() {
    if (this.token) {
      try {
        await this.client.tokenRevokeSelf();
        console.log('🔒 Vault token revoked');
      } catch (error) {
        console.error('⚠️  Failed to revoke token:', error.message);
      }
    }
    
    this.clearCache();
    this.token = null;
    this.tokenExpiry = null;
    this.client = null;
  }
}

// Singleton instance for the application
let vaultClientInstance = null;

/**
 * Get or create the singleton Vault client
 */
function getVaultClient(options) {
  if (!vaultClientInstance) {
    vaultClientInstance = new VaultClient(options);
  }
  return vaultClientInstance;
}

/**
 * Helper function to get pepper (convenience method)
 */
async function getPepper() {
  const client = getVaultClient();
  return await client.getPepper();
}

module.exports = {
  VaultClient,
  getVaultClient,
  getPepper
};
