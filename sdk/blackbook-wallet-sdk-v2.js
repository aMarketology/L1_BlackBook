/**
 * BlackBook Wallet SDK V2 - Dual-Key SSS Architecture
 * 
 * REPLACES: BIP39 mnemonics with Shamir Secret Sharing (SSS)
 * SECURITY MODEL:
 * - Root Key: Random 256-bit, SSS-split 2-of-3 (paper backup)
 * - Operational Key: Random 256-bit, encrypted with user password (Supabase)
 * - No mnemonics, no seed phrases, professional key management
 * - Auto-lock: 10 minutes desktop, 60 seconds mobile
 * - Closure-based: Keys never exposed in window scope
 */

const { EnhancedSecureWallet, SecureSession } = require('./enhanced-secure-wallet.js');

// ═══════════════════════════════════════════════════════════════
// BLACKBOOK WALLET V2 - DUAL-KEY ARCHITECTURE
// ═══════════════════════════════════════════════════════════════

class BlackBookWalletV2 {
  /**
   * Create new wallet SDK instance
   * 
   * @param {string} l1Url - Layer 1 blockchain endpoint
   * @param {string} supabaseUrl - Supabase project URL
   * @param {string} supabaseKey - Supabase anonymous key
   */
  constructor(l1Url = 'http://localhost:8080', supabaseUrl = null, supabaseKey = null) {
    this.apiUrl = l1Url;
    this.supabaseUrl = supabaseUrl;
    this.supabaseKey = supabaseKey;
    this.session = null; // SecureSession instance
    this.address = null;
    this.username = null;
  }

  /**
   * Register new wallet with dual-password architecture
   * 
   * @param {string} username - Username for Supabase auth
   * @param {string} authPassword - Password for Supabase login
   * @param {string} userPassword - Password for key encryption (never sent to server)
   * @returns {Promise<object>} Account data with SSS shares (save to paper backup!)
   */
  async register(username, authPassword, userPassword) {
    if (!username || username.length < 3) {
      throw new Error('Username must be at least 3 characters');
    }
    if (!authPassword || authPassword.length < 8) {
      throw new Error('Auth password must be at least 8 characters');
    }
    if (!userPassword || userPassword.length < 12) {
      throw new Error('User password must be at least 12 characters (encrypts your keys)');
    }

    // 1. Create account on Layer 1
    const accountData = await EnhancedSecureWallet.createAccount(
      authPassword,
      userPassword,
      this.supabaseUrl,
      this.supabaseKey,
      this.apiUrl
    );

    // 2. Store encrypted vault in Supabase
    if (this.supabaseUrl && this.supabaseKey) {
      await this._storeVaultInSupabase(username, authPassword, accountData);
    }

    // 3. Set instance state
    this.address = accountData.address;
    this.username = username;

    return {
      address: accountData.address,
      rootPubkey: accountData.rootPubkey,
      opPubkey: accountData.opPubkey,
      shares: accountData.shares, // CRITICAL: User must save these 3 shares!
      message: 'Registration successful. SAVE THE 3 SHARES TO PAPER BACKUP!'
    };
  }

  /**
   * Login with user password (decrypt operational key)
   * 
   * @param {string} username - Username
   * @param {string} authPassword - Auth password (Supabase login)
   * @param {string} userPassword - User password (key decryption)
   * @param {string} platform - 'desktop' | 'mobile' (affects timeout)
   * @returns {Promise<object>} Login result
   */
  async login(username, authPassword, userPassword, platform = 'desktop') {
    // 1. Authenticate with Supabase and get encrypted vault
    const accountData = await this._getVaultFromSupabase(username, authPassword);

    // 2. Decrypt operational key and get SecureSession
    this.session = await EnhancedSecureWallet.login(
      userPassword,
      accountData,
      { platform }
    );

    // 3. Set instance state
    this.address = this.session.address;
    this.username = username;

    return {
      address: this.session.address,
      opPubkey: this.session.opPubkey,
      message: 'Login successful',
      sessionTimeout: platform === 'mobile' ? '60 seconds' : '10 minutes'
    };
  }

  /**
   * Recover account from SSS shares and set new password
   * 
   * @param {Array} shares - 2 or 3 SSS shares from paper backup
   * @param {string} username - Username
   * @param {string} newAuthPassword - New auth password
   * @param {string} newUserPassword - New user password
   * @returns {Promise<object>} Recovery result
   */
  async recoverAccount(shares, username, newAuthPassword, newUserPassword) {
    if (shares.length < 2) {
      throw new Error('Need at least 2 shares to recover account');
    }

    // 1. Get address from Supabase user record (or derive from shares)
    const accountData = await this._getVaultFromSupabase(username, null, true);
    const address = accountData.address;

    // 2. Recover account on L1 (generates NEW op key and NEW salt)
    const recoveryData = await EnhancedSecureWallet.recoverAccount(
      shares,
      newUserPassword,
      address,
      this.apiUrl
    );

    // 3. Update Supabase with new encrypted vault
    await this._updateVaultInSupabase(username, newAuthPassword, recoveryData);

    return {
      address: recoveryData.address,
      newOpPubkey: recoveryData.newOpPubkey,
      message: 'Account recovered. New operational key and salt generated.'
    };
  }

  /**
   * Transfer tokens to another address
   * 
   * @param {string} to - Recipient address
   * @param {number} amount - Amount to transfer
   * @returns {Promise<object>} Transfer result
   */
  async transfer(to, amount) {
    if (!this.session || this.session.isLocked()) {
      throw new Error('Session locked or not logged in');
    }

    // 1. Build transaction
    const transaction = {
      timestamp: Date.now(),
      tx_data: {
        TransferWusdc: {
          from: this.session.address,
          to: to,
          amount: amount
        }
      }
    };

    // 2. Sign with operational key (closure-based, never exposed)
    const signedTx = this.session.signTransaction(transaction);

    // 3. Submit to L1
    const response = await fetch(`${this.apiUrl}/submit_transaction`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(signedTx)
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Transfer failed: ${error}`);
    }

    return await response.json();
  }

  /**
   * Get balance for current wallet
   * 
   * @returns {Promise<number>} Balance in BB tokens
   */
  async getBalance() {
    if (!this.address) {
      throw new Error('Not logged in');
    }

    const response = await fetch(`${this.apiUrl}/balance/${this.address}`);
    if (!response.ok) {
      throw new Error('Failed to fetch balance');
    }

    const data = await response.json();
    return data.balance;
  }

  /**
   * Lock current session (zeros keys)
   */
  lock() {
    if (this.session) {
      this.session.lock();
    }
  }

  /**
   * Check if session is locked
   * 
   * @returns {boolean}
   */
  isLocked() {
    return !this.session || this.session.isLocked();
  }

  // ═══════════════════════════════════════════════════════════════
  // SUPABASE INTEGRATION (PRIVATE METHODS)
  // ═══════════════════════════════════════════════════════════════

  async _storeVaultInSupabase(username, authPassword, accountData) {
    // Authenticate with Supabase
    const authResponse = await fetch(`${this.supabaseUrl}/auth/v1/signup`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey': this.supabaseKey
      },
      body: JSON.stringify({
        email: `${username}@blackbook.local`, // Use username as email
        password: authPassword
      })
    });

    if (!authResponse.ok) {
      const error = await authResponse.json();
      throw new Error(`Supabase auth failed: ${error.message}`);
    }

    const authData = await authResponse.json();
    const accessToken = authData.access_token;

    // Store encrypted vault
    const vaultResponse = await fetch(`${this.supabaseUrl}/rest/v1/wallets`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey': this.supabaseKey,
        'Authorization': `Bearer ${accessToken}`
      },
      body: JSON.stringify({
        username,
        address: accountData.address,
        root_pubkey: accountData.rootPubkey,
        op_pubkey: accountData.opPubkey,
        encrypted_op_key: accountData.encryptedOpKey,
        salt: accountData.salt,
        created_at: new Date().toISOString()
      })
    });

    if (!vaultResponse.ok) {
      const error = await vaultResponse.json();
      throw new Error(`Failed to store vault: ${error.message}`);
    }
  }

  async _getVaultFromSupabase(username, authPassword, skipAuth = false) {
    let accessToken;

    if (!skipAuth) {
      // Authenticate with Supabase
      const authResponse = await fetch(`${this.supabaseUrl}/auth/v1/token?grant_type=password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'apikey': this.supabaseKey
        },
        body: JSON.stringify({
          email: `${username}@blackbook.local`,
          password: authPassword
        })
      });

      if (!authResponse.ok) {
        throw new Error('Invalid username or auth password');
      }

      const authData = await authResponse.json();
      accessToken = authData.access_token;
    }

    // Get vault data
    const vaultResponse = await fetch(`${this.supabaseUrl}/rest/v1/wallets?username=eq.${username}`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'apikey': this.supabaseKey,
        'Authorization': accessToken ? `Bearer ${accessToken}` : this.supabaseKey
      }
    });

    if (!vaultResponse.ok) {
      throw new Error('Failed to retrieve vault');
    }

    const vaultData = await vaultResponse.json();
    if (vaultData.length === 0) {
      throw new Error('Wallet not found');
    }

    return vaultData[0];
  }

  async _updateVaultInSupabase(username, authPassword, recoveryData) {
    // Authenticate
    const authResponse = await fetch(`${this.supabaseUrl}/auth/v1/token?grant_type=password`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey': this.supabaseKey
      },
      body: JSON.stringify({
        email: `${username}@blackbook.local`,
        password: authPassword
      })
    });

    if (!authResponse.ok) {
      throw new Error('Authentication failed');
    }

    const authData = await authResponse.json();
    const accessToken = authData.access_token;

    // Update vault
    const updateResponse = await fetch(`${this.supabaseUrl}/rest/v1/wallets?username=eq.${username}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        'apikey': this.supabaseKey,
        'Authorization': `Bearer ${accessToken}`
      },
      body: JSON.stringify({
        op_pubkey: recoveryData.newOpPubkey,
        encrypted_op_key: recoveryData.encryptedOpKey,
        salt: recoveryData.newSalt,
        updated_at: new Date().toISOString()
      })
    });

    if (!updateResponse.ok) {
      throw new Error('Failed to update vault');
    }
  }
}

// ═══════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════

module.exports = {
  BlackBookWalletV2,
  EnhancedSecureWallet,
  SecureSession
};
