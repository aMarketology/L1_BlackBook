╔══════════════════════════════════════════════════════════════════════════════╗
║                    🧪 BLACKBOOK TEST ACCOUNTS INDEX                          ║
║                                                                               ║
║                         February 2026 - v2.0                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                              ACCOUNT OVERVIEW
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

┌────────────┬──────────────────────────────────────────────┬─────────────────┐
│ Account    │ L1 Address                                   │ Role            │
├────────────┼──────────────────────────────────────────────┼─────────────────┤
│ alice.txt  │ L1_40B59B2AE14FC3404E40477B557F6F5ED1FAC9DA  │ User/Bettor     │
│ bob.txt    │ L1_83474EAA6FEB5F10A673BC3F4ADC51F611EB4372  │ User/Bettor     │
│ mac.txt    │ L1_0CEB3CEC6F37F2C72CDE35231EB7A0B86AC169D5  │ Developer       │
│ apollo.txt │ L1_CDCFA0999FB34AD2AD226D1552B37CF9C677D342  │ Heavy Trader    │
│ dealer.txt │ L1_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D  │ Oracle/Dealer   │
└────────────┴──────────────────────────────────────────────┴─────────────────┘


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                              QUICK REFERENCE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Passwords:
  Alice:   AlicePassword123!
  Bob:     BobPassword123!
  Mac:     MacSecurePassword2026!
  Apollo:  apollo_secure_password_2026
  Dealer:  (private key in .env)

2FA Code (all accounts): 123456

Admin Recovery Key: blackbook_admin_recovery_key_2026
Vault Pepper:       blackbook_pepper_32_bytes_long!!


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                              WALLET TYPES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ZKP Wallet v2.0 (Alice, Bob, Mac, Apollo):
  • BIP-39 24-word mnemonic
  • Shamir 2-of-3 Secret Sharing
  • Share A: Client (Argon2id password-bound)
  • Share B: L1 Blockchain (ReDB)
  • Share C: HashiCorp Vault (AES-256-GCM encrypted)
  • Recovery: Any 2 of 3 shares

System Account (Dealer):
  • Direct Ed25519 keypair
  • Private key in .env file
  • No SSS (privileged system account)


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                              RECOVERY PATHS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Path A+B (Normal Operation):
  • User provides password → derives Share A
  • System retrieves Share B from blockchain
  • Reconstruct mnemonic from A + B
  POST /mnemonic/recover/ab

Path A+C (Emergency - L1 Down):
  • User provides password → derives Share A
  • User provides encrypted Share C from backup
  • Reconstruct mnemonic from A + C
  POST /mnemonic/recover/ac

Path B+C (Privileged - Admin Only):
  • Admin provides recovery key
  • System retrieves Share B from blockchain
  • System decrypts Share C from vault
  • Reconstruct mnemonic from B + C
  POST /mnemonic/recover/bc


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                              FILE STRUCTURE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

tests/
└── test-accounts/
    ├── README.txt       ← You are here
    ├── alice.txt        ← Regular user account
    ├── bob.txt          ← Regular user account  
    ├── mac.txt          ← Developer account
    ├── apollo.txt       ← Heavy trader account
    └── dealer.txt       ← Oracle/dealer system account


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                              COMMON API CALLS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Health Check:
  GET /health

Create Wallet:
  POST /mnemonic/create
  Body: { "password": "..." }

Sign Message:
  POST /mnemonic/sign
  Body: { "wallet_address": "bb_...", "password": "...", "message": "..." }

Export Mnemonic:
  POST /mnemonic/export/{address}
  Body: { "password": "...", "two_factor_code": "123456", "share_a_bound": "..." }

Get Share B:
  GET /mnemonic/share-b/{address}

Get Share C:
  GET /mnemonic/share-c/{address}


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                              ⚠️  SECURITY NOTICE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

These test accounts contain EXPOSED CRYPTOGRAPHIC MATERIAL.

DO NOT USE IN PRODUCTION.
DO NOT USE FOR REAL FUNDS.
FOR DEVELOPMENT AND TESTING ONLY.

Address derivation: L1_ + SHA256(publicKey).slice(0,40).toUpperCase()
