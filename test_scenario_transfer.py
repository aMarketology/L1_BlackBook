import requests
import json
import os
import secrets
import sys
import time

# Configuration
SERVER_URL = "http://localhost:8080"
JWT_SECRET = "super-secret-jwt-token-with-at-least-32-bytes-long"

def load_env():
    env_vars = {}
    try:
        with open(".env", "r", encoding="utf-8") as f:
            for line in f:
                if "=" in line and not line.strip().startswith("#"):
                    key, val = line.strip().split("=", 1)
                    env_vars[key] = val
    except FileNotFoundError:
        pass
    return env_vars

ENV = load_env()
SUPABASE_URL = ENV.get("SUPABASE_URL")
SUPABASE_SERVICE_KEY = ENV.get("SUPABASE_SERVICE_ROLE_KEY")

try:
    import jwt
except ImportError:
    print("Installing pyjwt requests...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyjwt", "requests"])
    import jwt

def create_supabase_user(email, password):
    print(f"  > Creating Supabase User: {email}...")
    url = f"{SUPABASE_URL}/auth/v1/admin/users"
    headers = {
        "apikey": SUPABASE_SERVICE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "email": email,
        "password": password,
        "email_confirm": True
    }
    
    try:
        resp = requests.post(url, json=payload, headers=headers)
        if resp.status_code in [200, 201]:
            uid = resp.json().get("id")
            # print(f"    ✅ Created: {uid}")
            return uid
        else:
            if "already registered" in resp.text:
                print("    ⚠️ User already exists, proceeding...")
                # We can't easily get the ID if we don't know it, but for a test script
                # we usually generate random emails. If we reuse, we fail.
                return None
            print(f"    ❌ Failed: {resp.status_code} {resp.text}")
            return None
    except Exception as e:
        print(f"    ❌ Connection Error: {e}")
        return None

def create_local_jwt(user_id):
    payload = {
        "sub": user_id,
        "aud": "authenticated",
        "role": "authenticated",
        "iss": "supabase", 
        "exp": int(time.time()) + 3600
    }
    # Algorithm must match what the server expects roughly, or just be valid structure
    # Since server uses insecure_decode currently, signature doesn't matter much 
    # but we sign it anyway.
    return jwt.encode(payload, "secret", algorithm="HS256")

def create_wallet(username, password="Password123!"):
    print(f"\n--- 👤 Setting up {username} ---")
    suffix = secrets.token_hex(2)
    email = f"{username.lower()}_{suffix}@example.com"
    real_username = f"{username}_{suffix}"
    
    user_id = create_supabase_user(email, password)
    if not user_id: return None
    
    token = create_local_jwt(user_id)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    
    payload = {
        "username": real_username,
        "password": password,
        "pin": "123456",
        "daily_limit": 50000
    }
    
    print(f"  > Requesting Wallet Creation...")
    resp = requests.post(f"{SERVER_URL}/wallet/create", json=payload, headers=headers)
    
    if resp.status_code == 200:
        data = resp.json()
        print(f"  ✅ Wallet Created: {data['wallet_id'][:12]}...")
        return {
            "username": real_username,
            "wallet_id": data['wallet_id'],
            "mnemonic": data.get('mnemonic', 'N/A'),
            "share_a": data['share_a'],    # Encrypted
            "share_c": data['share_c'],    # Plain/Vault
            "address": data['address'],
            "user_id": user_id,
            "token": token,
            "password": password
        }
    else:
        print(f"  ❌ Creation Failed: {resp.text}")
        return None

def save_to_markdown(max_wallet, apollo_wallet):
    filename = "SSS2wallet.md"
    print(f"\n📝 Saving wallet details to {filename}...")
    
    content = f"""# SSS Wallet Test Session
Date: {time.strftime("%Y-%m-%d %H:%M:%S")}

## 👤 Max Wallet
- **Username**: `{max_wallet['username']}`
- **User ID**: `{max_wallet['user_id']}`
- **Wallet ID**: `{max_wallet['wallet_id']}`
- **Address**: `{max_wallet['address']}`
- **Mnemonic**: `{max_wallet['mnemonic']}`
- **Share A (Encrypted)**: `Yes`
- **Share B (Cloud)**: `Stored in ReDB`
- **Share C (Vault)**: `Backup Generated`

## 👤 Apollo Wallet
- **Username**: `{apollo_wallet['username']}`
- **User ID**: `{apollo_wallet['user_id']}`
- **Wallet ID**: `{apollo_wallet['wallet_id']}`
- **Address**: `{apollo_wallet['address']}`
- **Mnemonic**: `{apollo_wallet['mnemonic']}`
- **Share A (Encrypted)**: `Yes`
- **Share B (Cloud)**: `Stored in ReDB`
- **Share C (Vault)**: `Backup Generated`

---
"""
    with open(filename, "w") as f:
        f.write(content)
    print("✅ SSS2wallet.md updated.")

def perform_transfer(sender, receiver_address, amount):
    print(f"\n--- 💸 Transfer: {sender['wallet_id'][:8]} -> {receiver_address[:8]} ({amount} BB) ---")
    
    # 1. Sign Transaction using SSS (Shard A + Shard B)
    # The 'sign' endpoint handles fetching Shard B internally
    
    sign_payload = {
        "wallet_id": sender['wallet_id'],
        "message": f"Transfer {amount} to {receiver_address}", 
        # In a real app, message is the transaction hash/payload. 
        # Here we just sign a string for demonstration.
        "share_a": sender['share_a'],    # Encrypted Share A provided by client
        "password": sender['password'],  # Password to decrypt Share A
        "pin": "123456",                 # PIN for auth/decryption if needed
        "amount": amount
    }
    
    headers = {"Authorization": f"Bearer {sender['token']}", "Content-Type": "application/json"}
    
    print("  > Requesting Signature (reconstructing key 2-of-3)...")
    resp = requests.post(f"{SERVER_URL}/wallet/sign", json=sign_payload, headers=headers)
    
    if resp.status_code == 200:
        data = resp.json()
        signature = data.get("signature")
        print(f"  ✅ Signature Generated: {signature[:16]}...")
        return True
    else:
        print(f"  ❌ Signing Failed: {resp.status_code} - {resp.text}")
        return False

if __name__ == "__main__":
    print("🚀 Starting Wallet Interaction Test (Max <-> Apollo)")
    
    # 1. Create Max
    max_wallet = create_wallet("Max")
    if not max_wallet: sys.exit(1)
    
    # 2. Create Apollo
    apollo_wallet = create_wallet("Apollo")
    if not apollo_wallet: sys.exit(1)
    
    # 3. Save Info
    save_to_markdown(max_wallet, apollo_wallet)

    # 4. Max sends tokens to Apollo
    success = perform_transfer(max_wallet, apollo_wallet['address'], 50)
    
    if success:
        print("\n✅ Test Scenario Complete: SSS Wallets created and transaction signed!")
    else:
        print("\n❌ Test Scenario Failed.")
