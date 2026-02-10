import requests
import json
import secrets
import time
import sys
import uuid

SERVER_URL = "http://localhost:8080"

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
    print("Installing pyjwt...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyjwt"])
    import jwt

def create_supabase_user(email, password):
    print(f"Creating Supabase User: {email}...")
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
    
    resp = requests.post(url, json=payload, headers=headers)
    if resp.status_code in [200, 201]:
        uid = resp.json().get("id")
        print(f"✅ Supabase User Created: {uid}")
        return uid
    else:
        print(f"⚠️ Failed: {resp.status_code} {resp.text}")
        return None

def create_local_jwt(user_id):
    payload = {
        "sub": user_id,
        "aud": "authenticated",
        "role": "authenticated",
        "iss": "supabase",
        "exp": int(time.time()) + 3600
    }
    return jwt.encode(payload, "secret", algorithm="HS256")

def create_apollo_wallet():
    print("\n--- 🚀 Creating Apollo's Wallet ---\n")
    
    suffix = secrets.token_hex(2)
    email = f"apollo_{suffix}@example.com"
    username = f"Apollo_{suffix}"
    password = "Apollo123!"
    
    user_id = create_supabase_user(email, password)
    if not user_id:
        print("❌ Failed to create Supabase user")
        return None
    
    token = create_local_jwt(user_id)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    
    payload = {
        "username": username,
        "password": password,
        "pin": "654321",
        "daily_limit": 100000
    }
    
    print(f"Requesting Wallet Creation for {username}...")
    resp = requests.post(f"{SERVER_URL}/wallet/create", json=payload, headers=headers)
    
    if resp.status_code == 200:
        data = resp.json()
        print(f"\n✅ Apollo's Wallet Created Successfully!\n")
        print(f"Username: {username}")
        print(f"User ID: {user_id}")
        print(f"Wallet ID: {data['wallet_id']}")
        print(f"Address: {data['address']}")
        print(f"Mnemonic: {data['mnemonic']}")
        print(f"Share A Encrypted: {data['share_a_is_encrypted']}")
        print(f"\nShare A (first 80 chars): {data['share_a'][:80]}...")
        print(f"Share C (first 80 chars): {data['share_c'][:80]}...")
        
        return {
            "username": username,
            "user_id": user_id,
            "wallet_id": data['wallet_id'],
            "address": data['address'],
            "mnemonic": data['mnemonic'],
            "share_a": data['share_a'],
            "share_c": data['share_c'],
            "password": password
        }
    else:
        print(f"❌ Wallet Creation Failed: {resp.status_code} - {resp.text}")
        return None

def create_max_wallet():
    print("\n--- 🚀 Creating Max's Wallet ---\n")
    
    suffix = secrets.token_hex(2)
    email = f"max_{suffix}@example.com"
    username = f"Max_{suffix}"
    password = "CorrectHorseBatteryStaple"
    
    user_id = create_supabase_user(email, password)
    if not user_id:
        print("❌ Failed to create Supabase user")
        return None
    
    token = create_local_jwt(user_id)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    
    payload = {
        "username": username,
        "password": password,
        "pin": "123456",
        "daily_limit": 50000
    }
    
    print(f"Requesting Wallet Creation for {username}...")
    resp = requests.post(f"{SERVER_URL}/wallet/create", json=payload, headers=headers)
    
    if resp.status_code == 200:
        data = resp.json()
        print(f"\n✅ Max's Wallet Created Successfully!\n")
        print(f"Username: {username}")
        print(f"User ID: {user_id}")
        print(f"Wallet ID: {data['wallet_id']}")
        print(f"Address: {data['address']}")
        print(f"Mnemonic: {data['mnemonic']}")
        print(f"Share A Encrypted: {data['share_a_is_encrypted']}")
        print(f"\nFULL Share A: {data['share_a']}")
        print(f"\nShare C (first 80 chars): {data['share_c'][:80]}...")
        
        return {
            "username": username,
            "user_id": user_id,
            "wallet_id": data['wallet_id'],
            "address": data['address'],
            "mnemonic": data['mnemonic'],
            "share_a": data['share_a'],
            "share_c": data['share_c'],
            "password": password
        }
    else:
        print(f"❌ Wallet Creation Failed: {resp.status_code} - {resp.text}")
        return None

if __name__ == "__main__":
    choice = input("Create wallet for (1) Max or (2) Apollo? [1/2]: ").strip()
    
    if choice == "1":
        wallet = create_max_wallet()
    elif choice == "2":
        wallet = create_apollo_wallet()
    else:
        print("Invalid choice")
        sys.exit(1)
    
    if wallet:
        print(f"\n✅ {wallet['username']}'s wallet is ready!")
    else:
        print(f"\n❌ Failed to create wallet")
        sys.exit(1)
