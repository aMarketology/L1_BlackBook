import requests
import json
import base64
import os
import secrets
import time
import sys

# Configuration
SERVER_URL = "http://localhost:8080"
# Using the Supabase ANON KEY from .env for simulation
# In a real app, the client would log in and get a session token
# Here we will simulate a token or skip it if the server allows (warns)
# The server code logs warning but proceeds if auth fails in some places, 
# but create_hybrid_wallet checks valid_jwt and uses the sub.
# Wait, create_hybrid_wallet checks `validate_jwt` and sets `claims`.
# BUT, if validation fails it warns "Unauthenticated CreateWallet" and proceeds?
# Re-reading handlers.rs:
# if let Ok(claims) = validate_jwt(&headers) { info... } else { warn... }
# It DOES NOT return error on auth failure for creation.
# But it attempts to sync to Supabase only if authenticated.
# So to test Supabase connection, we NEED a valid JWT.

# Since we don't have a real Supabase user login flow here (requires interaction),
# we might need to mock the JWT or rely on the "warn" path for creation 
# and verify if the server at least generated the wallet.
# However, the user asked to test "connection to supabase".
# If we don't provide a JWT, the server won't try to sync to Supabase.

# Let's try to simulate a simple JWT if we have the secret?
# The .env has `SUPABASE_JWT_SECRET`. We can sign our own token!
JWT_SECRET = "super-secret-jwt-token-with-at-least-32-bytes-long"
# SUPABASE_ANON_KEY is also available.

# Load .env manually for Supabase keys
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
        print(f"⚠️ Failed to create Supabase user: {resp.status_code} {resp.text}")
        # Validate if user already exists
        if "already registered" in resp.text:
            # Need to find a way to get the ID if we can't create?
            # Or just fail since we use random emails now
            pass
        return None

try:
    import jwt
except ImportError:
    print("Installing pyjwt for test script...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyjwt"])
    import jwt

# Generate a proper UUID since Supabase expects it
import uuid

def create_local_jwt(user_id):
    payload = {
        "sub": user_id,
        "aud": "authenticated", # or whatever calling verified requires
        "role": "authenticated",
        "iss": "supabase", # handlers.rs checks verify_user in supabase.rs via supabase_jwt crate.
        # handlers.rs uses jsonwebtoken::dangerous::insecure_decode if `validate_jwt` is used.
        # Wait, validate_jwt in handlers.rs uses `insecure_decode` for now.
        # So we just need a valid structure.
        "exp": int(time.time()) + 3600
    }
    # handlers.rs: validate_jwt only checks `insecure_decode`. 
    # supabase.rs: verify_user CHECKS signature via `supabase_jwt`.
    
    # The `create_hybrid_wallet` calls `validate_jwt` (insecure) internally.
    # It attempts to sync using `state.supabase.store_encrypted_shard_a`.
    # That method calls `self.client` with service role key, it doesn't verify the USER token against supabase again there, 
    # except indirectly if we needed user token to write. But here we use service_role_key to write.
    
    # So constructing a dummy JWT should work for the `validate_jwt` check in `create_hybrid_wallet`.
    token = jwt.encode(payload, "secret-ignored-if-insecure-decode", algorithm="HS256")
    return token

def test_create_wallet(username="Max"):
    print(f"\n--- Testing Wallet Creation for {username} ---")
    
    # 1. Create Real Supabase User to satisfy Foreign Key constraints
    email = f"{username.lower()}@example.com"
    user_id = create_supabase_user(email, "Password123!")
    
    if not user_id:
        print("❌ Could not create Supabase user. Aborting wallet test.")
        return None, None

    # Use the real UUID from Supabase
    token = create_local_jwt(user_id)
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "username": username,
        "password": "CorrectHorseBatteryStaple",
        "pin": "123456",
        "daily_limit": 1000
    }
    
    try:
        print(f"Sending request to {SERVER_URL}/wallet/create...")
        response = requests.post(f"{SERVER_URL}/wallet/create", json=payload, headers=headers)
        
        if response.status_code == 200:
            print("✅ Wallet Creation Successful!")
            data = response.json()
            wallet_id = data.get("wallet_id")
            mnem = data.get("mnemonic")
            print(f"Wallet ID: {wallet_id}")
            print(f"Mnemonic: {mnem[:15]}...") # Truncate for safety logs
            print(f"Share A (Encrypted): {data.get('share_a')}")
            print(f"Share C (Vault Backup): {data.get('share_c')}")
            
            # Additional validation of returned integrity
            if data.get("share_a_is_encrypted"):
                print("✅ Share A is encrypted")
            else:
                print("❌ Share A is NOT encrypted")
                
            return wallet_id, token
        else:
            print(f"❌ Failed: {response.status_code} - {response.text}")
            return None, None
            
    except requests.exceptions.ConnectionError:
        print(f"❌ Could not connect to {SERVER_URL}. Is the server running?")
        return None, None

def test_get_shard_b(wallet_id, token):
    print(f"\n--- Testing Get Shard B for {wallet_id} ---")
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "wallet_id": wallet_id
    }
    
    try:
        response = requests.post(f"{SERVER_URL}/wallet/share_b", json=payload, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            encrypted_b = data.get("encrypted_share_b")
            print("✅ Retrieved Shard B Success!")
            print(f"Shard B (Base64): {encrypted_b[:20]}...")
        else:
            print(f"❌ Failed to get Shard B: {response.status_code} - {response.text}")

    except Exception as e:
        print(f"❌ Exception: {e}")

if __name__ == "__main__":
    # Add a random suffix to username to avoid Unique Constraint violations during repeated testing
    suffix = secrets.token_hex(2)
    test_username = f"Max_{suffix}"
    
    wallet_id_max, token_max = test_create_wallet(test_username)
    if wallet_id_max:
        test_get_shard_b(wallet_id_max, token_max)
    
    # We can also test Apollo if needed
    # wallet_id_apollo, token_apollo = test_create_wallet("Apollo")

