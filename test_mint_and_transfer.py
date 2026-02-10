import requests
import json
import sys

SERVER_URL = "http://localhost:8080"

# From fresh wallet creation
MAX_WALLET = {
    "wallet_id": "8f42953c1f350a037bfb0b6dfa0596df61b01f7dd8ab3cfb454d150cd9d42e4b",
    "address":  "8f42953c1f350a037bfb0b6dfa0596df61b01f7dd8ab3cfb454d150cd9d42e4b",
    "share_a": "OMGiEYskJ9nwJb04/w6MpQ:70f59cd3d82384d94bb9d51d:d00d52c95c7ac4953c3cf48b9d5bb75a66a1a5228a6f4a09a100c2416bbbfbd4bbeb07a584fda61c1df86de4a25e8f42ada391144db3792f2616be6aa75e4048bd71baaa26fb3ab8c5dd54b1b596dfbb7ea087d037e29c5ff4f41507e0aaaad4f9538b8b9b93655e25cf939265d4fbe3d9c854aaa9dd39140251d333bd60dc52485696072d61dbb798ae7794b4cd03f50661d1d211a5a0dcfd3d2fdd9b004c36644569a0e74a7d72d1f647e1c177ec438098960e4584f412b17ae6cbfacfb605efcae6caaeea5f5329a5894d127261fd99d4a09f0d12b124d1322676fedf9562eb1b870c717190a8fd4493a83b06e582d9572cd15b7705f023572c2767ff998e48afdd1204a24724360c4750bb67be625baa736454b10d67666ac203800eb04fa9e2bbff710be4c881770cd754a6945612b7e244a1b5b5b63a7ea19b361d7d125f9a7e9a1bd741e4c9888586fbe8ba3f9be4015531e0031a6338a7ad92670e7ca5de5ba214683ee687712bc54be11811c989a06c9231ecea5c8554c523e1c0677662320c06cc71aa",
    "password": "CorrectHorseBatteryStaple"
}

APOLLO_WALLET = {
    "wallet_id": "cfee58e3d8b44bc08a257a4c6deb171892ee3e1ecfa7bce137cbcca30637e202",
    "address": "cfee58e3d8b44bc08a257a4c6deb171892ee3e1ecfa7bce137cbcca30637e202"
}

print("🚀 Testing SSS Wallet Transactions\n")

# Step 1: Mint 555 tokens to Max
print("--- Step 1: Minting 555 BB to Max ---")
mint_payload = {
    "to": MAX_WALLET['address'],
    "amount": 555.0
}

resp = requests.post(f"{SERVER_URL}/admin/mint", json=mint_payload)
if resp.status_code == 200:
    data = resp.json()
    print(f"✅ Minted {data['minted']} BB to Max")
    print(f"   Max Balance: {data['new_balance']} BB")
else:
    print(f"❌ Mint failed: {resp.status_code} - {resp.text}")
    sys.exit(1)

# Step 2: Transfer 222 BB from Max to Apollo using SSS
print("\n--- Step 2: Transfer 222 BB from Max to Apollo (SSS Signed) ---")
transfer_payload = {
    "from_wallet_id": MAX_WALLET['wallet_id'],
    "to_address": APOLLO_WALLET['address'],
    "amount": 222.0,
    "share_a": MAX_WALLET['share_a'],
    "password": MAX_WALLET['password']
}

resp = requests.post(f"{SERVER_URL}/transfer", json=transfer_payload)
if resp.status_code == 200:
    data = resp.json()
    print(f"✅ Transfer Successful!")
    print(f"   Signature: {data['signature'][:32]}...")
    print(f"   Max Balance: {data['from_balance']} BB")
    print(f"   Apollo Balance: {data['to_balance']} BB")
else:
    print(f"❌ Transfer failed: {resp.status_code} - {resp.text}")
    sys.exit(1)

print("\n✅ All transactions completed successfully!")
print(f"\n📊 Final Balances:")
print(f"   Max: {data['from_balance']} BB")
print(f"   Apollo: {data['to_balance']} BB")
