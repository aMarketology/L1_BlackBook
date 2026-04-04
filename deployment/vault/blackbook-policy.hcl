# BlackBook L1 - Vault Access Policy
# This policy restricts the wallet server to ONLY reading the pepper secret
# No write, delete, or administrative access is granted

# Allow reading the pepper from the KV v2 secrets engine
path "blackbook/data/pepper" {
  capabilities = ["read"]
}

# Allow listing secrets (for health checks)
path "blackbook/metadata/pepper" {
  capabilities = ["read"]
}

# Deny all other paths explicitly
path "*" {
  capabilities = ["deny"]
}
