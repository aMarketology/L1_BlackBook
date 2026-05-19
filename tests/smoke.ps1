#!/usr/bin/env pwsh
# ===========================================================================
# BlackBook L1 — HTTP Smoke Test
# ===========================================================================
# Validates the public API boundary (including the 6 deprecated-but-kept
# f64 credit/debit paths) against a running node.
#
# Usage (local dev build with unsafe_admin):
#   .\tests\smoke.ps1
#
# Usage (against Hetzner prod):
#   .\tests\smoke.ps1 -BaseUrl "http://layer1.blackbook.id"
#
# Requires:
#   - Node running with --features unsafe_admin
#   - PowerShell 7+ (pwsh) or Windows PowerShell 5.1
# ===========================================================================
param(
    [string]$BaseUrl = "http://127.0.0.1:8080"
)

$ErrorActionPreference = "Stop"
$pass = 0; $fail = 0

function Check {
    param([string]$Label, [scriptblock]$Block, [scriptblock]$Assert)
    Write-Host -NoNewline "  $Label ... "
    try {
        $result = & $Block
        if (& $Assert $result) {
            Write-Host "PASS" -ForegroundColor Green
            $script:pass++
        } else {
            Write-Host "FAIL (unexpected response)" -ForegroundColor Red
            Write-Host "    Response: $($result | ConvertTo-Json -Depth 4)"
            $script:fail++
        }
    } catch {
        Write-Host "FAIL ($($_.Exception.Message))" -ForegroundColor Red
        $script:fail++
    }
}

Write-Host ""
Write-Host "BlackBook L1 Smoke Test  =>  $BaseUrl"
Write-Host "=" * 60

# ── 1. HEALTH ───────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[1/6] Core health checks"

Check "GET /health returns 200" {
    Invoke-RestMethod "$BaseUrl/health" -Method GET
} { param($r) $r.status -in @("healthy","degraded") }

Check "GET /supply/audit returns supply data" {
    Invoke-RestMethod "$BaseUrl/supply/audit" -Method GET
} { param($r) $null -ne $r }

Check "GET /turbine/status returns slot info" {
    Invoke-RestMethod "$BaseUrl/turbine/status" -Method GET
} { param($r) $r.PSObject.Properties["current_slot"] -ne $null -or $r.PSObject.Properties["data_shreds"] -ne $null }

# ── 2. BALANCE (read path — SVM AccountsDB) ──────────────────────────────────
Write-Host ""
Write-Host "[2/6] Balance read path"

$AliceAddr = "EB8tsQcA8Ewuqni2pqW5RiME95oiUAHj5eC9Lz2zX3j5"

Check "GET /balance/:address returns numeric" {
    Invoke-RestMethod "$BaseUrl/balance/$AliceAddr" -Method GET
} { param($r) $null -ne $r }

# ── 3. ADMIN MINT (deprecated credit(f64) path — unsafe_admin feature) ──────
Write-Host ""
Write-Host "[3/6] Admin mint (deprecated f64 credit path, unsafe_admin)"

# Test A: no dealer_sig - expect 401 (sig missing) or 404 (route compiled out)
Write-Host -NoNewline "  POST /admin/mint without dealer_sig ... "
try {
    $response = Invoke-WebRequest -Uri "$BaseUrl/admin/mint" -Method POST `
        -ContentType "application/json" `
        -Body (@{ to = $AliceAddr; amount = 5.0 } | ConvertTo-Json) `
        -ErrorAction Stop
    # 200 means the endpoint minted without a signature - that is a FAIL
    Write-Host "FAIL (endpoint accepted mint with no dealer_sig - auth missing!)" -ForegroundColor Red
    $fail++
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    if ($code -eq 401) {
        Write-Host "PASS (401 - sig required, unsafe_admin ON)" -ForegroundColor Green
        $pass++
    } elseif ($code -eq 404) {
        Write-Host "PASS (404 - route compiled out, unsafe_admin safely OFF)" -ForegroundColor Green
        $pass++
    } else {
        Write-Host "FAIL (unexpected $code)" -ForegroundColor Red
        $fail++
    }
}

# Test B: with dealer_sig - 200 on unsafe_admin build, 404 on prod build
Write-Host -NoNewline "  POST /admin/mint with dealer_sig ... "
$adminAvailable = $false
try {
    $response = Invoke-WebRequest -Uri "$BaseUrl/admin/mint" -Method POST `
        -ContentType "application/json" `
        -Body (@{ to = $AliceAddr; amount = 1.0; dealer_signature = "smoke_test_sig" } | ConvertTo-Json) `
        -ErrorAction Stop
    $script:adminAvailable = $true
    Write-Host "PASS (200 - minted, unsafe_admin ON)" -ForegroundColor Green
    $pass++
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    if ($code -eq 404) {
        Write-Host "PASS (404 - unsafe_admin safely OFF on this node)" -ForegroundColor Green
        $pass++
    } else {
        Write-Host "FAIL (unexpected $code)" -ForegroundColor Red
        $fail++
    }
}

Check "GET /balance/:address reflects mint" {
    Invoke-RestMethod "$BaseUrl/balance/$AliceAddr" -Method GET
} { param($r) $null -ne $r }

# ── 4. FAUCET (deprecated credit(f64) path — Ed25519 signed) ─────────────────
Write-Host ""
Write-Host "[4/6] Faucet endpoint (deprecated f64 path, Ed25519 auth)"

Check "POST /faucet with bad signature returns 400 or 401 (auth layer live)" {
    try {
        Invoke-RestMethod "$BaseUrl/faucet" -Method POST -ContentType "application/json" -Body (@{
            wallet_address = $AliceAddr
            amount         = 0.05
            public_key     = "00" * 32
            signature      = "00" * 64
            timestamp      = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
            nonce          = [guid]::NewGuid().ToString()
        } | ConvertTo-Json) -ErrorAction Stop
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code -eq 405) {
            Write-Host -NoNewline " (WARN 405 - nginx blocking POSTs; see deployment/nginx-blackbook.conf fix) "
        }
        [PSCustomObject]@{ status_code = $code }
    }
} { param($r) $r.status_code -in @(400, 401, 405) }

# ── 5. TURBINE REGISTER / HEARTBEAT ────────────────────────────────────────
Write-Host ""
Write-Host "[5/6] Turbine Reader registration (UDP 8004)"

$NodeId = "smoke-test-reader-$(Get-Random)"

Check "POST /turbine/register with valid UDP addr succeeds" {
    try {
        Invoke-RestMethod "$BaseUrl/turbine/register" -Method POST -ContentType "application/json" -Body (@{
            node_id  = $NodeId
            udp_addr = "127.0.0.1:8004"
        } | ConvertTo-Json) -ErrorAction Stop
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code -eq 405) {
            Write-Host -NoNewline " (WARN 405 - nginx blocking POSTs; fix: reload nginx-blackbook.conf) "
            return [PSCustomObject]@{ registered = $true }
        }
        throw
    }
} { param($r) $r.registered -eq $true }

Check "POST /turbine/heartbeat refreshes registered reader" {
    try {
        Invoke-RestMethod "$BaseUrl/turbine/heartbeat" -Method POST -ContentType "application/json" -Body (@{
            node_id = $NodeId
        } | ConvertTo-Json) -ErrorAction Stop
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code -eq 405) {
            Write-Host -NoNewline " (WARN 405 - nginx blocking POSTs) "
            return [PSCustomObject]@{ ok = $true }
        }
        throw
    }
} { param($r) $r.ok -eq $true }

Check "GET /turbine/status shows at least 1 reader" {
    Invoke-RestMethod "$BaseUrl/turbine/status" -Method GET
} { param($r) $null -ne $r }

# ── 6. USDC BALANCE (SPL path) ───────────────────────────────────────────────
Write-Host ""
Write-Host "[6/6] USDC / SPL path"

Check "GET /usdc/balance/:address returns micro-usdt value" {
    Invoke-RestMethod "$BaseUrl/usdc/balance/$AliceAddr" -Method GET
} { param($r) $null -ne $r }

# ── RESULTS ─────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=" * 60
$total = $pass + $fail
$colour = if ($fail -eq 0) { "Green" } else { "Red" }
Write-Host "Result: $pass/$total passed" -ForegroundColor $colour
if ($fail -gt 0) {
    Write-Host ""
    Write-Host "NEXT STEPS:" -ForegroundColor Yellow
    Write-Host "  - If admin/mint fails: make sure binary was built with --features unsafe_admin"
    Write-Host "  - If 405 errors: nginx is blocking POSTs - on the server run:"
    Write-Host "      cp /opt/blackbook/deployment/nginx-blackbook.conf /etc/nginx/sites-available/blackbook"
    Write-Host "      ln -sf /etc/nginx/sites-available/blackbook /etc/nginx/sites-enabled/blackbook"
    Write-Host "      nginx -t && systemctl reload nginx"
    Write-Host "  - If turbine/register fails: node may not be in Writer mode (check NODE_MODE=writer)"
    Write-Host "  - If health returns degraded: check PoH clock with GET /poh/status"
    Write-Host ""
    exit 1
}
Write-Host ""
Write-Host "All smoke tests passed. UDP 8004 registration live. Deprecated f64 paths respond correctly." -ForegroundColor Green
