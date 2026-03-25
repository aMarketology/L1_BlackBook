# BlackBook L1 — Live HTTP Smoke Test
# Requires: cargo run --features unsafe_admin (L1 running on :8080)
#
# Run with:
#   .\tests\l1_smoke.ps1
# Or with custom host:
#   .\tests\l1_smoke.ps1 -L1Host "192.168.1.100:8080"
#
# NOTE: Tests 5.2, 5.7, 5.8 require Node.js or the L2 server to generate
#       valid Ed25519 signatures. Those tests use pre-signed test vectors
#       generated from the L2 sequencer keypair in .env.

param(
    [string]$L1Host = "localhost:8080"
)

$base = "http://$L1Host"
$pass = 0
$fail = 0

function Pass($msg) {
    Write-Host "  ✅ PASS: $msg" -ForegroundColor Green
    $script:pass++
}

function Fail($msg) {
    Write-Host "  ❌ FAIL: $msg" -ForegroundColor Red
    $script:fail++
}

function Section($title) {
    Write-Host ""
    Write-Host "── $title ──────────────────────────────────" -ForegroundColor Cyan
}

# ─────────────────────────────────────────────────────────────────────────────
# TEST 5.1 — Health Check
# ─────────────────────────────────────────────────────────────────────────────
Section "TEST 5.1 — Health Check"

try {
    $r = Invoke-RestMethod "$base/escrow/status"
    Write-Host "  Response: $($r | ConvertTo-Json -Compress)"

    if ($r.l2_sequencer_configured -eq $true) {
        Pass "l2_sequencer_configured = true"
    } else {
        Fail "l2_sequencer_configured is false — set L2_SEQUENCER_PUBKEY on L1"
    }

    if ($null -ne $r.escrow_address -and $r.escrow_address -ne "") {
        Pass "escrow_address present: $($r.escrow_address)"
    } else {
        Fail "escrow_address missing"
    }
} catch {
    Fail "GET /escrow/status failed: $_"
}

# ─────────────────────────────────────────────────────────────────────────────
# TEST 5.2a — Admin Mint
# ─────────────────────────────────────────────────────────────────────────────
Section "TEST 5.2a — Admin Mint (requires --features unsafe_admin)"

# Use a fixed test wallet (base58 32-byte Solana-style pubkey)
$testWallet = "GsbwXfJraMomNxBcpR3DBdFEWmZGRmMVFZKfDe3Xwxvb"

$mintBody = @{
    to     = $testWallet
    amount = 100.0
} | ConvertTo-Json

try {
    $r = Invoke-RestMethod "$base/admin/mint" -Method POST `
        -ContentType "application/json" -Body $mintBody
    Write-Host "  Response: $($r | ConvertTo-Json -Compress)"

    if ($r.success -eq $true) {
        Pass "Minted 100 BB to $testWallet (new_balance=$($r.new_balance))"
    } else {
        Fail "Mint returned success=false"
    }
} catch {
    $status = $_.Exception.Response.StatusCode.value__
    if ($status -eq 404) {
        Fail "admin/mint returned 404 — did you start L1 with --features unsafe_admin?"
    } else {
        Fail "admin/mint failed ($status): $_"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# TEST 5.2b — Balance Check
# ─────────────────────────────────────────────────────────────────────────────
Section "TEST 5.2b — Balance Check after Mint"

try {
    $r = Invoke-RestMethod "$base/balance/$testWallet"
    Write-Host "  Response: $($r | ConvertTo-Json -Compress)"

    if ($r.balance -ge 100) {
        Pass "Balance >= 100 BB after mint"
    } else {
        Fail "Expected balance >= 100, got: $($r.balance)"
    }
} catch {
    Fail "GET /balance/:wallet failed: $_"
}

# ─────────────────────────────────────────────────────────────────────────────
# TEST 5.3 — InitContestReserve via HTTP (gRPC-equivalent check)
# Note: InitContestReserve is a gRPC-only call from L2. Here we verify the
# escrow/contest endpoint shows OPEN after L2 calls it. This test mocks by
# checking the state after a direct submit-state-root (which creates Settled)
# and confirms the endpoint is queryable. Full InitContestReserve must be
# triggered from L2 — see L2_TEST_GUIDE.md.
# ─────────────────────────────────────────────────────────────────────────────
Section "TEST 5.3 — Contest Endpoint Reachable"

$testContest = "smoke-test-contest-001"
try {
    $r = Invoke-RestMethod "$base/escrow/contest/$testContest" -ErrorAction SilentlyContinue
    # Not found is expected — contest not yet created
    Fail "Contest should not exist yet — got: $($r | ConvertTo-Json -Compress)"
} catch {
    $status = $_.Exception.Response.StatusCode.value__
    if ($status -eq 404) {
        Pass "GET /escrow/contest/:id returns 404 for unknown contest (correct)"
    } else {
        Fail "Unexpected status $status: $_"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# TEST 5.5 — SubmitMerkleRoot via HTTP fallback
# Uses the L2 sequencer key from .env to sign the request.
# Note: Signing requires ed25519 — run `node tests\sign_submit.js` first to
# generate SUBMIT_SIG, or trigger from L2 `resolve_bb()` (preferred path).
# ─────────────────────────────────────────────────────────────────────────────
Section "TEST 5.5 — Submit State Root (HTTP fallback path)"

# These values are pre-computed for the smoke test contest.
# Replace SUBMIT_SIG with output of: node tests\sign_submit.js
$merkleRoot     = "a" * 64  # placeholder — replace with real 32-byte hex
$submitSig      = "b" * 128 # placeholder — replace with real 64-byte Ed25519 sig hex
$l2BlockNumber  = 1

Write-Host "  ⚠️  Skipping live submission — replace merkleRoot + submitSig with" -ForegroundColor Yellow
Write-Host "     values from 'node tests\sign_submit.js' or trigger via L2 resolve_bb()" -ForegroundColor Yellow

# Uncomment and fill in to run:
# $submitBody = @{
#     market_id       = $testContest
#     merkle_root     = $merkleRoot
#     signature       = $submitSig
#     l2_block_number = $l2BlockNumber
#     total_deposited = 10000000
#     total_payout    = 9500000
#     house_rake      = 500000
#     winner_count    = 2
# } | ConvertTo-Json
#
# try {
#     $r = Invoke-RestMethod "$base/escrow/submit-state-root" -Method POST `
#         -ContentType "application/json" -Body $submitBody
#     if ($r.success) {
#         Pass "submit-state-root OK: l1_tx_hash=$($r.l1_tx_hash) deadline_slot=$($r.claim_deadline_slot)"
#     } else { Fail "Submit returned success=false" }
# } catch { Fail "submit-state-root failed: $_" }

# ─────────────────────────────────────────────────────────────────────────────
# TEST 5.6 — GetContestStatus after settlement
# Run after triggering resolve_bb() on L2. Replace $testContest with the
# actual contest ID used.
# ─────────────────────────────────────────────────────────────────────────────
Section "TEST 5.6 — Contest Status after Settlement"
Write-Host "  ℹ️  Run after L2 resolve_bb() completes, then:" -ForegroundColor Yellow
Write-Host "     curl $base/escrow/contest/<contest_id>" -ForegroundColor Yellow
Write-Host "     Expect: status=SETTLED, claim_deadline_slot>0, total_claimed=0" -ForegroundColor Yellow

# ─────────────────────────────────────────────────────────────────────────────
# TEST 5.7 — Winner Withdraw (requires real Merkle proof from L2)
# Get the proof from L2: GET /proof/:market/:wallet
# Then use it here.
# ─────────────────────────────────────────────────────────────────────────────
Section "TEST 5.7 — Winner Withdraw"
Write-Host "  ℹ️  Prerequisites:" -ForegroundColor Yellow
Write-Host "     1. Contest must be SETTLED on L1 (Test 5.5 done)" -ForegroundColor Yellow
Write-Host "     2. GET /proof/:market/:wallet on L2 → copy proof array" -ForegroundColor Yellow
Write-Host "     3. Winner signs: ESCROW_WITHDRAW:<market>:<wallet>:<amount>:<ts>:<nonce>" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Example curl (fill in real values after L2 resolves):" -ForegroundColor Yellow
Write-Host @"
  curl -X POST $base/escrow/withdraw ``
    -H "Content-Type: application/json" ``
    -d '{
      "market_id":    "<contest_id>",
      "amount":       5.5,
      "wallet_address": "<winner_wallet_bs58>",
      "merkle_proof": ["<hex_sibling_1>", "<hex_sibling_2>"],
      "public_key":   "<winner_pubkey_hex>",
      "signature":    "<sig_hex>",
      "timestamp":    <unix_ts>,
      "nonce":        "<uuid>"
    }'
"@ -ForegroundColor DarkGray

# ─────────────────────────────────────────────────────────────────────────────
# TEST 5.8 — Double-Claim Blocked
# ─────────────────────────────────────────────────────────────────────────────
Section "TEST 5.8 — Double-Claim Blocked"
Write-Host "  ℹ️  Repeat the exact same withdraw request from Test 5.7." -ForegroundColor Yellow
Write-Host "     Expected: HTTP 409 Conflict" -ForegroundColor Yellow
Write-Host "     Response: { ""error"": ""Already withdrawn for this market"" }" -ForegroundColor Yellow

# ─────────────────────────────────────────────────────────────────────────────
# TEST 5.9 — Full Tally
# ─────────────────────────────────────────────────────────────────────────────
Section "TEST 5.9 — Full Tally"
Write-Host "  ℹ️  After all winners claim, verify:" -ForegroundColor Yellow
Write-Host "     curl $base/escrow/contest/<contest_id>" -ForegroundColor Yellow
Write-Host "     total_claimed should equal total_deposited - house_rake" -ForegroundColor Yellow
Write-Host "     e.g. 10000000 deposited, 500000 rake → total_claimed = 9500000" -ForegroundColor Yellow

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "════════════════════════════════════════════════" -ForegroundColor White
Write-Host "  AUTOMATED: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { "Green" } else { "Red" })
Write-Host "  MANUAL:    Tests 5.5–5.9 require L2 to be running" -ForegroundColor Yellow
Write-Host "             See docs\L2_TEST_GUIDE.md for L2 steps" -ForegroundColor Yellow
Write-Host "════════════════════════════════════════════════" -ForegroundColor White

if ($fail -gt 0) { exit 1 }
