# ============================================================================
# watch-feed.ps1 - Live L1 transaction feed watcher
# ============================================================================
# Polls the L1 /poh/transactions/recent endpoint and prints NEW transactions
# as they finalize. Useful for watching dealer/oracle-signed txs land.
#
# Usage:
#   .\watch-feed.ps1                          # watch all txs on l1.owire.org
#   .\watch-feed.ps1 -Address EdkcKbgiYRVWMGXKbehfDrAuWUcgd7A6UoJzVg7CYQCT
#   .\watch-feed.ps1 -Base http://localhost:8080
#   .\watch-feed.ps1 -IntervalSec 2
# ============================================================================

param(
    [string]$Base = "https://l1.owire.org",
    [string]$Address = "",
    [int]$IntervalSec = 3,
    [int]$Limit = 50
)

$Base = $Base.TrimEnd('/')
$seen = [System.Collections.Generic.HashSet[string]]::new()

function Get-Feed {
    if ($Address) {
        $url = "$Base/address/$Address/transactions?page=1&limit=$Limit"
        $r = Invoke-RestMethod -Uri $url -TimeoutSec 15
        return $r.transactions
    } else {
        $url = "$Base/poh/transactions/recent?limit=$Limit"
        $r = Invoke-RestMethod -Uri $url -TimeoutSec 15
        return $r.transactions
    }
}

function Format-Tx($tx) {
    $bb = [math]::Round($tx.amount / 100000.0, 5)
    $from = if ($tx.from_address.Length -gt 10) { $tx.from_address.Substring(0,8) + ".." } else { $tx.from_address }
    $to   = if ($tx.to_address.Length -gt 10)   { $tx.to_address.Substring(0,8) + ".." }   else { $tx.to_address }
    $ts   = [DateTimeOffset]::FromUnixTimeSeconds([int64]$tx.timestamp).ToLocalTime().ToString("HH:mm:ss")
    $line = "{0}  blk {1,-9} {2,-9} {3} -> {4}  {5,12} BB  [{6}]" -f $ts, $tx.block_height, $tx.tx_type, $from, $to, $bb, $tx.status
    return $line
}

Write-Host ""
Write-Host "  BlackBook L1 - live feed" -ForegroundColor Cyan
Write-Host "  Base     : $Base" -ForegroundColor Gray
if ($Address) {
    Write-Host "  Filter   : $Address" -ForegroundColor Gray
} else {
    Write-Host "  Filter   : (all transactions)" -ForegroundColor Gray
}
Write-Host "  Interval : ${IntervalSec}s   (Ctrl+C to stop)" -ForegroundColor Gray
Write-Host ("  " + ("-" * 100)) -ForegroundColor DarkGray

# Prime: mark existing txs as seen so we only print NEW ones
try {
    $initial = Get-Feed
    foreach ($tx in $initial) { [void]$seen.Add($tx.tx_id) }
    Write-Host "  Primed with $($seen.Count) existing tx(s). Waiting for new activity..." -ForegroundColor DarkGray
    Write-Host ""
} catch {
    Write-Host "  Failed to reach $Base : $_" -ForegroundColor Red
    exit 1
}

while ($true) {
    try {
        $txs = Get-Feed
        # Oldest-first so the feed reads chronologically
        foreach ($tx in ($txs | Sort-Object timestamp)) {
            if ($seen.Add($tx.tx_id)) {
                Write-Host (Format-Tx $tx) -ForegroundColor Green
            }
        }
    } catch {
        Write-Host "  (poll error: $_)" -ForegroundColor DarkYellow
    }
    Start-Sleep -Seconds $IntervalSec
}
