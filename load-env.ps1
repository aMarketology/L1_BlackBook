# Load environment variables from .env file
Get-Content .env | ForEach-Object {
    $line = $_.Trim()
    # Skip empty lines and comments
    if ($line -and !$line.StartsWith('#')) {
        # Match KEY=VALUE pattern
        if ($line -match '^([A-Z_][A-Z0-9_]*)=(.*)$') {
            $key = $matches[1]
            $value = $matches[2].Trim('"').Trim("'")
            [System.Environment]::SetEnvironmentVariable($key, $value, 'Process')
            Write-Host "✓ Loaded: $key" -ForegroundColor Green
        }
    }
}

Write-Host "`n🚀 Starting Layer1..." -ForegroundColor Cyan
cargo run --bin layer1
