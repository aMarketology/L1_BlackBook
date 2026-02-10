# Load environment variables from .env file
Get-Content .env | ForEach-Object {
    if ($_ -match '^([^=]+)=(.*)$') {
        $key = $matches[1]
        $value = $matches[2]
        Set-Item -Path "env:$key" -Value $value
        Write-Host "✓ Loaded $key" -ForegroundColor Green
    }
}

Write-Host "`n🚀 Starting Layer 1 Server...`n" -ForegroundColor Cyan

# Run the server
cargo run --bin layer1
