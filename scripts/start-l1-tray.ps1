Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$repo = "C:\Users\maxd1\Documents\GitHub\blackbook-wallet\L1_BlackBook"
$iconPath = Join-Path $repo "1 (1).png"
$tailScript = Join-Path $repo "scripts\tail-l1-log.ps1"

function ConvertTo-TrayIcon {
    param([string]$Path)
    $bitmap = [System.Drawing.Bitmap]::FromFile($Path)
    $size = 32
    $canvas = New-Object System.Drawing.Bitmap $size, $size
    $graphics = [System.Drawing.Graphics]::FromImage($canvas)
    $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $graphics.DrawImage($bitmap, 0, 0, $size, $size)
    $iconHandle = $canvas.GetHicon()
    $icon = [System.Drawing.Icon]::FromHandle($iconHandle)
    $clone = $icon.Clone()
    $graphics.Dispose()
    $bitmap.Dispose()
    return $clone
}

function Open-L1Terminal {
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit -NoProfile -ExecutionPolicy Bypass -File `"$tailScript`""
}

$tray = New-Object System.Windows.Forms.NotifyIcon
if (Test-Path $iconPath) {
    $tray.Icon = ConvertTo-TrayIcon $iconPath
} else {
    $tray.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon((Get-Process -Id $PID).Path)
}
$tray.Text = "Layer 1 is running at localhost:8080"
$tray.Visible = $true
$tray.ShowBalloonTip(4000, "BlackBook L1", "Layer 1 is running at localhost:8080", [System.Windows.Forms.ToolTipIcon]::Info)

$menu = New-Object System.Windows.Forms.ContextMenuStrip

$itemTerminal = New-Object System.Windows.Forms.ToolStripMenuItem
$itemTerminal.Text = "Open terminal"
$itemTerminal.Add_Click({ Open-L1Terminal })
[void]$menu.Items.Add($itemTerminal)

$itemRestart = New-Object System.Windows.Forms.ToolStripMenuItem
$itemRestart.Text = "Restart node"
$itemRestart.Add_Click({
    Start-Process -FilePath "powershell.exe" -Verb RunAs -WindowStyle Hidden -ArgumentList "-NoProfile -Command Restart-Service BlackBookL1"
    $tray.ShowBalloonTip(2000, "BlackBook L1", "Restart requested.", [System.Windows.Forms.ToolTipIcon]::Info)
})
[void]$menu.Items.Add($itemRestart)

[void]$menu.Items.Add("-")

$itemExit = New-Object System.Windows.Forms.ToolStripMenuItem
$itemExit.Text = "Hide tray icon"
$itemExit.Add_Click({
    $tray.Visible = $false
    $tray.Dispose()
    [System.Windows.Forms.Application]::Exit()
})
[void]$menu.Items.Add($itemExit)

$tray.ContextMenuStrip = $menu
[System.Windows.Forms.Application]::Run()
