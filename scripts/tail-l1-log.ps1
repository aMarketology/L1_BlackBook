$log = "C:\Users\maxd1\Documents\GitHub\blackbook-wallet\L1_BlackBook\blockchain_data\service-out.log"
$Host.UI.RawUI.WindowTitle = "BlackBook L1 — live log (closing this window does not stop the node)"
Write-Host "BlackBook L1 is running as a Windows service."
Write-Host "Closing this window does not stop the node."
Write-Host ""
Get-Content -Path $log -Wait -Tail 40
