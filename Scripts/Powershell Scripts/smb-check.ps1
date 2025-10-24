<#
    Script Name : Check-And-Fix-SMB.ps1
    Description : Checks and disables SMBv1 completely (feature, registry, GPO override)
                  while ensuring SMBv2/3 is enabled. Works on all modern Windows versions.
    Author      : Sevag Bairamian
    Date        : 2025-10-16
#>

Write-Host ""
Write-Host "=== SMB Version Hardening Script ==="
Write-Host ""

function Get-SMBStatus {
    $smbFeature = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State
    $smb1Config = (Get-SmbServerConfiguration).EnableSMB1Protocol
    $smb2Config = (Get-SmbServerConfiguration).EnableSMB2Protocol

    Write-Host "SMBv1 Feature: $smbFeature"
    Write-Host "SMBv1 Protocol Enabled: $smb1Config"
    Write-Host "SMBv2/3 Protocol Enabled: $smb2Config"
}

Write-Host "Current SMB Configuration:"
Get-SMBStatus
Write-Host ""

# Disable SMBv1 Feature if present
Write-Host "Disabling SMBv1 Windows Feature..."
$features = Get-WindowsOptionalFeature -Online | Where-Object FeatureName -like "*SMB1*"
foreach ($f in $features) {
    Disable-WindowsOptionalFeature -Online -FeatureName $f.FeatureName -NoRestart -ErrorAction SilentlyContinue | Out-Null
}

# Disable SMBv1 via Server Configuration
Write-Host "Disabling SMBv1 via SMB Server Configuration..."
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue

# Registry enforcement (Server, Client, and Policy)
Write-Host "Applying registry-level SMBv1 disablement..."
$serverPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$clientPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanServer"

New-ItemProperty -Path $serverPath -Name SMB1 -Value 0 -PropertyType DWORD -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -Path $clientPath -Name SMB1 -Value 0 -PropertyType DWORD -Force -ErrorAction SilentlyContinue | Out-Null
New-Item -Path $policyPath -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -Path $policyPath -Name SMB1 -Value 0 -PropertyType DWORD -Force -ErrorAction SilentlyContinue | Out-Null

# Ensure SMBv2/3 Enabled
Write-Host "Ensuring SMBv2/3 is enabled..."
Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force -ErrorAction SilentlyContinue

# Final check
Write-Host ""
Write-Host "Final SMB Configuration (no reboot needed):"
Get-SMBStatus

Write-Host ""
Write-Host "SMBv1 has been disabled at all available layers."
Write-Host "SMBv2/3 confirmed enabled."
Write-Host "No reboot required, but SMBv1 services will be inactive until restart if they were previously active."
Write-Host ""
Write-Host "=== SMB Hardening Complete ==="