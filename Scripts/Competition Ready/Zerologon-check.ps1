# ZeroLogon (CVE-2020-1472) Check & Mitigation Script
# Run as Administrator on a Domain Controller

Write-Host "=== Checking for ZeroLogon Mitigation Status ==="

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
$regName = "FullSecureChannelProtection"

try {
    # Check if key exists
    $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop | Select-Object -ExpandProperty $regName
    if ($value -eq 1) {
        Write-Host "ZeroLogon mitigation is already enabled. (FullSecureChannelProtection = 1)"
    }
    else {
        Write-Host "ZeroLogon mitigation is not fully enforced. Applying fix..."
        Set-ItemProperty -Path $regPath -Name $regName -Value 1
        Write-Host "Mitigation applied successfully. (FullSecureChannelProtection set to 1)"
    }
}
catch {
    Write-Host "Registry key not found. Creating and enabling mitigation..."
    New-ItemProperty -Path $regPath -Name $regName -Value 1 -PropertyType DWORD -Force | Out-Null
    Write-Host "Mitigation applied successfully. (FullSecureChannelProtection created and set to 1)"
}

# Confirm result
$confirm = Get-ItemProperty -Path $regPath -Name $regName | Select-Object -ExpandProperty $regName
Write-Host "Current ZeroLogon mitigation state: $confirm (1 = Enabled, 0 = Disabled)"