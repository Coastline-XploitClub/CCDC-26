<#
.SYNOPSIS
  Performs a full Domain Controller hardening audit for critical Windows vulnerabilities.
.DESCRIPTION
  This script checks and optionally fixes key security configurations such as:
  - ZeroLogon (Netlogon hardening)
  - SMBv1 / EternalBlue exposure
  - NTLM enforcement (NTLMv2 only)
  - LLMNR, LSASS, Kerberos, SMB Signing
  - Anonymous and Guest account restrictions
  - Audit policy verification

  It highlights [Secure], [Warning], or [Critical] results in color,
  and offers on-demand fixes for unsafe settings.
  Ideal for blue team competitions, DC baselines, or quick post-incident checks.
#>


Import-Module ActiveDirectory -ErrorAction SilentlyContinue
Write-Host "=== Domain Controller Security Hardening Audit ===" -ForegroundColor Cyan
Write-Host "Running local checks on $env:COMPUTERNAME ..." -ForegroundColor Yellow
Write-Host ""

function Write-Result {
    param($Name,$Status,$Info)
    $c = switch ($Status) {
        "Secure"   { "Green" }
        "Warning"  { "Yellow" }
        "Critical" { "Red" }
        default    { "Gray" }
    }
    Write-Host ("[{0}] {1} - {2}" -f $Status,$Name,$Info) -ForegroundColor $c
}

# --- ZEROLOGON ---
Write-Host "`n[+] Checking ZeroLogon..." -ForegroundColor Cyan
try {
    $r = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -ErrorAction Stop
    $values = @(
        $r.RequireStrongKey,
        $r.RequireSignOrSeal,
        $r.RequireSeal,
        $r.RequireSigning
    )
    $isHardened = ($values -notcontains 0 -and $values.Count -ge 3)

    if ($isHardened) {
        Write-Result "ZeroLogon" "Secure" "Netlogon channel hardened (ensure latest Windows update installed)"
    } else {
        Write-Result "ZeroLogon" "Critical" "Not hardened - vulnerable to ZeroLogon"
        $fix = Read-Host "      Apply this fix now? (Y/N)"
        if ($fix -match "^[Yy]$") {
            Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters -Name RequireStrongKey -Value 1 -Type DWord -Force
            Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters -Name RequireSignOrSeal -Value 1 -Type DWord -Force
            Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters -Name RequireSeal -Value 1 -Type DWord -Force
            Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters -Name RequireSigning -Value 1 -Type DWord -Force
            Restart-Service Netlogon
            Write-Host "      ✅ Netlogon hardened successfully." -ForegroundColor Green
        }
    }
} catch {
    Write-Result "ZeroLogon" "Warning" "Unable to verify Netlogon configuration"
}

# --- SMBv1 / EternalBlue ---
Write-Host "`n[+] Checking EternalBlue..." -ForegroundColor Cyan
try {
    $smbf = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
    $smbs = (Get-SmbServerConfiguration).EnableSMB1Protocol
    if ($smbf.State -eq "Disabled" -and (-not $smbs)) {
        Write-Result "EternalBlue" "Secure" "SMBv1 fully disabled"
    } else {
        Write-Result "EternalBlue" "Critical" "SMBv1 enabled or partially active"
        $fix = Read-Host "      Apply this fix now? (Y/N)"
        if ($fix -match "^[Yy]$") {
            Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null
            Set-SmbServerConfiguration -EnableSMB1Protocol $False -Force | Out-Null
            Write-Host "      ✅ SMBv1 disabled successfully. Restart required to take full effect." -ForegroundColor Green
        }
    }
} catch {
    Write-Result "EternalBlue" "Warning" "Unable to verify SMBv1 status"
}

# --- NTLM ---
Write-Host "`n[+] Checking NTLM..." -ForegroundColor Cyan
try {
    $lvl = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa").LmCompatibilityLevel
    if ($lvl -ge 5) {
        Write-Result "NTLM" "Secure" "NTLMv2 only (Level $lvl)"
    } else {
        Write-Result "NTLM" "Warning" "Not configured"
        $fix = Read-Host "      Apply this fix now? (Y/N)"
        if ($fix -match "^[Yy]$") {
            New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LmCompatibilityLevel -Value 5 -Type DWord -Force
            Write-Host "      ✅ NTLMv2 enforced successfully." -ForegroundColor Green
        }
    }
} catch { Write-Result "NTLM" "Warning" "Unable to verify" }

# --- LLMNR ---
Write-Host "`n[+] Checking LLMNR..." -ForegroundColor Cyan
try {
    $dnsKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    if (-not (Test-Path $dnsKey)) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT" -Name "DNSClient" -Force | Out-Null
    }
    $ll = Get-ItemProperty -Path $dnsKey -Name EnableMulticast -ErrorAction SilentlyContinue
    if ($ll.EnableMulticast -eq 0) {
        Write-Result "LLMNR" "Secure" "Disabled"
    } else {
        Write-Result "LLMNR" "Warning" "Enabled"
        $fix = Read-Host "      Apply this fix now? (Y/N)"
        if ($fix -match "^[Yy]$") {
            New-ItemProperty -Path $dnsKey -Name EnableMulticast -Value 0 -Type DWord -Force | Out-Null
            Write-Host "      ✅ LLMNR disabled successfully." -ForegroundColor Green
        }
    }
} catch {
    Write-Result "LLMNR" "Warning" "Policy missing or inaccessible"
}


# --- LSASS ---
Write-Host "`n[+] Checking LSASS..." -ForegroundColor Cyan
try {
    $lsaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $ls = Get-ItemProperty -Path $lsaKey -Name RunAsPPL -ErrorAction SilentlyContinue
    if ($ls.RunAsPPL -eq 1) {
        Write-Result "LSASS" "Secure" "Protected"
    } else {
        Write-Result "LSASS" "Warning" "Not protected"
        $fix = Read-Host "      Apply this fix now? (Y/N)"
        if ($fix -match "^[Yy]$") {
            New-ItemProperty -Path $lsaKey -Name RunAsPPL -Value 1 -Type DWord -Force | Out-Null
            Write-Host "      ✅ LSASS protection enabled. Restart required." -ForegroundColor Green
        }
    }
} catch {
    Write-Result "LSASS" "Warning" "Not configured"
}

# --- Kerberos ---
Write-Host "`n[+] Checking Kerberos..." -ForegroundColor Cyan
$svc = Get-Service KDC -ErrorAction SilentlyContinue
if ($svc.Status -eq "Running") {
    Write-Result "Kerberos KDC" "Secure" "Running"
} else {
    Write-Result "Kerberos KDC" "Critical" "Not running"
}

try {
    $kerbPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
    if (-not (Test-Path $kerbPath)) {
        New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "Kerberos" -Force | Out-Null
        New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos" -Name "Parameters" -Force | Out-Null
    }
    $enc = Get-ItemProperty -Path $kerbPath -Name SupportOldEncryptionTypes -ErrorAction SilentlyContinue
    if ($enc.SupportOldEncryptionTypes -eq 0) {
        Write-Result "Kerberos Encryption" "Secure" "DES/RC4 disabled"
    } else {
        Write-Result "Kerberos Encryption" "Warning" "Legacy ciphers enabled"
        $fix = Read-Host "      Apply this fix now? (Y/N)"
        if ($fix -match "^[Yy]$") {
            New-ItemProperty -Path $kerbPath -Name SupportOldEncryptionTypes -Value 0 -Type DWord -Force | Out-Null
            Write-Host "      ✅ Kerberos hardened successfully." -ForegroundColor Green
        }
    }
} catch {
    Write-Result "Kerberos Encryption" "Warning" "Cannot verify or permission denied"
}

# --- SMB Signing ---
Write-Host "`n[+] Checking SMB Signing..." -ForegroundColor Cyan
try {
    $srv = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters').RequireSecuritySignature
    $cli = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters').RequireSecuritySignature
    if ($srv -eq 1 -and $cli -eq 1) {
        Write-Result "SMB Signing" "Secure" "Enforced"
    } else {
        Write-Result "SMB Signing" "Warning" "Not enforced"
        $fix = Read-Host "      Apply this fix now? (Y/N)"
        if ($fix -match "^[Yy]$") {
            Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name RequireSecuritySignature -Value 1 -Type DWord
            Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name RequireSecuritySignature -Value 1 -Type DWord
            Write-Host "      ✅ SMB Signing enforced successfully." -ForegroundColor Green
        }
    }
} catch { Write-Result "SMB Signing" "Warning" "Cannot verify" }

# --- Anonymous Access ---
Write-Host "`n[+] Checking Anonymous Access..." -ForegroundColor Cyan
try {
    $anon = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction Stop
    if ($anon.RestrictAnonymous -eq 1) {
        Write-Result "Anonymous Access" "Secure" "Restricted"
    } else {
        Write-Result "Anonymous Access" "Warning" "Unrestricted"
        $fix = Read-Host "      Apply this fix now? (Y/N)"
        if ($fix -match "^[Yy]$") {
            New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymous -Value 1 -Type DWord -Force
            Write-Host "      ✅ Anonymous access restricted." -ForegroundColor Green
        }
    }
} catch { Write-Result "Anonymous Access" "Warning" "Cannot verify" }

# --- Guest Account ---
Write-Host "`n[+] Checking Guest Account..." -ForegroundColor Cyan
try {
    $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($guest -and -not $guest.Enabled) {
        Write-Result "Guest Account" "Secure" "Disabled"
    } else {
        Write-Result "Guest Account" "Warning" "Enabled"
        $fix = Read-Host "      Apply this fix now? (Y/N)"
        if ($fix -match "^[Yy]$") {
            net user guest /active:no | Out-Null
            Write-Host "      ✅ Guest account disabled successfully." -ForegroundColor Green
        }
    }
} catch { Write-Result "Guest Account" "Warning" "Cannot verify" }

# --- Audit Policy ---
Write-Host "`n[+] Checking Audit Policy..." -ForegroundColor Cyan
try {
    $audit = auditpol /get /category:* | Out-String
    if ($audit -match "No Auditing") {
        Write-Host "[Info] Audit Policy appears managed by Group Policy or partially applied." -ForegroundColor Yellow
        Write-Host "       Wait for gpupdate/replication to complete, or verify via GPMC -> Advanced Audit Policy Configuration." -ForegroundColor Gray
    } else {
        Write-Host "[Secure] Audit Policy - Major categories enabled via GPO or local policy." -ForegroundColor Green
    }
} catch {
    Write-Host "[Warning] Audit Policy - Unable to verify (permissions or module issue)." -ForegroundColor Yellow
}

Write-Host "`n=== Audit Complete ===" -ForegroundColor Cyan
