<#
.SYNOPSIS
  Local security baseline installer (password, lockout, audit, SMB, LDAP signing)
.DESCRIPTION
  Hardens a standalone or workgroup Windows machine. No domain/GPO requirements.
  Sets password & lockout policy, enforces SMB signing, LDAP signing, audit categories,
  and other common hardening flags.
.NOTES
  Author: Cesar
  Run as Administrator
#>

Write-Host "=== LOCAL SECURITY BASELINE APPLY ===" -ForegroundColor Cyan

# ---------------------------
# Utility Functions
# ---------------------------
function Write-Ok($msg)  { Write-Host "✔ $msg" -ForegroundColor Green }
function Write-Info($msg){ Write-Host "→ $msg" -ForegroundColor Cyan }
function Write-Warn($msg){ Write-Host "⚠ $msg" -ForegroundColor Yellow }

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Write-Warn "Please run this script as Administrator. Exiting."
    return
}

# ---------------------------
# 1) Local Password / Lockout Policy
# ---------------------------
Write-Info "Configuring local password & lockout policy..."
try {
    net accounts /MINPWLEN:14 /MAXPWAGE:60 /MINPWAGE:1 /UNIQUEPW:24 /LOCKOUTTHRESHOLD:5 /LOCKOUTDURATION:15 /LOCKOUTWINDOW:15 | Out-Null
    Write-Ok "Password & lockout policy applied via 'net accounts'"
} catch { Write-Warn "Failed to apply password policy: $($_.Exception.Message)" }

# ---------------------------
# 2) Local Audit Policy
# ---------------------------
Write-Info "Enabling recommended advanced audit subcategories..."
$AuditSubcategories = @(
    "Logon", "Logoff", "Account Lockout", "Special Logon",
    "File System", "Registry", "File Share", "Removable Storage",
    "Process Creation", "Process Termination", "Policy Change",
    "Account Management", "System Integrity", "Security State Change"
)
foreach ($sub in $AuditSubcategories) {
    try { auditpol /set /subcategory:"$sub" /success:enable /failure:enable | Out-Null }
    catch { Write-Warn "auditpol failed for '$sub': $($_.Exception.Message)" }
}
Write-Ok "Local audit subcategories enabled."

# ---------------------------
# 3) SMB Signing (client + server)
# ---------------------------
Write-Info "Configuring SMB signing locally..."
try {
    Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force | Out-Null
    Set-SmbClientConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force | Out-Null
    Write-Ok "SMB signing enforced (client + server)"
} catch { Write-Warn "Unable to set SMB signing: $($_.Exception.Message)" }

# ---------------------------
# 4) LDAP Client Signing (interactive)
# ---------------------------
Write-Info "Checking LDAP client signing requirement..."
try {
    $ldapKey = "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP"
    if (-not (Test-Path $ldapKey)) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services" -Name "LDAP" -Force | Out-Null }

    $current = (Get-ItemProperty -Path $ldapKey -Name LDAPClientIntegrity -ErrorAction SilentlyContinue).LDAPClientIntegrity
    switch ($current) {
        2 { Write-Ok "LDAP client signing already set to 'Require signing'" }
        1 { Write-Warn "LDAP client signing is 'Negotiate signing' (weaker)." }
        0 { Write-Warn "LDAP client signing is 'None' (insecure)." }
        Default { Write-Warn "LDAP client signing not configured." }
    }

    if ($current -ne 2) {
        $resp = Read-Host "Apply fix to set 'Require signing'? (Y/N)"
        if ($resp -match "^[Yy]$") {
            New-ItemProperty -Path $ldapKey -Name "LDAPClientIntegrity" -Value 2 -Type DWord -Force | Out-Null
            Write-Ok "LDAP client signing now set to 'Require signing'."
        } else {
            Write-Warn "LDAP client signing left unchanged."
        }
    }
} catch { Write-Warn "Unable to verify or set LDAP client signing: $($_.Exception.Message)" }

# ---------------------------
# 5) Misc Hardening
# ---------------------------
Write-Info "Applying misc security tweaks..."
try {
    # Require Ctrl+Alt+Del
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Value 0 -Type DWord -Force
    # Defender enabled
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0 -Type DWord -Force
    # Disable NetBIOS over TCP/IP on all adapters
    Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" | ForEach-Object {
        $_.SetTcpipNetbios(2) | Out-Null
    }
    Write-Ok "Ctrl+Alt+Del enforced, Defender active, NetBIOS disabled"
} catch { Write-Warn "Minor hardening tweaks failed: $($_.Exception.Message)" }

# ---------------------------
# 6) Verification Summary
# ---------------------------
Write-Host "`n=== VERIFICATION SUMMARY ===" -ForegroundColor Cyan
Write-Host "Password policy:" -ForegroundColor White
net accounts

Write-Host "`nLDAP signing status:" -ForegroundColor White
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" -Name LDAPClientIntegrity -ErrorAction SilentlyContinue | Format-Table

Write-Host "`nSMB signing status:" -ForegroundColor White
Get-SmbServerConfiguration | Select RequireSecuritySignature, EnableSecuritySignature
Get-SmbClientConfiguration | Select RequireSecuritySignature, EnableSecuritySignature

Write-Host "`nAudit policy (top):" -ForegroundColor White
auditpol /get /category:* | Select-String -Pattern "No Auditing" -NotMatch | Select-Object -First 15

Write-Host "`n✔ Local baseline applied successfully." -ForegroundColor Green
Write-Host "Reboot recommended for LDAP signing and NetBIOS settings to fully apply."
