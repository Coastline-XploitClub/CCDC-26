<#
.SYNOPSIS
  Domain-wide security baseline installer (password, lockout, audit, GPOs, SMB, LDAP signing)
.DESCRIPTION
  Run as Domain Admin on a Domain Controller. Uses ActiveDirectory & GroupPolicy modules.
  Sets domain password/lockout, creates GPOs for audit and security baseline, enables key audit subcategories,
  enables SMB signing (client+server) and LDAP signing via Default Domain Controllers Policy.
.NOTES
  Author: Cesar
#>

# ---------------------------
# Configuration - edit as needed
# ---------------------------
$DomainDnsName = (Get-ADDomain).DNSRoot                 # autodetect domain
$AuditGpoName   = "Audit Baseline Clients"
$SecGpoName     = "Security Baseline - Clients"
$DDCPolicyName  = "Default Domain Controllers Policy"   # built-in
# Password & Lockout settings
$MinPasswordLength = 14
$PasswordHistory   = 24
$MinPasswordAge    = 1        # days
$MaxPasswordAge    = 60       # days
$LockoutThreshold  = 5
$LockoutDuration   = 15       # minutes
$LockoutWindow     = 15       # minutes
# Kerberos (best-effort)
$KerbTicketHours   = 10
$KerbRenewDays     = 7
# ---------------------------

function Write-Ok($msg)  { Write-Host "✔ $msg" -ForegroundColor Green }
function Write-Info($msg){ Write-Host "-> $msg" -ForegroundColor Cyan }
function Write-Warn($msg){ Write-Host "⚠ $msg" -ForegroundColor Yellow }

# Ensure script runs elevated
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warn "Please run this script as Administrator (elevated). Exiting."
    return
}

Write-Host "=== DOMAIN SECURITY BASELINE APPLY ===" -ForegroundColor Cyan
Write-Info "Target domain: $DomainDnsName"

# Import modules if available
try { Import-Module ActiveDirectory -ErrorAction Stop; Write-Ok "ActiveDirectory module loaded" }
catch { Write-Warn "ActiveDirectory module not found. Install RSAT or run on a DC with AD tools. Continuing..." }

try { Import-Module GroupPolicy -ErrorAction Stop; Write-Ok "GroupPolicy module loaded" }
catch { Write-Warn "GroupPolicy module not found. GPO operations may fail. Install RSAT/GPMC. Continuing..." }

# ---------------------------
# 1) Domain password & lockout (via AD cmdlet)
# ---------------------------
Write-Info "Applying domain password & lockout policy..."
try {
    Set-ADDefaultDomainPasswordPolicy -Identity $DomainDnsName `
        -ComplexityEnabled $true `
        -ReversibleEncryptionEnabled $false `
        -MinPasswordLength $MinPasswordLength `
        -PasswordHistoryCount $PasswordHistory `
        -MinPasswordAge ([timespan]::FromDays($MinPasswordAge)) `
        -MaxPasswordAge ([timespan]::FromDays($MaxPasswordAge)) `
        -LockoutThreshold $LockoutThreshold `
        -LockoutDuration ([timespan]::FromMinutes($LockoutDuration)) `
        -LockoutObservationWindow ([timespan]::FromMinutes($LockoutWindow))
    Write-Ok "Domain password & lockout policy applied to $DomainDnsName"
} catch {
    Write-Warn "Failed to set AD default password policy via Set-ADDefaultDomainPasswordPolicy: $($_.Exception.Message)"
    Write-Warn "You can set these manually in GPMC -> Default Domain Policy -> Account Policies -> Password Policy"
}

# ---------------------------
# 2) Kerberos ticket lifetime (best-effort)
# ---------------------------
Write-Info "Configuring Kerberos lifetime (best-effort)..."
try {
    # Try Set-ADDomain; some AD module versions support time-span-like literals, some don't.
    Set-ADDomain -Identity $DomainDnsName `
      -MaxTicketAge ("$KerbTicketHours:00:00") `
      -MaxRenewAge ("$KerbRenewDays.00:00:00") `
      -MaxServiceAge ("$KerbTicketHours:00:00") `
      -MaxClockSkew "00:05:00" -ErrorAction Stop
    Write-Ok "Kerberos domain attributes updated via Set-ADDomain"
} catch {
    Write-Warn "Set-ADDomain with Kerberos parameters failed or unsupported in this AD module."
    Write-Info "Please update RSAT/AD module or set Kerberos lifetimes via GPMC -> Default Domain Policy -> Kerberos Policy."
}

# ---------------------------
# 3) Create / link GPOs
# ---------------------------
Write-Info "Creating and linking GPOs..."

function Ensure-GpoLink($gpoName, $targetDN, $enforce = $false) {
    $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
    if (-not $gpo) {
        $gpo = New-GPO -Name $gpoName -ErrorAction Stop
        Write-Ok "Created GPO: $gpoName"
    } else {
        Write-Info "Existing GPO found: $gpoName"
    }
    # Link (if not already linked)
    $links = Get-GPLink -Scope $targetDN -ErrorAction SilentlyContinue
    $already = $links | Where-Object { $_.DisplayName -eq $gpoName }
    if (-not $already) {
        New-GPLink -Name $gpoName -Target $targetDN -LinkEnabled Yes -ErrorAction Stop
        Write-Ok "Linked GPO '$gpoName' to $targetDN"
    } else {
        Write-Info "GPO '$gpoName' already linked to $targetDN"
    }
    if ($enforce) {
        Set-GPLink -Name $gpoName -Target $targetDN -Enforced Yes -ErrorAction SilentlyContinue
    }
    return $gpo
}

try {
    $domainDN = (Get-ADDomain).DistinguishedName
    $gpoAudit = Ensure-GpoLink -gpoName $AuditGpoName -targetDN $domainDN -enforce $true
    $gpoSec   = Ensure-GpoLink -gpoName $SecGpoName -targetDN $domainDN -enforce $false
} catch {
    Write-Warn "GPO creation/linking might have failed: $($_.Exception.Message)"
}

# ---------------------------
# 4) Advanced audit policy - enable subcategories (local and for clients)
# ---------------------------
Write-Info "Enabling recommended advanced audit subcategories (local execution; consider import to GPO for domain-wide)."

$AuditSubcategories = @(
    "Logon", "Logoff", "Account Lockout", "Special Logon", "Other Logon/Logoff Events",
    "File System", "Registry", "File Share", "Removable Storage",
    "Directory Service Access", "Directory Service Changes", "Directory Service Replication",
    "Process Creation", "Process Termination", "Policy Change", "Account Management",
    "Credential Validation", "Kerberos Service Ticket Operations", "Audit Other System Events",
    "Detailed Directory Service Replication", "Detailed File Share", "Sensitive Privilege Use",
    "Non Sensitive Privilege Use", "Other Privilege Use Events", "Security System Extension"
)

foreach ($sub in $AuditSubcategories) {
    try {
        Write-Info "Enabling audit: $sub"
        auditpol /set /subcategory:"$sub" /success:enable /failure:enable | Out-Null
    } catch {
        Write-Warn "auditpol failed for '$sub': $($_.Exception.Message)"
    }
}
Write-Ok "Audit subcategories enabled locally. To apply domain-wide, consider exporting an audit policy and import into GPO (auditpol /backup and auditpol /restore)."

# ---------------------------
# 5) SMB signing (client + server) via GPO (registry-backed)
# ---------------------------
Write-Info "Configuring SMB signing in Security GPO (registry policy entries)..."
try {
    # LanmanServer (server-side)
    Set-GPRegistryValue -Name $SecGpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "RequireSecuritySignature" -Type DWord -Value 1 -ErrorAction Stop
    Set-GPRegistryValue -Name $SecGpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "EnableSecuritySignature" -Type DWord -Value 1 -ErrorAction Stop
    # LanmanWorkstation (client-side)
    Set-GPRegistryValue -Name $SecGpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ValueName "RequireSecuritySignature" -Type DWord -Value 1 -ErrorAction Stop
    Set-GPRegistryValue -Name $SecGpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ValueName "EnableSecuritySignature" -Type DWord -Value 1 -ErrorAction Stop

    Write-Ok "SMB signing registry values set in GPO '$SecGpoName'."
} catch {
    Write-Warn "Failed to set SMB registry GPO values: $($_.Exception.Message)"
    Write-Info "You can still run Set-SmbServerConfiguration/Set-SmbClientConfiguration locally to enforce immediately."
}

# ---------------------------

# ---------------------------
# 6) Misc security registry items (Ctrl+Alt+Del, Defender)
# ---------------------------
Write-Info "Configuring small security registry items in Security GPO ($SecGpoName)..."
try {
    # Require Ctrl+Alt+Del at logon (DisableCAD = 0)
    Set-GPRegistryValue -Name $SecGpoName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "DisableCAD" -Type DWord -Value 0 -ErrorAction Stop

    # Ensure Defender real-time not disabled (DisableAntiSpyware = 0 => enabled)
    Set-GPRegistryValue -Name $SecGpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" -ValueName "DisableAntiSpyware" -Type DWord -Value 0 -ErrorAction Stop

    Write-Ok "Security registry values set in GPO '$SecGpoName'."
} catch {
    Write-Warn "Failed to set some security registry GPO values: $($_.Exception.Message)"
}

# ---------------------------
# 7) Force GP update & replication
# ---------------------------
Write-Info "Forcing group policy update and replication..."
try {
    gpupdate /force | Out-Null
    Write-Ok "gpupdate executed"
} catch {
    Write-Warn "gpupdate may have failed: $($_.Exception.Message)"
}

try {
    repadmin /syncall /AdeP | Out-Null
    Write-Ok "repadmin syncall executed"
} catch {
    Write-Warn "repadmin sync may have issues: $($_.Exception.Message)"
}

# ---------------------------
# 8) Local immediate enforcement options (optional)
# ---------------------------
Write-Info "Optionally apply immediate local SMB signing if you need it NOW on this DC (uncomment to run)."
# If you want to enforce immediately on this DC (not via GPO), uncomment:
# Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
# Set-SmbClientConfiguration -RequireSecuritySignature $true -Force

# ---------------------------
# 9) Verification output / tips
# ---------------------------
Write-Host "`n=== VERIFICATION / NEXT STEPS ===" -ForegroundColor Cyan

Write-Host "Domain password policy (net accounts):"
net accounts

Write-Host "`nAudit policy summary (auditpol):"
auditpol /get /category:* | Select-String -Pattern "No Auditing" -NotMatch | Select-Object -First 20
Write-Host "`n(If you see 'No Auditing' entries, rerun the auditpol loop for missing subcategories.)"

Write-Host "`nCheck SMB signing config on clients/servers (will apply via GPO):"
Write-Host "  Get-SmbServerConfiguration | Select RequireSecuritySignature"
Write-Host "  Get-SmbClientConfiguration | Select RequireSecuritySignature"

Write-Host "`nCheck GPO links:"
Get-GPO -All | ForEach-Object {
    [xml]$Report = Get-GPOReport -Guid $_.Id -ReportType Xml
    [PSCustomObject]@{
        DisplayName = $_.DisplayName
        LinksTo     = ($Report.GPO.LinksTo.SOMPath -join ', ')
    }
} | Where-Object { $_.LinksTo } | Format-Table -AutoSize


Write-Host "`nIf the Kerberos Set-ADDomain step failed earlier, set Kerberos lifetimes manually via:"
Write-Host "  GPMC -> Default Domain Policy -> Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Account Policies -> Kerberos Policy"

Write-Host "`nTo force clients to pick new GPOs now: run gpupdate /force on each machine or wait ~90 minutes + reboot."

Write-Ok "Baseline script finished. Review any warnings above and fix manually as required."

# End script
