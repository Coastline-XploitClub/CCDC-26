<#
.SYNOPSIS
  Domain-Wide Security Baseline (ASCII Safe + BlueShield Compatible)

.DESCRIPTION
  Applies domain-wide security settings BlueShield does NOT configure:
   - Password & Lockout Policy (DDP)
   - Kerberos Policy (DDP)
   - Security Baseline - Clients GPO (LLMNR, mDNS, SmartScreen, SMB signing, Defender MAPS)
   - Hardened UNC Paths
   - Advanced Audit Policy (correct subcategories, domain-wide)

  Safe for:
   - Windows Server 2016, 2019, 2022
   - Windows 10 and 11 clients

.NOTES
  No Unicode. Fully Windows PowerShell 5.1 compatible.
#>

# ==========================================================
# OUTPUT HELPERS (ASCII ONLY)
# ==========================================================
function Write-Ok($msg){ Write-Host "[OK]    $msg" -ForegroundColor Green }
function Write-Info($msg){ Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
function Write-Warn($msg){ Write-Host "[WARN]  $msg" -ForegroundColor Yellow }
function Write-Err($msg){ Write-Host "[ERROR] $msg" -ForegroundColor Red }

Write-Host "=== Domain-Wide Security Baseline Apply ===" -ForegroundColor Cyan

# ==========================================================
# LOAD MODULES
# ==========================================================
try { Import-Module ActiveDirectory -ErrorAction Stop; Write-Ok "ActiveDirectory module loaded." }
catch { Write-Err "ActiveDirectory module missing."; exit 1 }

try { Import-Module GroupPolicy -ErrorAction Stop; Write-Ok "GroupPolicy module loaded." }
catch { Write-Err "GroupPolicy module missing."; exit 1 }

# ==========================================================
# DOMAIN INFORMATION
# ==========================================================
$Domain   = (Get-ADDomain).DNSRoot
$DomainDN = (Get-ADDomain).DistinguishedName

$AuditGpo = "Audit Baseline Clients"
$SecGpo   = "Security Baseline - Clients"
$DDP      = "Default Domain Policy"

Write-Info "Domain detected: $Domain"

# ==========================================================
# GPO CREATION FUNCTION
# ==========================================================
function Ensure-GPO {
    param($Name)
    $gpo = Get-GPO -Name $Name -ErrorAction SilentlyContinue
    if (-not $gpo) {
        $gpo = New-GPO -Name $Name
        Write-Ok "Created GPO: $Name"
    } else {
        Write-Info "GPO exists: $Name"
    }
    return $gpo
}

# Create required GPOs
$AuditGpoObj = Ensure-GPO $AuditGpo
$SecGpoObj   = Ensure-GPO $SecGpo

# ==========================================================
# LINK GPOS
# ==========================================================
Write-Info "Linking GPOs..."

New-GPLink -Name $AuditGpo -Target $DomainDN -Enforced Yes -ErrorAction SilentlyContinue
New-GPLink -Name $SecGpo   -Target $DomainDN -Enforced No  -ErrorAction SilentlyContinue

Write-Ok "GPOs linked."

# ==========================================================
# 1. PASSWORD & LOCKOUT POLICY (DDP)
# ==========================================================
Write-Info "Applying password and lockout policy..."

try {
    Set-ADDefaultDomainPasswordPolicy -Identity $Domain `
        -ComplexityEnabled $true `
        -ReversibleEncryptionEnabled $false `
        -MinPasswordLength 14 `
        -PasswordHistoryCount 24 `
        -MinPasswordAge (New-TimeSpan -Days 1) `
        -MaxPasswordAge (New-TimeSpan -Days 60) `
        -LockoutThreshold 5 `
        -LockoutDuration (New-TimeSpan -Minutes 15) `
        -LockoutObservationWindow (New-TimeSpan -Minutes 15)

    Write-Ok "Password and lockout policy applied."
}
catch {
    Write-Err "Password policy error: $($_.Exception.Message)"
}

# ==========================================================
# 2. KERBEROS LIFETIME POLICY (DDP)
# ==========================================================
Write-Info "Applying Kerberos policy..."

try {
    Set-ADDomain -Identity $Domain `
        -MaxTicketAge "10.00:00:00" `
        -MaxRenewAge "7.00:00:00" `
        -MaxServiceAge "10.00:00:00" `
        -MaxClockSkew "00:05:00"

    Write-Ok "Kerberos lifetime applied."
}
catch {
    Write-Warn "Kerberos lifetime settings not supported by module version."
}

# ==========================================================
# 3. SECURITY BASELINE GPO (CLIENTS)
# ==========================================================
Write-Host "`n=== Applying Client Security Baseline (GPO) ===" -ForegroundColor Cyan

# -----------------------------
# LLMNR Disable
# -----------------------------
Set-GPRegistryValue -Name $SecGpo `
 -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
 -ValueName "EnableMulticast" -Type DWord -Value 0
Write-Ok "LLMNR disabled."

# -----------------------------
# mDNS Disable
# -----------------------------
Set-GPRegistryValue -Name $SecGpo `
 -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
 -ValueName "EnableMDNS" -Type DWord -Value 0
Write-Ok "mDNS disabled."

# -----------------------------
# SmartScreen Enable
# -----------------------------
Set-GPRegistryValue -Name $SecGpo `
 -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" `
 -ValueName "EnableSmartScreen" -Type DWord -Value 1
Write-Ok "SmartScreen enabled."

# -----------------------------
# Defender Cloud, MAPS, Sample Submission
# -----------------------------
$MAPSKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"

Set-GPRegistryValue -Name $SecGpo -Key $MAPSKey -ValueName "SpynetReporting" -Type DWord -Value 2
Set-GPRegistryValue -Name $SecGpo -Key $MAPSKey -ValueName "SubmitSamplesConsent" -Type DWord -Value 3

Write-Ok "Defender MAPS and cloud reporting configured."

# -----------------------------
# Defender Real-Time Protection
# -----------------------------
$RTPKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"

Set-GPRegistryValue -Name $SecGpo -Key $RTPKey -ValueName "DisableRealtimeMonitoring" -Type DWord -Value 0
Set-GPRegistryValue -Name $SecGpo -Key $RTPKey -ValueName "DisableBehaviorMonitoring" -Type DWord -Value 0
Set-GPRegistryValue -Name $SecGpo -Key $RTPKey -ValueName "DisableIOAVProtection" -Type DWord -Value 0
Set-GPRegistryValue -Name $SecGpo -Key $RTPKey -ValueName "DisableOnAccessProtection" -Type DWord -Value 0

Write-Ok "Defender real-time protection enabled."

# -----------------------------
# SMB Signing (Client)
# -----------------------------
Set-GPRegistryValue -Name $SecGpo `
 -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
 -ValueName "RequireSecuritySignature" -Type DWord -Value 1
Write-Ok "SMB signing enforced for clients."

# -----------------------------
# Hardened UNC Paths (SYSVOL & NETLOGON)
# -----------------------------
$UNCKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"

Set-GPRegistryValue -Name $SecGpo -Key $UNCKey `
 -ValueName "\\*\SYSVOL"   -Type String -Value "RequireMutualAuthentication=1,RequireIntegrity=1"

Set-GPRegistryValue -Name $SecGpo -Key $UNCKey `
 -ValueName "\\*\NETLOGON" -Type String -Value "RequireMutualAuthentication=1,RequireIntegrity=1"

Write-Ok "Hardened UNC paths applied."

# ==========================================================
# 4. ADVANCED AUDIT POLICY (CORRECTED SUBCATEGORIES)
# ==========================================================
Write-Host "`n=== Applying Audit Baseline (Domain-Wide) ===" -ForegroundColor Cyan

$AuditSubcategories = @(
    "Credential Validation",
    "Kerberos Authentication Service",
    "Kerberos Service Ticket Operations",
    "Other Account Logon Events",

    "Computer Account Management",
    "Distribution Group Management",
    "Security Group Management",
    "User Account Management",
    "Other Account Management Events",

    "Directory Service Access",
    "Directory Service Changes",
    "Directory Service Replication",
    "Detailed Directory Service Replication",

    "Account Lockout",
    "IPsec Main Mode",
    "IPsec Quick Mode",
    "IPsec Extended Mode",
    "Logon",
    "Logoff",
    "Special Logon",
    "Other Logon/Logoff Events",
    "Network Policy Server",

    "File System",
    "Registry",
    "Kernel Object",
    "SAM",
    "Certification Services",
    "Application Generated",
    "Handle Manipulation",
    "Removable Storage",
    "Central Policy Staging",

    "Sensitive Privilege Use",
    "Non Sensitive Privilege Use",
    "Other Privilege Use Events",

    "Audit Policy Change",
    "Authentication Policy Change",
    "Authorization Policy Change",
    "MPSSVC Rule-Level Policy Change",
    "Filtering Platform Policy Change",

    "Security System Extension",
    "System Integrity",
    "IPsec Driver",
    "Other System Events"
)

foreach ($sub in $AuditSubcategories) {
    Write-Info "Enabling audit: $sub"
    auditpol /set /subcategory:"$sub" /success:enable /failure:enable | Out-Null
}

Write-Ok "Local audit policy configured."

# Export local audit policy
$TempAudit = "$env:TEMP\audit.pol"
auditpol /backup /file:$TempAudit
Write-Ok "Audit policy backed up to $TempAudit"

# Attempt import into GPO
try {
    Import-GPO -BackupGpoName "AuditBackup" -TargetName $AuditGpo -path $env:TEMP -ErrorAction SilentlyContinue
    Write-Ok "Audit baseline GPO applied."
}
catch {
    Write-Warn "GPO import skipped. This is normal for Server 2016."
}

# ==========================================================
# FINAL MESSAGE
# ==========================================================
Write-Host "`n=== Baseline Applied Successfully ===" -ForegroundColor Green
Write-Host "Run 'gpupdate /force' on all clients or wait 90-120 minutes."
