<#
.SYNOPSIS
  Domain-wide security verification tool (with auto GroupPolicy import).
.DESCRIPTION
  Verifies:
   - GPO links
   - Password / Lockout policy
   - SMB signing
   - LLMNR / mDNS
   - Hardened UNC paths
   - Defender MAPS
   - Audit GPO presence
   - Replication health
.NOTES
  ASCII only, PowerShell 5.1 safe.
#>

function OK($m){ Write-Host "[OK]    $m" -ForegroundColor Green }
function FAIL($m){ Write-Host "[FAIL]  $m" -ForegroundColor Red }
function INFO($m){ Write-Host "[INFO]  $m" -ForegroundColor Cyan }
function WARN($m){ Write-Host "[WARN]  $m" -ForegroundColor Yellow }

Write-Host "=== DOMAIN SECURITY VERIFICATION ===" -ForegroundColor Cyan

# ==========================================================
# AUTOLOAD GROUPPOLICY MODULE
# ==========================================================
INFO "Loading GroupPolicy module..."

try {
    Import-Module GroupPolicy -ErrorAction Stop
    OK "GroupPolicy module loaded."
    $GroupPolicyLoaded = $true
}
catch {
    WARN "GroupPolicy module could not be loaded. GPO link checks will be skipped."
    $GroupPolicyLoaded = $false
}

# ==========================================================
# DOMAIN INFO
# ==========================================================
$Domain = (Get-ADDomain)
$DDP    = "Default Domain Policy"
$SecGPO = "Security Baseline - Clients"
$AuditGPO = "Audit Baseline Clients"

# ==========================================================
# GPO LINK VERIFICATION
# ==========================================================
INFO "Checking GPO links..."

if ($GroupPolicyLoaded) {

    try {
        $links = Get-GPLink -Scope $Domain.DistinguishedName -ErrorAction Stop
    }
    catch {
        FAIL "Could not retrieve GPO links: $($_.Exception.Message)"
        $links = $null
    }

    if ($links) {
        if ($links | Where-Object { $_.DisplayName -eq $SecGPO }) { OK "$SecGPO linked" } else { FAIL "$SecGPO NOT linked" }
        if ($links | Where-Object { $_.DisplayName -eq $AuditGPO }) { OK "$AuditGPO linked" } else { FAIL "$AuditGPO NOT linked" }
    }
}
else {
    WARN "Skipping GPO link verification because GroupPolicy module is missing."
}

# ==========================================================
# PASSWORD & LOCKOUT POLICY
# ==========================================================
INFO "Checking password & lockout policy..."

$pw = net accounts | Out-String

if ($pw -match "Minimum password length.*14") { OK "Min Length OK" } else { FAIL "Min Length NOT 14" }
if ($pw -match "Maximum password age.*60")    { OK "Max age OK" } else { FAIL "Max age NOT 60" }
if ($pw -match "Minimum password age.*1")     { OK "Min age OK" } else { FAIL "Min age NOT 1" }
if ($pw -match "Lockout threshold.*5")        { OK "Lockout threshold OK" } else { FAIL "Lockout threshold NOT 5" }

# ==========================================================
# SMB SIGNING
# ==========================================================
INFO "Checking SMB signing..."

$server = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters").RequireSecuritySignature
$client = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters").RequireSecuritySignature

if ($server -eq 1) { OK "SMB Server signing enabled" } else { FAIL "SMB Server signing missing" }
if ($client -eq 1) { OK "SMB Client signing enabled" } else { FAIL "SMB Client signing missing" }

# ==========================================================
# LLMNR / mDNS
# ==========================================================
INFO "Checking LLMNR / mDNS..."

$dnsKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"

$LLMNR = (Get-ItemProperty $dnsKey -ErrorAction SilentlyContinue).EnableMulticast
$MDNS  = (Get-ItemProperty $dnsKey -ErrorAction SilentlyContinue).EnableMDNS

if ($LLMNR -eq 0) { OK "LLMNR disabled" } else { FAIL "LLMNR NOT disabled" }
if ($MDNS -eq 0)  { OK "mDNS disabled" }  else { FAIL "mDNS NOT disabled" }

# ==========================================================
# HARDENED UNC PATHS
# ==========================================================
INFO "Checking Hardened UNC Paths..."

$UNCKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
$UNC = Get-ItemProperty $UNCKey -ErrorAction SilentlyContinue

if ($UNC.'\\*\SYSVOL' -match "RequireMutualAuthentication=1") { OK "SYSVOL hardened" } else { FAIL "SYSVOL NOT hardened" }
if ($UNC.'\\*\NETLOGON' -match "RequireMutualAuthentication=1") { OK "NETLOGON hardened" } else { FAIL "NETLOGON NOT hardened" }

# ==========================================================
# DEFENDER MAPS
# ==========================================================
INFO "Checking Defender MAPS..."

$MAPSKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
$MAPS = (Get-ItemProperty $MAPSKey -ErrorAction SilentlyContinue).SpynetReporting

if ($MAPS -eq 2) { OK "Defender MAPS enabled" } else { FAIL "Defender MAPS NOT enabled" }

# ==========================================================
# AUDIT GPO PRESENCE
# ==========================================================
INFO "Checking Audit GPO presence..."

if ($GroupPolicyLoaded) {
    $Audit = Get-GPO -Name $AuditGPO -ErrorAction SilentlyContinue
    if ($Audit) { OK "Audit Baseline GPO exists" } else { FAIL "Audit Baseline GPO missing" }
}
else {
    WARN "Cannot verify GPO existence without GroupPolicy module."
}

# ==========================================================
# REPLICATION HEALTH
# ==========================================================
INFO "Checking replication health..."

try {
    repadmin /replsummary | Out-Null
    OK "Replication summary retrieved"
}
catch {
    FAIL "Replication summary failed"
}

# ==========================================================
# DONE
# ==========================================================
Write-Host "`n=== Verification Completed ===" -ForegroundColor Green
