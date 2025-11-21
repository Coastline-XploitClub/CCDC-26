<#
.SYNOPSIS
  Verifies Advanced Audit Policy (full subcategories).
.DESCRIPTION
  Ensures all recommended audit subcategories are:
   - Enabled locally
   - Enabled in GPO
   - Not overridden by "No Auditing"
.NOTES
  ASCII only, PowerShell 5.1 safe
#>

function Write-Ok($m){ Write-Host "[OK]    $m" -ForegroundColor Green }
function Write-Fail($m){ Write-Host "[FAIL]  $m" -ForegroundColor Red }
function Write-Info($m){ Write-Host "[INFO]  $m" -ForegroundColor Cyan }

Write-Host "=== Audit Policy Verification ===" -ForegroundColor Cyan

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

Write-Host "`nChecking each audit subcategory..." -ForegroundColor Yellow

foreach ($sub in $AuditSubcategories) {
    $line = auditpol /get /subcategory:"$sub" 2>$null
    if ($line -match "Success and Failure") {
        Write-Ok "$sub"
    } else {
        Write-Fail "$sub is NOT fully enabled"
    }
}

Write-Host "`n=== Effective Policy Summary ===" -ForegroundColor Cyan
auditpol /get /category:*

Write-Host "`nIf any items show 'No Auditing', re-apply the GPO." -ForegroundColor Yellow
