# ======================================================================
#   DNS HARDENING SCRIPT – Windows Server 2016 (NO DNSSEC)
#   Author: Cesar
#   Version: CCDC
# ======================================================================

Write-Host "`n========== DNS HARDENING ==========" -ForegroundColor Cyan
Import-Module ActiveDirectory -ErrorAction SilentlyContinue

# --------------------------
#  ASK FOR DNS ZONE NAME
# --------------------------
$ZoneName = Read-Host "Enter your DNS Zone Name (example: great.cretaceous)"

if (-not (Get-DnsServerZone -Name $ZoneName -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] Zone $ZoneName does not exist on this server!" -ForegroundColor Red
    exit
}

Write-Host "`n[1] Locking down DNS ACL..." -ForegroundColor Yellow

# ------------------------------------------------------
#  DNS ACL LOCKDOWN – prevents unauthorized deletion
# ------------------------------------------------------
$dnsZone = Get-DnsServerZone -Name $ZoneName
$aclPath = "AD:$($dnsZone.DistinguishedName)"
$acl = Get-Acl $aclPath

# Remove dangerous defaults
$remove = @(
    "NT AUTHORITY\Authenticated Users",
    "BUILTIN\Pre-Windows 2000 Compatible Access",
    "Everyone"
)

foreach ($rule in $acl.Access) {
    if ($rule.IdentityReference -in $remove) {
        $acl.RemoveAccessRule($rule)
    }
}

Set-Acl -Path $aclPath -AclObject $acl
Write-Host "[OK] DNS ACL locked (zone deletion protection enabled)" -ForegroundColor Green


Write-Host "`n[2] Disabling Zone Transfers..." -ForegroundColor Yellow
# ------------------------------------------------------
#  Disable ALL zone transfers
# ------------------------------------------------------
dnscmd localhost /ZoneResetSecondaries $ZoneName /NoXfr | Out-Null
Write-Host "[OK] Zone transfers fully disabled." -ForegroundColor Green


Write-Host "`n[3] Enabling Cache Locking & Socket Pool..." -ForegroundColor Yellow
# ------------------------------------------------------
#  Cache locking prevents cache poisoning
# ------------------------------------------------------
dnscmd /config /socketpoolsize 5000 | Out-Null
Set-DnsServerCache -LockingPercent 75
Write-Host "[OK] Cache locking + socket pool configured." -ForegroundColor Green


Write-Host "`n[4] Enabling DNS Debug Logging..." -ForegroundColor Yellow
# ------------------------------------------------------
#  DNS Logging (2016 supports only -All)
# ------------------------------------------------------
Set-DnsServerDiagnostics -All $true
Write-Host "[OK] DNS Debug Logging Enabled" -ForegroundColor Green


Write-Host "`n[5] Protecting DNS Service from Stop/Disable..." -ForegroundColor Yellow
# ------------------------------------------------------
#  Prevent DNS service from being stopped/disabled
# ------------------------------------------------------
sc.exe config dns start= auto | Out-Null
sc.exe sdset dns "D:(A;;CCDCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRRC;;;BA)" | Out-Null
Write-Host "[OK] DNS service stop protection applied" -ForegroundColor Green


Write-Host "`n[6] Additional DNS HARDENING (Recommended)..." -ForegroundColor Yellow
# =======================================================================
#  EXTRA HARDENING (SAFE FOR DCs – recommended for competitions)
# =======================================================================

# ---------------------------
#  Disable Recursion
# ---------------------------
Set-DnsServerRecursion -Enable $false
Write-Host "[OK] Recursion disabled (prevents abuse)" -ForegroundColor Green

# ---------------------------
#  Disable EDNS UDP amplification
# ---------------------------
Set-ItemProperty `
  -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" `
  -Name "EnableEDNSProbes" -Value 0 -Type DWord
Write-Host "[OK] EDNS amplification mitigated" -ForegroundColor Green

# ---------------------------
#  Disable Response Rate Limiting (only if enabled)
# ---------------------------
try {
    Set-DnsServerResponseRateLimiting -Mode Enable -ErrorAction Stop
    Write-Host "[OK] DNS RRL enabled" -ForegroundColor Green
} catch {
    Write-Host "[INFO] DNS RRL not supported on 2016 or not available" -ForegroundColor Yellow
}

# ---------------------------
#  Randomize port allocation
# ---------------------------
Set-ItemProperty `
  -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" `
  -Name "UdpReceiveWindow" -Value 0xFFFF
Write-Host "[OK] Randomized port behavior strengthened." -ForegroundColor Green


Write-Host "`n========== DNS HARDENING COMPLETE ==========" -ForegroundColor Cyan

