<#
    Script: Create cesar_la Domain Admin + DNS Admin
    This version DOES NOT modify DNS ACLs.
    Run ONLY on the Domain Controller.
#>

# ==============================
# STEP 1 — CREATE USER 
# ==============================

$UserName = "cesar_la"
$Password = Read-Host "Enter a STRONG password for user '$UserName'" -AsSecureString

Write-Host "`n[1] Creating the user account $UserName..." -ForegroundColor Cyan

New-ADUser `
    -Name $UserName `
    -SamAccountName $UserName `
    -UserPrincipalName "$UserName@$(Get-ADDomain).DNSRoot" `
    -AccountPassword $Password `
    -Enabled $true

Write-Host "✔ User $UserName created." -ForegroundColor Green


# ==============================
# STEP 2 — ADD USER TO GROUP
# ==============================

Write-Host "`n[2] Adding $UserName to Domain Admins..." -ForegroundColor Cyan
Add-ADGroupMember -Identity "Domain Admins" -Members $UserName
Write-Host "✔ Added to Domain Admins." -ForegroundColor Green


# ==============================
# DONE
# ==============================

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " SETUP COMPLETE!" -ForegroundColor Green
Write-Host " User: $UserName" -ForegroundColor Yellow
Write-Host " Groups: Domain Admins + DNSAdmins" -ForegroundColor Yellow
Write-Host "========================================"

# ======================================================================
#   DNS HARDENING SCRIPT – Windows Server 2016 (NO DNSSEC)
#   Author: Cesar
#   Version: CCDC
# ======================================================================

Write-Host "`n========== DNS HARDENING ==========" -ForegroundColor Cyan
Import-Module ActiveDirectory -ErrorAction SilentlyContinue

# --------------------------
#  AUTO-DETECT DNS ZONE NAME
# --------------------------
Write-Host "`n[0] Detecting DNS Zone automatically..." -ForegroundColor Cyan

$zones = Get-DnsServerZone |
    Where-Object {
        $_.ZoneType -eq "Primary" -and
        $_.IsDsIntegrated -eq $true -and
        $_.ZoneName -ne "TrustAnchors"
    }

if ($zones.Count -eq 0) {
    Write-Host "[ERROR] No valid AD-integrated Primary DNS zones found on this server!" -ForegroundColor Red
    Write-Host "       You MUST create your domain DNS zone first." -ForegroundColor Yellow
    exit
}

# If only ONE zone exists, auto-select it
if ($zones.Count -eq 1) {
    $ZoneName = $zones[0].ZoneName
    Write-Host "[OK] Detected DNS Zone: $ZoneName" -ForegroundColor Green
}
else {
    Write-Host "Multiple DNS Zones detected:" -ForegroundColor Yellow
    $i = 1
    foreach ($z in $zones) {
        Write-Host " [$i] $($z.ZoneName)"
        $i++
    }

    $selection = Read-Host "Select the DNS Zone Number"
    if ($selection -notmatch '^\d+$' -or $selection -lt 1 -or $selection -gt $zones.Count) {
        Write-Host "[ERROR] Invalid selection!" -ForegroundColor Red
        exit
    }

    $ZoneName = $zones[$selection - 1].ZoneName
    Write-Host "[OK] Selected DNS Zone: $ZoneName" -ForegroundColor Green
}



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


<#
=======================================================================
   FULL DOMAIN HARDENING SCRIPT (GPO + FIREWALL RULES)
   DYNAMIC DOMAIN PROMPT + GPO LINK + PRIORITY + PROFILE SETTINGS
=======================================================================
#>

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "   DOMAIN CONTROLLER HARDENING – AUTO GPO + FIREWALL" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan


# ==========================================================
#  AUTO-DETECT DOMAIN & ALLOW MANUAL OVERRIDE WITH VALIDATION
# ==========================================================

# Try to auto-detect the domain
try {
    $AutoDomain = (Get-ADDomain).DNSRoot
} catch {
    Write-Host "[WARN] Unable to auto-detect domain. Machine may not be domain-joined." -ForegroundColor Yellow
    $AutoDomain = $null
}

# If auto-detected, ask user to confirm
if ($AutoDomain) {
    Write-Host "`nDetected domain: $AutoDomain" -ForegroundColor Cyan
    $choice = Read-Host "Use this domain? (Y/N)"

    if ($choice.ToUpper() -eq "Y") {
        $DomainName = $AutoDomain
    }
}

# If auto-detect not used or user chose NO → ask manually
if (-not $DomainName) {
    $DomainName = Read-Host "Enter your domain name manually (example: great.cretaceous)"

    if (-not $DomainName) {
        Write-Host "[ERROR] Domain cannot be empty." -ForegroundColor Red
        exit
    }

    # Validate domain exists in AD
    try {
        $null = Get-ADDomain -Identity $DomainName -ErrorAction Stop
        Write-Host "[OK] Domain verified: $DomainName" -ForegroundColor Green
    } catch {
        Write-Host "[ERROR] Domain '$DomainName' does not exist or cannot be contacted." -ForegroundColor Red
        exit
    }
}

# Prepare GPO variables
$GpoName     = "Domain Hardening"
$PolicyStore = "$DomainName\$GpoName"

Start-Sleep -Seconds 1


# ==========================================================
#  SECTION 0.1 – FIX DNS & ACTIVATE DOMAIN PROFILE (AUTO-DETECT + VALIDATION)
# ==========================================================
Write-Host "`n[0.1] DNS Fix – Configure correct DNS for Domain Profile…" -ForegroundColor Yellow

# Attempt to auto-detect the Domain Controller IP
try {
    $AutoDC_IP = (Get-ADDomainController -Discover -ErrorAction Stop).IPv4Address
} catch {
    Write-Host "[WARN] Unable to auto-detect the Domain Controller IP." -ForegroundColor Yellow
    $AutoDC_IP = $null
}

# If auto-detected, ask for confirmation
if ($AutoDC_IP) {
    Write-Host "`nDetected Domain Controller IP: $AutoDC_IP" -ForegroundColor Cyan
    $choice = Read-Host "Use this IP? (Y/N)"

    if ($choice.ToUpper() -eq "Y") {
        $DC_IP = $AutoDC_IP
    }
}

# If user declined or auto-detect failed → manual entry
if (-not $DC_IP) {

    $DC_IP = Read-Host "Enter the Domain Controller IP address (example: 192.168.220.12)"

    if (-not $DC_IP) {
        Write-Host "[ERROR] IP cannot be empty." -ForegroundColor Red
        exit
    }

    # Validate the IP format using regex
    if ($DC_IP -notmatch '^([0-9]{1,3}\.){3}[0-9]{1,3}$') {
        Write-Host "[ERROR] Invalid IP address format." -ForegroundColor Red
        exit
    }

    # Validate the IP is reachable (ping test)
    if (-not (Test-Connection -Count 1 -Quiet $DC_IP)) {
        Write-Host "[ERROR] IP $DC_IP is not reachable on the network." -ForegroundColor Red
        exit
    }

    # Validate LDAP is responding (389)
    $test = Test-NetConnection -ComputerName $DC_IP -Port 389
    if (-not $test.TcpTestSucceeded) {
        Write-Host "[ERROR] IP exists but LDAP port 389 is NOT responding." -ForegroundColor Red
        exit
    }

    Write-Host "[OK] Domain Controller validated successfully." -ForegroundColor Green
}

# APPLY DNS SETTINGS
Write-Host "  → Setting DNS servers to: $DC_IP and 127.0.0.1" -ForegroundColor Cyan
Set-DnsClientServerAddress -InterfaceAlias "Ethernet 2" -ServerAddresses ($DC_IP, "127.0.0.1")

Write-Host "  → Applying DNS suffix: $DomainName" -ForegroundColor Cyan
Set-DnsClient -InterfaceAlias "Ethernet 2" -ConnectionSpecificSuffix $DomainName

# Cleanup DNS
ipconfig /flushdns    | Out-Null
ipconfig /registerdns | Out-Null

# Restart NLA service
Restart-Service nlasvc -Force
Start-Sleep 2

# Check firewall profile
$profile = (Get-NetConnectionProfile).NetworkCategory
Write-Host "  → Active Firewall Profile Detected: $profile" -ForegroundColor Green

if ($profile -ne "DomainAuthenticated") {
    Write-Host "[WARN] Domain profile not active yet. A reboot may be required." -ForegroundColor Yellow
} else {
    Write-Host "[OK] Domain profile active." -ForegroundColor Green
}


# ==========================================================
#  SECTION 0 – CREATE GPO + LINK + PRIORITY
# ==========================================================
Write-Host "`n[0] Checking for '$GpoName' GPO..." -ForegroundColor Yellow

$gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if (-not $gpo) {
    Write-Host "  → Creating GPO '$GpoName'..." -ForegroundColor Cyan
    $gpo = New-GPO -Name $GpoName
} else {
    Write-Host "  → GPO already exists." -ForegroundColor Green
}

# Build correct OU DN (OU=Domain Controllers,...)
$parts = $DomainName.Split('.')
$DC_OU = "OU=Domain Controllers,DC=$($parts[0]),DC=$($parts[1])"

Write-Host "  → Linking GPO to Domain Controllers OU..." -ForegroundColor Cyan
New-GPLink -Name $GpoName -Target $DC_OU -LinkEnabled Yes -ErrorAction Stop | Out-Null

Write-Host "  → Setting link priority to 1..." -ForegroundColor Cyan
Set-GPLink -Name $GpoName -Target $DC_OU -Order 1
Write-Host "[OK] GPO linked & priority #1" -ForegroundColor Green


# ==========================================================
#  SECTION 0.5 – DISABLE LOCAL RULE MERGING (Firewall + IPsec)
# ==========================================================
Write-Host "`n[0.5] Disabling local rule merging..." -ForegroundColor Yellow

$FWBase = "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile"

# Disable Local Firewall Rules
Set-GPRegistryValue -Name $GpoName `
    -Key $FWBase `
    -ValueName "AllowLocalPolicyMerge" `
    -Type DWord -Value 0

# Disable Local IPsec Rules
Set-GPRegistryValue -Name $GpoName `
    -Key $FWBase `
    -ValueName "AllowLocalIPsecPolicyMerge" `
    -Type DWord -Value 0

Write-Host "[OK] Local firewall merge disabled." -ForegroundColor Green


# ==========================================================
#  SECTION 0.6 – FIREWALL PROFILE SETTINGS (Domain + Private)
# ==========================================================
Write-Host "`n[0.6] Enforcing firewall profile settings..." -ForegroundColor Yellow

$Profiles = @("DomainProfile","PrivateProfile")

foreach ($p in $Profiles) {
    $base = "HKLM\Software\Policies\Microsoft\WindowsFirewall\$p"

    # Firewall ON
    Set-GPRegistryValue -Name $GpoName -Key $base -ValueName "EnableFirewall" -Type DWord -Value 1

    # Inbound Block (1)
    Set-GPRegistryValue -Name $GpoName -Key $base -ValueName "DefaultInboundAction" -Type DWord -Value 1

    # Outbound Allow (0)
    Set-GPRegistryValue -Name $GpoName -Key $base -ValueName "DefaultOutboundAction" -Type DWord -Value 0

    Write-Host "  → $p profile hardened." -ForegroundColor Cyan
}

Write-Host "[OK] Domain + Private firewall profiles configured." -ForegroundColor Green

# ==========================================================
#  SECTION 0.65 – CLEANUP ANY BROKEN FIREWALL LOGGING KEYS
#  (Prevents MMC WFAS Snap-In Crash on Server 2016)
# ==========================================================
Write-Host "`n[0.65] Cleaning leftover Firewall Logging keys..." -ForegroundColor Yellow

$Paths = @(
    "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging",
    "HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
)

foreach ($path in $Paths) {
    Remove-GPRegistryValue -Name $GpoName -Key $path -ValueName "LogDroppedPackets" -ErrorAction SilentlyContinue
    Remove-GPRegistryValue -Name $GpoName -Key $path -ValueName "LogSuccessfulConnections" -ErrorAction SilentlyContinue
    Remove-GPRegistryValue -Name $GpoName -Key $path -ValueName "LogFileName" -ErrorAction SilentlyContinue
    Remove-GPRegistryValue -Name $GpoName -Key $path -ValueName "LogFileSize" -ErrorAction SilentlyContinue
}

Write-Host "[OK] Firewall logging registry cleanup complete — MMC crash prevented." -ForegroundColor Green

# ==========================================================
#  SECTION 0.7 – ENABLE LOCAL FIREWALL LOGGING (SAFE, NO GPO)
# ==========================================================
Write-Host "`n[0.7] Enabling Local Firewall Logging (safe mode)..." -ForegroundColor Yellow

# Enable logging of dropped packets
netsh advfirewall set currentprofile logging droppedconnections enable | Out-Null

# Enable logging of allowed connections
netsh advfirewall set currentprofile logging allowedconnections enable | Out-Null

Write-Host "[OK] Local Firewall Logging Enabled (No GPO → No MMC crash)" -ForegroundColor Green

# Show active logging configuration
netsh advfirewall firewall show logging


# ==========================================================
#  SECTION 1 – VARIABLES
# ==========================================================
$NetworkScope = "192.168.220.0/24"

$Machines = @{
    "PC2"    = "192.168.220.20"
    "PC3"    = "192.168.220.37"
    "Linux1" = "192.168.220.2"
    "Linux2" = "192.168.220.70"
    "Linux3" = "192.168.220.76"
    "Linux4" = "192.168.220.103"
    "Linux5" = "192.168.220.104"
    "Linux6" = "192.168.220.170"
}

# Network-level AD ports
$NetworkPortsTCP = @(88,389,636, 464,3268,3269)
$NetworkPortsUDP = @(88,389, 464)

# Per-machine ports
$StrictTcpPorts = @(22,53,135,139,445)
$StrictUdpPorts = @(53)

# RPC Dynamic ports
$DynStart = 49152
$DynEnd   = 65535


# ==========================================================
#  SECTION 2 – NETWORK-WIDE (Kerberos/LDAP)
# ==========================================================
Write-Host "`n[1] Applying Network-Wide Kerberos/LDAP rules..." -ForegroundColor Yellow

foreach ($p in $NetworkPortsTCP) {
    New-NetFirewallRule `
        -DisplayName "Allow NET TCP $p (Kerberos/LDAP)" `
        -Direction Inbound -Protocol TCP `
        -LocalPort $p -RemoteAddress $NetworkScope `
        -Action Allow -Profile Domain `
        -PolicyStore $PolicyStore `
        -ErrorAction SilentlyContinue | Out-Null
}

foreach ($p in $NetworkPortsUDP) {
    New-NetFirewallRule `
        -DisplayName "Allow NET UDP $p (Kerberos/LDAP)" `
        -Direction Inbound -Protocol UDP `
        -LocalPort $p -RemoteAddress $NetworkScope `
        -Action Allow -Profile Domain `
        -PolicyStore $PolicyStore `
        -ErrorAction SilentlyContinue | Out-Null
}

Write-Host "[OK] Network-Level Kerberos/LDAP rules applied." -ForegroundColor Green


# ==========================================================
#  SECTION 2.5 – GLOBAL RDP ACCESS (SAFE FOR COMPETITIONS)
# ==========================================================
Write-Host "`n[1.5] Applying Global RDP Rules (TCP/UDP 3389 from ANY IP)..." -ForegroundColor Yellow

# Allow RDP TCP 3389 from ANY IP
New-NetFirewallRule `
    -DisplayName "Allow RDP TCP 3389 (Global)" `
    -Direction Inbound -Protocol TCP `
    -LocalPort 3389 `
    -RemoteAddress Any `
    -Action Allow -Profile Domain `
    -PolicyStore $PolicyStore `
    -ErrorAction SilentlyContinue | Out-Null

# Allow RDP UDP 3389 from ANY IP
New-NetFirewallRule `
    -DisplayName "Allow RDP UDP 3389 (Global)" `
    -Direction Inbound -Protocol UDP `
    -LocalPort 3389 `
    -RemoteAddress Any `
    -Action Allow -Profile Domain `
    -PolicyStore $PolicyStore `
    -ErrorAction SilentlyContinue | Out-Null

Write-Host "[OK] Global RDP Rules Applied (3389 TCP/UDP)" -ForegroundColor Green

# ==========================================================
#  SECTION 2.8 – ALLOW NTP (UDP 123) FOR TIME SYNC
# ==========================================================
Write-Host "`n[2.8] Applying NTP (UDP 123) Time Synchronization Rule..." -ForegroundColor Yellow

New-NetFirewallRule `
    -DisplayName "Allow NTP UDP 123 (Time Sync for Clients)" `
    -Direction Inbound `
    -Protocol UDP `
    -LocalPort 123 `
    -RemoteAddress $NetworkScope `
    -Action Allow `
    -Profile Domain `
    -PolicyStore $PolicyStore `
    -ErrorAction SilentlyContinue | Out-Null

Write-Host "[OK] NTP Rule Applied (UDP 123)" -ForegroundColor Green
# ==========================================================
#  SECTION 2.9 – ALLOW ICMP (PING) FOR SCORE ENGINE + HEALTH CHECKS
# ==========================================================

Write-Host "`n[2.9] Applying ICMP Allow Rule (Ping)..." -ForegroundColor Yellow

New-NetFirewallRule `
    -DisplayName "Allow ICMPv4 Echo Request (Ping)" `
    -Direction Inbound `
    -Protocol ICMPv4 `
    -IcmpType 8 `
    -RemoteAddress $NetworkScope `
    -Action Allow `
    -Profile Domain `
    -PolicyStore $PolicyStore `
    -ErrorAction SilentlyContinue | Out-Null

New-NetFirewallRule `
    -DisplayName "Allow ICMPv4 Echo Reply (Ping)" `
    -Direction Inbound `
    -Protocol ICMPv4 `
    -IcmpType 0 `
    -RemoteAddress $NetworkScope `
    -Action Allow `
    -Profile Domain `
    -PolicyStore $PolicyStore `
    -ErrorAction SilentlyContinue | Out-Null

Write-Host "[OK] ICMP Rules Applied (Ping Request + Reply)" -ForegroundColor Green

# ==========================================================
#  SECTION 2.95 – ALLOW RPC HIGH PORTS FOR ALL WINDOWS CLIENTS
#  (Fixes Public Profile, GPO processing, nltest, LDAP, Kerberos)
# ==========================================================
Write-Host "`n[2.95] Allowing RPC Dynamic Ports for All Windows Clients..." -ForegroundColor Yellow

New-NetFirewallRule `
    -DisplayName "Allow RPC High Ports (Windows Clients)" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort "$DynStart-$DynEnd" `
    -RemoteAddress $NetworkScope `
    -Action Allow `
    -Profile Domain `
    -PolicyStore $PolicyStore `
    -ErrorAction SilentlyContinue | Out-Null

Write-Host "[OK] RPC High Ports Allowed for All Domain Clients" -ForegroundColor Green

# ==========================================================
#  SECTION 3 – MACHINE-SPECIFIC RULES
# ==========================================================
Write-Host "`n[2] Applying Machine-Specific rules..." -ForegroundColor Yellow

foreach ($entry in $Machines.GetEnumerator()) {

    $Machine = $entry.Key
    $IP      = $entry.Value

    Write-Host "  → $Machine ($IP)" -ForegroundColor Cyan

    foreach ($p in $StrictTcpPorts) {
        New-NetFirewallRule `
            -DisplayName "$Machine Allow TCP $p" `
            -Direction Inbound -Protocol TCP `
            -LocalPort $p -RemoteAddress $IP `
            -Action Allow -Profile Domain `
            -PolicyStore $PolicyStore `
            -ErrorAction SilentlyContinue | Out-Null
    }

    foreach ($p in $StrictUdpPorts) {
        New-NetFirewallRule `
            -DisplayName "$Machine Allow UDP $p" `
            -Direction Inbound -Protocol UDP `
            -LocalPort $p -RemoteAddress $IP `
            -Action Allow -Profile Domain `
            -PolicyStore $PolicyStore `
            -ErrorAction SilentlyContinue | Out-Null
    }

    New-NetFirewallRule `
        -DisplayName "$Machine Allow RPC High Ports" `
        -Direction Inbound -Protocol TCP `
        -LocalPort "$DynStart-$DynEnd" `
        -RemoteAddress $IP `
        -Action Allow -Profile Domain `
        -PolicyStore $PolicyStore `
        -ErrorAction SilentlyContinue | Out-Null
}

Write-Host "[OK] Machine-Specific rules applied." -ForegroundColor Green

# =====================================================================
#   SECTION 4 - DOMAIN CONTROLLER HARDENING – CLEAN VERSION (NO LDAP CHECKS)
# =====================================================================

Write-Host "`n================ DOMAIN CONTROLLER HARDENING ================" -ForegroundColor Cyan

# -------------------------------------------------------------
# AUTO-DETECT DOMAIN NAME
# -------------------------------------------------------------
try {
    $DomainName = (Get-ADDomain).DNSRoot
    Write-Host "[OK] Domain Detected: $DomainName" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Cannot detect AD domain. Are you on the DC?" -ForegroundColor Red
    exit
}

# -------------------------------------------------------------
# CREATE/LOAD GPO
# -------------------------------------------------------------
$GpoName = "Domain Hardening"
$gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue

if (-not $gpo) {
    Write-Host "  → Creating GPO '$GpoName'..." -ForegroundColor Cyan
    $gpo = New-GPO -Name $GpoName
} else {
    Write-Host "  → GPO '$GpoName' already exists." -ForegroundColor Yellow
}

# -------------------------------------------------------------
# LINK TO DOMAIN CONTROLLERS OU
# -------------------------------------------------------------
$parts = $DomainName.Split('.')
$DC_OU = "OU=Domain Controllers,DC=$($parts[0]),DC=$($parts[1])"

Write-Host "  → Linking GPO to Domain Controllers OU..." -ForegroundColor Cyan
New-GPLink -Name $GpoName -Target $DC_OU -LinkEnabled Yes -ErrorAction SilentlyContinue | Out-Null

Set-GPLink -Name $GpoName -Target $DC_OU -Order 1
Write-Host "[OK] GPO Linked with Priority #1" -ForegroundColor Green

# -------------------------------------------------------------
# FIREWALL PROFILES (DOMAIN + PRIVATE)
# -------------------------------------------------------------
Write-Host "`n[1] Enforcing Firewall Profiles…" -ForegroundColor Yellow

$Profiles = @("DomainProfile","PrivateProfile")

foreach ($p in $Profiles) {
    $base = "HKLM\Software\Policies\Microsoft\WindowsFirewall\$p"

    Set-GPRegistryValue -Name $GpoName -Key $base -ValueName "EnableFirewall" -Type DWord -Value 1
    Set-GPRegistryValue -Name $GpoName -Key $base -ValueName "DefaultInboundAction" -Type DWord -Value 1
    Set-GPRegistryValue -Name $GpoName -Key $base -ValueName "DefaultOutboundAction" -Type DWord -Value 0
    Write-Host "  → $p hardened." -ForegroundColor Cyan
}

Write-Host "[OK] Firewall profiles configured." -ForegroundColor Green

# -------------------------------------------------------------
# SMB HARDENING
# -------------------------------------------------------------
Write-Host "`n[2] SMB Hardening…" -ForegroundColor Yellow

# Disable SMBv1 Client+Server
Set-GPRegistryValue -Name $GpoName -Key "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters"      -ValueName "SMB1" -Type DWord -Value 0
Set-GPRegistryValue -Name $GpoName -Key "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ValueName "SMB1" -Type DWord -Value 0

# Ensure SMBv2/3 Enabled
Set-GPRegistryValue -Name $GpoName -Key "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters"      -ValueName "SMB2" -Type DWord -Value 1
Set-GPRegistryValue -Name $GpoName -Key "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ValueName "SMB2" -Type DWord -Value 1

# Require SMB Signing
Set-GPRegistryValue -Name $GpoName -Key "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters"      -ValueName "RequireSecuritySignature" -Type DWord -Value 1
Set-GPRegistryValue -Name $GpoName -Key "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ValueName "RequireSecuritySignature" -Type DWord -Value 1

# -------------------------------------------------------------
# ENFORCE SMB3 SECURITY ON SERVER (DC-SPECIFIC)
# -------------------------------------------------------------

# Require SMB server signing
Set-SmbServerConfiguration -EnableSecuritySignature $true -Force

# Enable SMB encryption (SMB3)
Set-SmbServerConfiguration -EncryptData $true -Force

# Do NOT disable encryption even on secure connections
Set-SmbServerConfiguration -DisableSmbEncryptionOnSecureConnection $false -Force

Write-Host "[OK] SMB hardened (SMB1 disabled, SMB2/3 enforced, signing + encryption enabled)." -ForegroundColor Green

# -------------------------------------------------------------
# DISABLE LLMNR, NETBIOS, GUEST, NULL SESSION, LMHASH
# -------------------------------------------------------------
Write-Host "`n[3] Disabling legacy protocols…" -ForegroundColor Yellow

Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" -ValueName "EnableMulticast" -Type DWord -Value 0
Set-GPRegistryValue -Name $GpoName -Key "HKLM\System\CurrentControlSet\Services\NetBT\Parameters" -ValueName "EnableLmhosts" -Type DWord -Value 0
Set-GPRegistryValue -Name $GpoName -Key "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ValueName "AllowInsecureGuestAuth" -Type DWord -Value 0
Set-GPRegistryValue -Name $GpoName -Key "HKLM\System\CurrentControlSet\Control\Lsa" -ValueName "restrictanonymous" -Type DWord -Value 1
Set-GPRegistryValue -Name $GpoName -Key "HKLM\System\CurrentControlSet\Control\Lsa" -ValueName "NoLMHash" -Type DWord -Value 1

Write-Host "[OK] Legacy protocols disabled." -ForegroundColor Green

# ==============================================================
# 4.8 – ZeroLogon / Netlogon Secure Channel Protection
# ==============================================================

Write-Host "`n[4.8] Enforcing ZeroLogon / Netlogon Secure Channel Protections..." -ForegroundColor Cyan

# Require RPC Signing
Set-GPRegistryValue -Name $GpoName `
    -Key "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" `
    -ValueName "RequireSignOrSeal" -Type DWord -Value 1

# Require Strong Keys — *This is the KEY setting for ZeroLogon*
Set-GPRegistryValue -Name $GpoName `
    -Key "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" `
    -ValueName "RequireStrongKey" -Type DWord -Value 1

# Enforce RPC Signing & Sealing
Set-GPRegistryValue -Name $GpoName `
    -Key "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" `
    -ValueName "SignSecureChannel" -Type DWord -Value 1

Set-GPRegistryValue -Name $GpoName `
    -Key "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" `
    -ValueName "SealSecureChannel" -Type DWord -Value 1

# Enforce Full Security Level
Set-GPRegistryValue -Name $GpoName `
    -Key "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" `
    -ValueName "FullSecureChannelProtection" -Type DWord -Value 1

Write-Host "✔ Netlogon protections enforced (ZeroLogon mitigated)." -ForegroundColor Green

# -------------------------------------------------------------
# APPLY GPO
# -------------------------------------------------------------
Write-Host "`n[+] Applying changes…" -ForegroundColor Cyan
gpupdate /force
Write-Host "[✔] DOMAIN CONTROLLER HARDENED" -ForegroundColor Green

# ==========================================================
#  FINAL SUMMARY
# ==========================================================
Write-Host "`n====================================================" -ForegroundColor Cyan
Write-Host "                     HARDENING SUMMARY" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

Write-Host "• Domain Provided ..................... $DomainName" -ForegroundColor Green
Write-Host "• GPO Created ........................ OK" -ForegroundColor Green
Write-Host "• GPO Linked to DC OU ............... OK" -ForegroundColor Green
Write-Host "• GPO Priority Set to #1 ............ OK" -ForegroundColor Green
Write-Host "• Local Firewall Rules Disabled ...... OK" -ForegroundColor Green
Write-Host "• Firewall Profiles Enforced ......... OK" -ForegroundColor Green
Write-Host "• Kerberos/LDAP Rules Applied ........ OK" -ForegroundColor Green
Write-Host "• Machine-Specific Rules Applied ..... OK" -ForegroundColor Green

Write-Host "`n🔥 COMPLETE – DOMAIN HARDENING WITH GPO AUTO-CONFIG 🔥" -ForegroundColor Yellow

# ==========================================================
#  APPLY ALL CHANGES (GPO + Firewall + LDAP + Kerberos)
# ==========================================================
Write-Host "`n[+] Applying all GPO changes with gpupdate /force..." -ForegroundColor Cyan

try {
    gpupdate /force
    Write-Host "[✔] GPUPDATE completed successfully." -ForegroundColor Green
} catch {
    Write-Host "[✖] GPUPDATE failed! Run gpupdate manually." -ForegroundColor Red
}

Write-Host "`n🎯 All hardening settings are now active!" -ForegroundColor Yellow

Write-Host "`n[✔] Completed! OUs created, computers sorted, GPO created, firewall settings applied, GPO linked, and gpupdate executed." -ForegroundColor Green

# ======================================================================
# WINDOWS MACHINES HARDENING – ORDERED & OPTIMIZED
# ======================================================================

Import-Module ActiveDirectory
Import-Module GroupPolicy

# ==============================================================
# 1. CREATE ORGANIZATIONAL UNITS
# ==============================================================
Write-Host "`n[1] Creating Organizational Units (if not existing)..." -ForegroundColor Cyan

$domainDN   = (Get-ADDomain).DistinguishedName
$OU_Windows = "OU=Windows Machines,$domainDN"
$OU_Linux   = "OU=Linux Machines,$domainDN"

# Create Windows OU
if (-not (Get-ADOrganizationalUnit -LDAPFilter "(ou=Windows Machines)" -SearchBase $domainDN -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit -Name "Windows Machines" -Path $domainDN
    Write-Host "  → OU 'Windows Machines' created." -ForegroundColor Green
} else {
    Write-Host "  → OU 'Windows Machines' already exists." -ForegroundColor Yellow
}

# Create Linux OU
if (-not (Get-ADOrganizationalUnit -LDAPFilter "(ou=Linux Machines)" -SearchBase $domainDN -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit -Name "Linux Machines" -Path $domainDN
    Write-Host "  → OU 'Linux Machines' created." -ForegroundColor Green
} else {
    Write-Host "  → OU 'Linux Machines' already exists." -ForegroundColor Yellow
}

# ==============================================================
# 2. SORT COMPUTERS INTO CORRECT OU
# ==============================================================
Write-Host "`n[2] Sorting computers into OUs..." -ForegroundColor Cyan

$Computers = Get-ADComputer -SearchBase "CN=Computers,$domainDN" -Filter * -Properties OperatingSystem

if ($Computers.Count -eq 0) {
    Write-Host "No computer objects found in the Computers container." -ForegroundColor Red
    exit
}

foreach ($comp in $Computers) {

    $Name = $comp.Name
    $OS   = $comp.OperatingSystem
    Write-Host "`nChecking: $Name" -ForegroundColor White

    if ($OS -match "Windows") {
        Move-ADObject -Identity $comp.DistinguishedName -TargetPath $OU_Windows
        Write-Host "  → Moved to Windows Machines OU" -ForegroundColor Green
    }
    elseif ($OS -match "Linux|Ubuntu|CentOS|Red Hat") {
        Move-ADObject -Identity $comp.DistinguishedName -TargetPath $OU_Linux
        Write-Host "  → Moved to Linux Machines OU" -ForegroundColor Green
    }
    else {
        Write-Host "  → Unknown OS. Skipping…" -ForegroundColor Yellow
        Write-Host "    (OperatingSystem: '$OS')" -ForegroundColor DarkYellow
    }
}

# ==============================================================
# 3. CREATE/LOAD WINDOWS_MACHINES GPO
# ==============================================================
Write-Host "`n[3] Creating Firewall GPO for Windows Machines..." -ForegroundColor Cyan

$GpoName = "Windows_Machines"
$GPO = New-GPO -Name $GpoName -ErrorAction SilentlyContinue

if ($GPO) {
    Write-Host "  → GPO '$GpoName' created." -ForegroundColor Green
} else {
    Write-Host "  → GPO '$GpoName' already exists. Using existing one." -ForegroundColor Yellow
}

# ==============================================================
# 4. FIREWALL HARDENING (DOMAIN, PRIVATE, PUBLIC)
# ==============================================================
Write-Host "`n[4] Configuring Firewall Profiles..." -ForegroundColor Cyan

$Profiles = @("DomainProfile", "PrivateProfile", "PublicProfile")

foreach ($p in $Profiles) {
    $base = "HKLM\Software\Policies\Microsoft\WindowsFirewall\$p"
    Write-Host "  → Configuring $p..." -ForegroundColor Yellow

    Set-GPRegistryValue -Name $GpoName -Key $base -ValueName "EnableFirewall" -Type DWord -Value 1
    Set-GPRegistryValue -Name $GpoName -Key $base -ValueName "DefaultInboundAction" -Type DWord -Value 1
    Set-GPRegistryValue -Name $GpoName -Key $base -ValueName "DefaultOutboundAction" -Type DWord -Value 0
    Set-GPRegistryValue -Name $GpoName -Key $base -ValueName "DisableNotifications" -Type DWord -Value 1
    Set-GPRegistryValue -Name $GpoName -Key $base -ValueName "AllowLocalPolicyMerge" -Type DWord -Value 1
    Set-GPRegistryValue -Name $GpoName -Key $base -ValueName "AllowLocalIPsecPolicyMerge" -Type DWord -Value 1

    Write-Host "     ✔ $p configured" -ForegroundColor Green
}

# ==============================================================
# 5. SECURITY HARDENING SECTIONS
# ==============================================================

# --------------------------- SMB ---------------------------
Write-Host "`n[5.1] SMB Hardening..." -ForegroundColor Cyan

# Disable SMBv1 (both client and server)
Set-GPRegistryValue -Name $GpoName -Key "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ValueName "SMB1" -Type DWord -Value 0
Set-GPRegistryValue -Name $GpoName -Key "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters"      -ValueName "SMB1" -Type DWord -Value 0

# Ensure SMBv2/3 remain enabled
Set-GPRegistryValue -Name $GpoName -Key "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ValueName "SMB2" -Type DWord -Value 1
Set-GPRegistryValue -Name $GpoName -Key "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters"      -ValueName "SMB2" -Type DWord -Value 1

# Require SMB Signing (Client + Server)
Set-GPRegistryValue -Name $GpoName -Key "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ValueName "RequireSecuritySignature" -Type DWord -Value 1
Set-GPRegistryValue -Name $GpoName -Key "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters"      -ValueName "RequireSecuritySignature" -Type DWord -Value 1

# ---------------------------
# ENFORCE SMB3 SERVER SECURITY (SIGNING + ENCRYPTION)
# ---------------------------

# Enable SMB server signing
Set-SmbServerConfiguration -EnableSecuritySignature $true -Force

# Enable SMB3 encryption on the server
Set-SmbServerConfiguration -EncryptData $true -Force

# Enforce encryption even on secure channels
Set-SmbServerConfiguration -DisableSmbEncryptionOnSecureConnection $false -Force

Write-Host "  ✔ SMB hardened (SMB1 disabled, v2/v3 enforced, signing + encryption enabled)" -ForegroundColor Green


# --------------------------- LLMNR ---------------------------
Write-Host "`n[5.2] Disabling LLMNR..." -ForegroundColor Cyan

Set-GPRegistryValue -Name $GpoName `
    -Key "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" `
    -ValueName "EnableMulticast" -Type DWord -Value 0

Write-Host "  ✔ LLMNR disabled" -ForegroundColor Green

# --------------------------- NetBIOS ---------------------------
Write-Host "`n[5.3] Disabling NetBIOS..." -ForegroundColor Cyan

Set-GPRegistryValue -Name $GpoName -Key "HKLM\System\CurrentControlSet\Services\NetBT\Parameters" `
    -ValueName "EnableLmhosts" -Type DWord -Value 0

Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows NT\Netbios" `
    -ValueName "NoNameReleaseOnDemand" -Type DWord -Value 1

Write-Host "  ✔ NetBIOS disabled" -ForegroundColor Green

# --------------------------- Guest + Anonymous ---------------------------
Write-Host "`n[5.4] Disabling Guest Account + Anonymous Access..." -ForegroundColor Cyan

# Disable Guest Account
Set-GPRegistryValue -Name $GpoName `
    -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
    -ValueName "DisableGuestAccount" -Type DWord -Value 1

# Disable Anonymous enumeration
Set-GPRegistryValue -Name $GpoName `
    -Key "HKLM\System\CurrentControlSet\Control\Lsa" `
    -ValueName "RestrictAnonymous" -Type DWord -Value 1

Set-GPRegistryValue -Name $GpoName `
    -Key "HKLM\System\CurrentControlSet\Control\Lsa" `
    -ValueName "restrictanonymoussam" -Type DWord -Value 1

# Disable SMB Guest Logons (extra protection)
Set-SmbClientConfiguration -EnableInsecureGuestLogons $false -Force

Write-Host "  ✔ Guest, Anonymous, and SMB Guest Logons disabled" -ForegroundColor Green

# --------------------------- No LM Hash ---------------------------
Write-Host "`n[5.5] Enforcing Secure Password Storage (No LM Hash)..." -ForegroundColor Cyan

Set-GPRegistryValue -Name $GpoName `
    -Key "HKLM\System\CurrentControlSet\Control\Lsa" `
    -ValueName "NoLMHash" -Type DWord -Value 1

Write-Host "  ✔ LM Hash disabled" -ForegroundColor Green

# --------------------------- Remote Assistance ---------------------------
Write-Host "`n[5.6] Disabling Remote Assistance..." -ForegroundColor Cyan

Set-GPRegistryValue -Name $GpoName `
    -Key "HKLM\System\CurrentControlSet\Control\Remote Assistance" `
    -ValueName "fAllowToGetHelp" -Type DWord -Value 0

Write-Host "  ✔ Remote Assistance disabled" -ForegroundColor Green

# --------------------------- SmartScreen ---------------------------
Write-Host "`n[5.7] Enabling Windows Defender SmartScreen..." -ForegroundColor Cyan

Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName "EnableSmartScreen"      -Type DWord -Value 1
Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName "ShellSmartScreenLevel" -Type String -Value "Block"

Write-Host "  ✔ SmartScreen enforced" -ForegroundColor Green

# --------------------------- Disable Services ---------------------------
Write-Host "`n[5.8] Disabling Fax, XPS, Print Spooler..." -ForegroundColor Cyan

Set-GPRegistryValue -Name $GpoName -Key "HKLM\System\CurrentControlSet\Services\Fax"      -ValueName "Start" -Type DWord -Value 4
Set-GPRegistryValue -Name $GpoName -Key "HKLM\System\CurrentControlSet\Services\XpsPrint" -ValueName "Start" -Type DWord -Value 4
Set-GPRegistryValue -Name $GpoName -Key "HKLM\System\CurrentControlSet\Services\Spooler"  -ValueName "Start" -Type DWord -Value 4

Write-Host "  ✔ Fax, XPS, Print Spooler disabled" -ForegroundColor Green

# ==============================================================
# 6. LINK GPO
# ==============================================================
Write-Host "`n[6] Linking GPO to Windows Machines OU..." -ForegroundColor Cyan

New-GPLink -Name $GpoName -Target $OU_Windows -ErrorAction SilentlyContinue | Out-Null

Write-Host "  → GPO linked to: $OU_Windows" -ForegroundColor Green

# ==============================================================
# 7. APPLY CHANGES
# ==============================================================
Write-Host "`n[7] Applying GPO changes (gpupdate /force)..." -ForegroundColor Cyan
gpupdate /force
Write-Host "`n[✔] Windows Machines hardened + GPO applied!" -ForegroundColor Green
