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
#  ASK FOR DOMAIN NAME (Dynamic)
# ==========================================================
$DomainName = Read-Host "Enter your domain name (example: great.cretaceous)"
if (-not $DomainName) {
    Write-Host "[ERROR] Domain cannot be empty." -ForegroundColor Red
    exit
}

$GpoName     = "Domain Hardening"
$PolicyStore = "$DomainName\$GpoName"

Start-Sleep -Seconds 1

# ==========================================================
#  SECTION 0.1 – FIX DNS & ACTIVATE DOMAIN PROFILE (ASK FOR DC IP)
# ==========================================================
Write-Host "`n[0.1] DNS Fix – Configure correct DNS for Domain Profile…" -ForegroundColor Yellow

$DC_IP = Read-Host "Enter the Domain Controller IP address (example: 192.168.220.12)"

if (-not $DC_IP) {
    Write-Host "[ERROR] IP cannot be empty." -ForegroundColor Red
    exit
}

# Apply DNS servers
Write-Host "  → Setting DNS servers to: $DC_IP and 127.0.0.1" -ForegroundColor Cyan
Set-DnsClientServerAddress -InterfaceAlias "Ethernet 2" -ServerAddresses ($DC_IP, "127.0.0.1")

# Apply DNS suffix
Write-Host "  → Applying DNS suffix: $DomainName" -ForegroundColor Cyan
Set-DnsClient -InterfaceAlias "Ethernet 2" -ConnectionSpecificSuffix $DomainName

# DNS cleanup & registration
ipconfig /flushdns    | Out-Null
ipconfig /registerdns | Out-Null

# Restart NLA
Restart-Service nlasvc -Force

Start-Sleep 2

# Check profile
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
$NetworkPortsTCP = @(88,389,636)
$NetworkPortsUDP = @(88,389)

# Per-machine ports
$StrictTcpPorts = @(22,53,135,139,445,464,3268,3269)
$StrictUdpPorts = @(53,464)

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
