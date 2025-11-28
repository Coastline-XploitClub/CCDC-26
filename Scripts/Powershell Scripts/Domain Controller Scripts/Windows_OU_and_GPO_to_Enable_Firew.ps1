<# 
    Script: OU_and_GPO_AutoSetup.ps1
    Purpose:
        - Creates OUs: Windows Machines & Linux Machines
        - Reads all computer objects from "CN=Computers" default container
        - Detects whether each computer runs Windows or Linux
        - Moves them to the correct OU
        - Creates GPO "Windows_Machines"
        - Configures firewall for Domain, Private, Public profiles
        - Links GPO to Windows Machines OU
        - Forces GPO update
#>

Import-Module ActiveDirectory
Import-Module GroupPolicy

Write-Host "`n[1] Creating Organizational Units (if not existing)..." -ForegroundColor Cyan

# Distinguished Name of the domain (auto-detected)
$domainDN = (Get-ADDomain).DistinguishedName

# Target OU paths
$OU_Windows = "OU=Windows Machines,$domainDN"
$OU_Linux   = "OU=Linux Machines,$domainDN"

# Create OUs if they don’t already exist
if (-not (Get-ADOrganizationalUnit -LDAPFilter "(ou=Windows Machines)" -SearchBase $domainDN -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit -Name "Windows Machines" -Path $domainDN
    Write-Host "  → OU 'Windows Machines' created." -ForegroundColor Green
} else {
    Write-Host "  → OU 'Windows Machines' already exists." -ForegroundColor Yellow
}

if (-not (Get-ADOrganizationalUnit -LDAPFilter "(ou=Linux Machines)" -SearchBase $domainDN -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit -Name "Linux Machines" -Path $domainDN
    Write-Host "  → OU 'Linux Machines' created." -ForegroundColor Green
} else {
    Write-Host "  → OU 'Linux Machines' already exists." -ForegroundColor Yellow
}

Write-Host "`n[2] Scanning default Computers container..." -ForegroundColor Cyan

# Get computers from default container CN=Computers
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
        Write-Host "  → Detected OS: Windows" -ForegroundColor Green

        Move-ADObject -Identity $comp.DistinguishedName -TargetPath $OU_Windows
        Write-Host "  → Moved to OU: Windows Machines" -ForegroundColor Cyan
    }
    elseif ($OS -match "Linux" -or $OS -match "Ubuntu" -or $OS -match "CentOS" -or $OS -match "Red Hat") {
        Write-Host "  → Detected OS: Linux" -ForegroundColor Green

        Move-ADObject -Identity $comp.DistinguishedName -TargetPath $OU_Linux
        Write-Host "  → Moved to OU: Linux Machines" -ForegroundColor Cyan
    }
    else {
        Write-Host "  → Unknown OS, cannot classify. Skipping..." -ForegroundColor Yellow
        Write-Host "    (OperatingSystem attribute: '$OS')" -ForegroundColor DarkYellow
    }
}

Write-Host "`n[3] Creating Firewall GPO for Windows Machines..." -ForegroundColor Cyan

$GpoName = "Windows_Machines"

# Create or reuse GPO
$GPO = New-GPO -Name $GpoName -ErrorAction SilentlyContinue
if ($GPO) {
    Write-Host "  → GPO '$GpoName' created." -ForegroundColor Green
} else {
    Write-Host "  → GPO '$GpoName' already exists. Using existing one." -ForegroundColor Yellow
}

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

# =============================================================
# [4.x] SECURITY HARDENING SECTION
# =============================================================


# =============================================================
# SMB HARDENING — Disable SMBv1, Require SMBv2/v3
# =============================================================
Write-Host "`n[4.1] Hardening SMB Protocols..." -ForegroundColor Cyan

# Disable SMBv1 client
Set-GPRegistryValue -Name $GpoName `
    -Key "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
    -ValueName "SMB1" -Type DWord -Value 0

# Disable SMBv1 server
Set-GPRegistryValue -Name $GpoName `
    -Key "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" `
    -ValueName "SMB1" -Type DWord -Value 0

# Require SMB signing
Set-GPRegistryValue -Name $GpoName `
    -Key "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
    -ValueName "RequireSecuritySignature" -Type DWord -Value 1

# Enforce SMB Server Signing
Write-Host "`n[4.1b] Enforcing SMB Server Signing..." -ForegroundColor Cyan

Set-GPRegistryValue -Name $GpoName `
    -Key "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" `
    -ValueName "RequireSecuritySignature" -Type DWord -Value 1



# =============================================================
# Disable LLMNR
# =============================================================
Write-Host "`n[4.2] Disabling LLMNR..." -ForegroundColor Cyan

Set-GPRegistryValue -Name $GpoName `
    -Key "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" `
    -ValueName "EnableMulticast" -Type DWord -Value 0


# =============================================================
# Disable NetBIOS
# =============================================================
Write-Host "`n[4.3] Disabling NetBIOS..." -ForegroundColor Cyan

# Disable LMHOSTS lookup
Set-GPRegistryValue -Name $GpoName `
    -Key "HKLM\System\CurrentControlSet\Services\NetBT\Parameters" `
    -ValueName "EnableLmhosts" -Type DWord -Value 0

# Prevent NetBIOS name release
Set-GPRegistryValue -Name $GpoName `
    -Key "HKLM\Software\Policies\Microsoft\Windows NT\Netbios" `
    -ValueName "NoNameReleaseOnDemand" -Type DWord -Value 1


# =============================================================
# Disable Guest Account
# =============================================================
Write-Host "`n[4.4] Disabling Guest Account..." -ForegroundColor Cyan

Set-GPRegistryValue -Name $GpoName `
    -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
    -ValueName "DisableGuestAccount" -Type DWord -Value 1


# =============================================================
# Disable Anonymous Enumeration
# =============================================================
Write-Host "`n[4.5] Blocking Anonymous Enumeration..." -ForegroundColor Cyan

Set-GPRegistryValue -Name $GpoName `
    -Key "HKLM\System\CurrentControlSet\Control\Lsa" `
    -ValueName "RestrictAnonymous" -Type DWord -Value 1


# =============================================================
# Do NOT store LM Hash
# =============================================================
Write-Host "`n[4.6] Enforcing Secure Password Storage..." -ForegroundColor Cyan

Set-GPRegistryValue -Name $GpoName `
    -Key "HKLM\System\CurrentControlSet\Control\Lsa" `
    -ValueName "NoLMHash" -Type DWord -Value 1


# =============================================================
# Disable Remote Assistance
# =============================================================
Write-Host "`n[4.7] Disabling Remote Assistance..." -ForegroundColor Cyan

Set-GPRegistryValue -Name $GpoName `
    -Key "HKLM\System\CurrentControlSet\Control\Remote Assistance" `
    -ValueName "fAllowToGetHelp" -Type DWord -Value 0


# =============================================================
# Enable Windows Defender SmartScreen
# =============================================================
Write-Host "`n[4.8] Enabling Windows Defender SmartScreen..." -ForegroundColor Cyan

# Enable SmartScreen
Set-GPRegistryValue -Name $GpoName `
    -Key "HKLM\Software\Policies\Microsoft\Windows\System" `
    -ValueName "EnableSmartScreen" -Type DWord -Value 1

# Set SmartScreen to Block mode
Set-GPRegistryValue -Name $GpoName `
    -Key "HKLM\Software\Policies\Microsoft\Windows\System" `
    -ValueName "ShellSmartScreenLevel" -Type String -Value "Block"


# =============================================================
# Disable Fax Service
# =============================================================
Write-Host "`n[4.9] Disabling Fax Service..." -ForegroundColor Cyan

Set-GPRegistryValue -Name $GpoName `
    -Key "HKLM\System\CurrentControlSet\Services\Fax" `
    -ValueName "Start" -Type DWord -Value 4


# =============================================================
# Disable XPS Services
# =============================================================
Write-Host "`n[4.10] Disabling XPS Services..." -ForegroundColor Cyan

Set-GPRegistryValue -Name $GpoName `
    -Key "HKLM\System\CurrentControlSet\Services\XpsPrint" `
    -ValueName "Start" -Type DWord -Value 4


# =============================================================
# Disable Print Spooler (Optional)
# =============================================================
Write-Host "`n[4.11] Disabling Print Spooler (Optional)..." -ForegroundColor Yellow

# COMMENT OUT this line if you *need printers*
Set-GPRegistryValue -Name $GpoName `
    -Key "HKLM\System\CurrentControlSet\Services\Spooler" `
    -ValueName "Start" -Type DWord -Value 4

Write-Host "`n[5] Linking GPO to Windows Machines OU..." -ForegroundColor Cyan

New-GPLink -Name $GpoName -Target $OU_Windows

Write-Host "  → GPO linked to: $OU_Windows" -ForegroundColor Green

gpupdate /force

Write-Host "`n[✔] Completed! OUs created, computers sorted, GPO created, firewall settings applied, GPO linked, and gpupdate executed." -ForegroundColor Green

