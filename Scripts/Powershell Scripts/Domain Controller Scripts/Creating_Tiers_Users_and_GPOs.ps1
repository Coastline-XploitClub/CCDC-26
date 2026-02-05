# =====================================================================
# ACTIVE DIRECTORY USER & COMPUTER ORGANIZATION SCRIPT
# Safe for Windows Server 2016 / 2019 / 2022
# No user creation | Conditional OU creation | Idempotent
# =====================================================================

Import-Module ActiveDirectory -ErrorAction Stop

# =====================================================================
# DOMAIN DETECTION (LOCKED)
# =====================================================================
try {
    $DomainDN = (Get-ADDomain -ErrorAction Stop).DistinguishedName
    if ([string]::IsNullOrWhiteSpace($DomainDN)) { throw "DomainDN is null" }
    Write-Host "[OK] Detected domain: $DomainDN" -ForegroundColor Green
}
catch {
    Write-Error "FATAL: Unable to detect domain. $_"
    exit 1
}

# =====================================================================
# SHARED VARIABLES
# =====================================================================
$ExcludeUsers = @(
    "Administrator",
    "krbtgt",
    "Guest",
    "DefaultAccount"
)

$IgnoreGroups = @(
    "Domain Users",
    "Authenticated Users"
)

$PrivilegedGroupPattern = 'admin|tier|enterprise|schema|dns|operator|backup|server'

$ExplicitPrivGroups = @(
    "Domain Admins","Enterprise Admins","Administrators","Schema Admins",
    "DNSAdmins","Backup Operators","Server Operators","Account Operators",
    "Print Operators","Cert Publishers","RAS and IAS Servers",
    "Group Policy Creator Owners","Hyper-V Administrators"
)

# Pull users ONCE (DN is re-fetched before moves)
$AllUsers = Get-ADUser -Filter * -Properties SamAccountName,MemberOf

# =====================================================================
# TEST 1 — ADMIN ACCOUNT ORGANIZATION
# =====================================================================
Write-Host "`n=== TEST 1: ADMIN ACCOUNT ORGANIZATION ===" -ForegroundColor Cyan

$AdminOU = "OU=Admin_Accounts,$DomainDN"

if (-not (Get-ADOrganizationalUnit -Filter "Name -eq 'Admin_Accounts'" `
    -SearchBase $DomainDN -ErrorAction SilentlyContinue)) {

    New-ADOrganizationalUnit -Name "Admin_Accounts" -Path $DomainDN
    Write-Host "[+] Created OU: Admin_Accounts" -ForegroundColor Green
}

foreach ($user in $AllUsers) {

    if ($ExcludeUsers -contains $user.SamAccountName) { continue }
    if (-not $user.MemberOf) { continue }

    $FreshUser = Get-ADUser -Identity $user.SamAccountName `
        -Properties DistinguishedName,MemberOf -ErrorAction SilentlyContinue
    if (-not $FreshUser) { continue }

    if ($FreshUser.DistinguishedName -match 'OU=Tier_') { continue }

    $Groups = $FreshUser.MemberOf | ForEach-Object {
        (Get-ADGroup $_ -ErrorAction SilentlyContinue).Name
    }

    if ($Groups | Where-Object {
        $_ -match $PrivilegedGroupPattern -or $ExplicitPrivGroups -contains $_
    }) {
        if ($FreshUser.DistinguishedName -notlike "*OU=Admin_Accounts,*") {
            Move-ADObject -Identity $FreshUser.DistinguishedName `
                -TargetPath $AdminOU -ErrorAction SilentlyContinue
            Write-Host "[ADMIN] $($FreshUser.SamAccountName) → Admin_Accounts" -ForegroundColor Green
        }
    }
}

# =====================================================================
# TEST 2 — MULTIPLE GROUP USERS
# =====================================================================
Write-Host "`n=== MULTIPLE GROUP ACCOUNT ORGANIZATION ===" -ForegroundColor Cyan

$MultiOU = "OU=Multiple_Group_Accounts,$DomainDN"

if (-not (Get-ADOrganizationalUnit -Filter "Name -eq 'Multiple_Group_Accounts'" `
    -SearchBase $DomainDN -ErrorAction SilentlyContinue)) {

    New-ADOrganizationalUnit -Name "Multiple_Group_Accounts" -Path $DomainDN
    Write-Host "[+] Created OU: Multiple_Group_Accounts" -ForegroundColor Green
}

foreach ($user in $AllUsers) {

    if ($ExcludeUsers -contains $user.SamAccountName) { continue }

    $FreshUser = Get-ADUser -Identity $user.SamAccountName `
        -Properties DistinguishedName,MemberOf -ErrorAction SilentlyContinue
    if (-not $FreshUser) { continue }

    if ($FreshUser.DistinguishedName -match 'Admin_Accounts|Tier_') { continue }
    if (-not $FreshUser.MemberOf) { continue }

    $Groups = $FreshUser.MemberOf | ForEach-Object {
        (Get-ADGroup $_ -ErrorAction SilentlyContinue).Name
    }

    $Meaningful = $Groups | Where-Object { $IgnoreGroups -notcontains $_ }

    if ($Meaningful.Count -ge 2 -and
        $FreshUser.DistinguishedName -notlike "*OU=Multiple_Group_Accounts,*") {

        Move-ADObject -Identity $FreshUser.DistinguishedName `
            -TargetPath $MultiOU -ErrorAction SilentlyContinue
        Write-Host "[MULTI] $($FreshUser.SamAccountName) → Multiple_Group_Accounts" -ForegroundColor Magenta
    }
}

# =====================================================================
# TEST 3 — SINGLE GROUP USERS
# =====================================================================
Write-Host "`n=== SINGLE GROUP ACCOUNT ORGANIZATION ===" -ForegroundColor Cyan

foreach ($user in $AllUsers) {

    if ($ExcludeUsers -contains $user.SamAccountName) { continue }

    $FreshUser = Get-ADUser -Identity $user.SamAccountName `
        -Properties DistinguishedName,MemberOf -ErrorAction SilentlyContinue
    if (-not $FreshUser) { continue }

    if ($FreshUser.DistinguishedName -match 'Admin_Accounts|Multiple_Group_Accounts|Tier_') { continue }
    if (-not $FreshUser.MemberOf) { continue }

    $Groups = $FreshUser.MemberOf | ForEach-Object {
        (Get-ADGroup $_ -ErrorAction SilentlyContinue).Name
    }

    $Meaningful = $Groups | Where-Object { $IgnoreGroups -notcontains $_ }

    if ($Meaningful.Count -ne 1) { continue }
    if ($Meaningful[0] -match $PrivilegedGroupPattern) {
        Write-Host "[SKIP] Privileged group ($($Meaningful[0]))" -ForegroundColor Yellow
        continue
    }

    $OUName = ($Meaningful[0] -replace '[\/\[\]:;|=,+*?<>]', '').Trim()
    $TargetOU = "OU=$OUName,$DomainDN"

    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$OUName'" `
        -SearchBase $DomainDN -ErrorAction SilentlyContinue)) {

        New-ADOrganizationalUnit -Name $OUName -Path $DomainDN
        Write-Host "[+] Created OU: $OUName" -ForegroundColor Cyan
    }

    Move-ADObject -Identity $FreshUser.DistinguishedName `
        -TargetPath $TargetOU -ErrorAction SilentlyContinue
    Write-Host "[SINGLE] $($FreshUser.SamAccountName) → $OUName" -ForegroundColor Green
}

# =====================================================================
# TEST 4 — REGULAR USERS (PRIMARY GROUP ONLY)
# =====================================================================
Write-Host "`n=== REGULAR ACCOUNT ORGANIZATION ===" -ForegroundColor Cyan

$RegularOU = "OU=Regular_Accounts,$DomainDN"

if (-not (Get-ADOrganizationalUnit -Filter "Name -eq 'Regular_Accounts'" `
    -SearchBase $DomainDN -ErrorAction SilentlyContinue)) {

    New-ADOrganizationalUnit -Name "Regular_Accounts" -Path $DomainDN
    Write-Host "[+] Created OU: Regular_Accounts" -ForegroundColor Green
}

foreach ($user in Get-ADUser -Filter * `
    -Properties PrimaryGroupID,MemberOf,DistinguishedName,SamAccountName) {

    if ($ExcludeUsers -contains $user.SamAccountName) { continue }
    if ($user.DistinguishedName -match 'Tier_') { continue }

    if ($user.PrimaryGroupID -eq 513 -and -not $user.MemberOf) {
        if ($user.DistinguishedName -notlike "*OU=Regular_Accounts,*") {
            Move-ADObject -Identity $user.DistinguishedName `
                -TargetPath $RegularOU -ErrorAction SilentlyContinue
            Write-Host "[REGULAR] $($user.SamAccountName) → Regular_Accounts" -ForegroundColor White
        }
    }
}

Write-Host "`n[✓] USER ORGANIZATION COMPLETE" -ForegroundColor Cyan

# =====================================================================
# COMPUTER ORGANIZATION (WINDOWS / LINUX)
# =====================================================================
Write-Host "`n=== COMPUTER ORGANIZATION ===" -ForegroundColor Cyan

$Computers = Get-ADComputer -SearchBase "CN=Computers,$DomainDN" -Filter * -Properties OperatingSystem,DistinguishedName

$WindowsComputers = $Computers | Where-Object { $_.OperatingSystem -match "Windows" }
$LinuxComputers   = $Computers | Where-Object { $_.OperatingSystem -match "Linux|Ubuntu|CentOS|Red Hat|Debian|Rocky|Alma" }

if ($WindowsComputers) {
    $WindowsOU = "OU=Windows Machines,$DomainDN"
    if (-not (Get-ADOrganizationalUnit -LDAPFilter "(ou=Windows Machines)" -SearchBase $DomainDN -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name "Windows Machines" -Path $DomainDN
    }
    foreach ($c in $WindowsComputers) {
        Move-ADObject $c.DistinguishedName -TargetPath $WindowsOU -ErrorAction SilentlyContinue
        Write-Host "[WINDOWS] $($c.Name)" -ForegroundColor Green
    }
}

if ($LinuxComputers) {
    $LinuxOU = "OU=Linux Machines,$DomainDN"
    if (-not (Get-ADOrganizationalUnit -LDAPFilter "(ou=Linux Machines)" -SearchBase $DomainDN -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name "Linux Machines" -Path $DomainDN
    }
    foreach ($c in $LinuxComputers) {
        Move-ADObject $c.DistinguishedName -TargetPath $LinuxOU -ErrorAction SilentlyContinue
        Write-Host "[LINUX] $($c.Name)" -ForegroundColor Magenta
    }
}

Write-Host "`n[✓] USER AND COMPUTER ORGANIZATION COMPLETE" -ForegroundColor Cyan

<#
================================================================================
 CREATE PRIVILEGED ACCOUNT TIER OUs
 Parent OU: Privileged_Accounts
 Child OUs: Tier_0 / Tier_2
================================================================================
#>

Import-Module ActiveDirectory -ErrorAction Stop

$DomainDN = (Get-ADDomain).DistinguishedName

$ParentOUName = "Privileged_Accounts"
$TierOUs      = @("Tier_0","Tier_2")

$ParentOUDN = "OU=$ParentOUName,$DomainDN"

if (-not ([ADSI]::Exists("LDAP://$ParentOUDN"))) {
    New-ADOrganizationalUnit -Name $ParentOUName -Path $DomainDN -ProtectedFromAccidentalDeletion $true
    Write-Host "[+] Created OU: $ParentOUName" -ForegroundColor Green
}

foreach ($Tier in $TierOUs) {
    $TierDN = "OU=$Tier,$ParentOUDN"
    if (-not ([ADSI]::Exists("LDAP://$TierDN"))) {
        New-ADOrganizationalUnit -Name $Tier -Path $ParentOUDN -ProtectedFromAccidentalDeletion $true
        Write-Host "[+] Created OU: $Tier" -ForegroundColor Green
    }
}

Write-Host "=== PRIVILEGED OUs COMPLETE ===" -ForegroundColor Cyan

<#
================================================================================
 CREATE TIER SECURITY GROUPS
 Groups: Tier0_Admins / Tier2_Admins
================================================================================
#>

$GroupsOUName = "Groups"
$GroupsOUDN   = "OU=$GroupsOUName,OU=Privileged_Accounts,$DomainDN"

if (-not ([ADSI]::Exists("LDAP://$GroupsOUDN"))) {
    New-ADOrganizationalUnit -Name $GroupsOUName -Path "OU=Privileged_Accounts,$DomainDN" -ProtectedFromAccidentalDeletion $true
}

$TierGroups = @("Tier0_Admins","Tier2_Admins")

foreach ($Group in $TierGroups) {
    if (-not (Get-ADGroup -Filter "Name -eq '$Group'" -ErrorAction SilentlyContinue)) {
        New-ADGroup `
            -Name $Group `
            -SamAccountName $Group `
            -GroupScope Global `
            -GroupCategory Security `
            -Path $GroupsOUDN `
            -Description "Privileged access group: $Group"
        Write-Host "[+] Created group: $Group" -ForegroundColor Green
    }
}

Write-Host "=== TIER GROUPS COMPLETE ===" -ForegroundColor Cyan
<#
================================================================================
 INTERACTIVE TIER USER CREATION (FIXED)
 Tier 0  -> Domain Admins + Tier0_Admins
 Tier 2  -> Tier2_Admins ONLY
================================================================================
#>

Import-Module ActiveDirectory -ErrorAction Stop

$DomainDN = (Get-ADDomain).DistinguishedName
$Domain   = (Get-ADDomain).DNSRoot
$BaseOU   = "OU=Privileged_Accounts,$DomainDN"

$Tiers = @(
    @{
        Name        = "Tier 0"
        OU          = "OU=Tier_0,$BaseOU"
        Group       = "Tier0_Admins"
        IsDomainAdmin = $true
    },
    @{
        Name        = "Tier 2"
        OU          = "OU=Tier_2,$BaseOU"
        Group       = "Tier2_Admins"
        IsDomainAdmin = $false
    }
)

function Test-StrongPassword {
    param([string]$Password)
    $Password.Length -ge 14 -and
    $Password -match '[A-Z]' -and
    $Password -match '[a-z]' -and
    $Password -match '[0-9]' -and
    $Password -match '[^a-zA-Z0-9]'
}

function Read-ValidatedPassword {
    do {
        $Secure = Read-Host "Enter strong password (min 14 chars)" -AsSecureString
        $Plain  = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure))
    } until (Test-StrongPassword $Plain)

    return $Secure
}

foreach ($Tier in $Tiers) {

    do {
        $User = Read-Host "Enter username for $($Tier.Name)"
        $Pwd  = Read-ValidatedPassword

        $ExistingUser = Get-ADUser -Filter "SamAccountName -eq '$User'" -ErrorAction SilentlyContinue

        if (-not $ExistingUser) {
            New-ADUser `
                -Name $User `
                -SamAccountName $User `
                -UserPrincipalName "$User@$Domain" `
                -AccountPassword $Pwd `
                -Enabled $true `
                -Path $Tier.OU

            Write-Host "[+] Created user $User in $($Tier.Name)" -ForegroundColor Cyan
        }
        else {
            Write-Host "[!] User $User already exists – skipping creation" -ForegroundColor Yellow
        }

        # Tier-specific admin group
        Add-ADGroupMember -Identity $Tier.Group -Members $User -ErrorAction SilentlyContinue
        Write-Host "[+] $User added to $($Tier.Group)" -ForegroundColor Green

        # Domain Admins ONLY for Tier 0
        if ($Tier.IsDomainAdmin) {
            Add-ADGroupMember -Identity "Domain Admins" -Members $User -ErrorAction SilentlyContinue
            Write-Host "[+] $User added to Domain Admins (Tier 0)" -ForegroundColor Red
        }

        $Again = Read-Host "Add another $($Tier.Name) user? (Y/N)"
    }
    while ($Again -match '^[Yy]$')
}

Write-Host "=== USER CREATION COMPLETE ===" -ForegroundColor Cyan

<#
================================================================================
 MOVE BUILT-IN ADMINISTRATOR (RID 500) TO TIER_0
================================================================================
#>

Import-Module ActiveDirectory -ErrorAction Stop

# Ensure clean DN (fixes partition errors)
$DomainDN = (Get-ADDomain).DistinguishedName.Trim()

try {
    # Locate built-in Administrator by SID (RID 500)
    $BuiltinAdmin = Get-ADUser -Filter * -Properties ObjectSID |
        Where-Object { $_.ObjectSID.Value.EndsWith("-500") }

    if (-not $BuiltinAdmin) {
        Write-Host "[INFO] Built-in Administrator account not found" -ForegroundColor Yellow
        return
    }

    Write-Host "[!] Built-in Administrator detected: $($BuiltinAdmin.SamAccountName)" -ForegroundColor Yellow
    $Choice = Read-Host "Move built-in Administrator into Tier_0 and add to Tier0_Admins? (Y/N)"

    if ($Choice -notmatch '^[Yy]$') {
        Write-Host "[INFO] Administrator left unchanged" -ForegroundColor Cyan
        return
    }

    # Resolve Tier_0 OU safely
    $Tier0OU = Get-ADOrganizationalUnit `
        -LDAPFilter "(ou=Tier_0)" `
        -SearchBase "OU=Privileged_Accounts,$DomainDN"

    if (-not $Tier0OU) {
        throw "Tier_0 OU not found under Privileged_Accounts"
    }

    # Move Administrator to Tier_0
    Move-ADObject `
        -Identity $BuiltinAdmin.DistinguishedName `
        -TargetPath $Tier0OU.DistinguishedName

    # Add Administrator to Tier0_Admins
    Add-ADGroupMember `
        -Identity "Tier0_Admins" `
        -Members $BuiltinAdmin.SamAccountName `
        -ErrorAction SilentlyContinue

    Write-Host "[+] Built-in Administrator moved to Tier_0 and added to Tier0_Admins" -ForegroundColor Green
}
catch {
    Write-Host "[ERROR] Failed to move Administrator to Tier_0: $_" -ForegroundColor Red
}

Import-Module GroupPolicy -ErrorAction Stop
Import-Module ActiveDirectory -ErrorAction Stop

# ============================================================
# MODULES
# ============================================================
Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy    -ErrorAction Stop

# ============================================================
# DOMAIN / OU VARIABLES
# ============================================================
$DomainDN = (Get-ADDomain).DistinguishedName
$OU_DomainControllers = "OU=Domain Controllers,$DomainDN"
$OU_WindowsMachines  = "OU=Windows Machines,$DomainDN"

# ============================================================
# ENSURE WINDOWS MACHINES OU EXISTS
# ============================================================
if (-not (Get-ADOrganizationalUnit -LDAPFilter "(distinguishedName=$OU_WindowsMachines)" -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit -Name "Windows Machines" -Path $DomainDN
    Write-Host "[+] Created OU: Windows Machines" -ForegroundColor Green
}
else {
    Write-Host "[=] OU exists: Windows Machines" -ForegroundColor Yellow
}

# ============================================================
# GPO DEFINITIONS
# ============================================================
$DomainLevelGPOs = @(
    "GPO - Domain Password Policies",
    "GPO - Domain Account Policies",
    "GPO - Domain Audit Policies"
)

$DomainControllerGPOs = @(
    "GPO - Tier 0 Logon Restrictions",
    "GPO - DC Firewall Rules",      # CREATED ONLY – NOT LINKED
    "GPO - WinDefender & Updates",
    "GPO - DC Security Hardening",
    "GPO - DC Audit & Visibility",
    "GPO - DC Credential Protection"
)

$WindowsMachineGPOs = @(
    "GPO - Tier 2 Logon Restrictions",
    "GPO - Tier 2 Local Admin Delegation",
    "GPO - Windows Firewall Security"
)

# ============================================================
# FUNCTION: ENSURE GPO EXISTS (RETURNS TRUE IF EXISTS)
# ============================================================
function Ensure-GPO {
    param ([string]$Name)

    if (Get-GPO -Name $Name -ErrorAction SilentlyContinue) {
        Write-Host "[=] GPO exists, skipping: $Name" -ForegroundColor Yellow
        return $true
    }
    else {
        New-GPO -Name $Name | Out-Null
        Write-Host "[+] Created GPO: $Name" -ForegroundColor Green
        return $false
    }
}

# ============================================================
# FUNCTION: LINK GPO
# ============================================================
function Link-GPO {
    param (
        [string]$Name,
        [string]$Target,
        [int]$Order
    )

    $Inheritance = Get-GPInheritance -Target $Target
    $ExistingLink = $Inheritance.GpoLinks | Where-Object {
        $_.DisplayName -eq $Name
    }

    if (-not $ExistingLink) {
        New-GPLink -Name $Name -Target $Target -LinkEnabled Yes | Out-Null
        Write-Host "    [+] Link created: $Name" -ForegroundColor Green
    }

    Set-GPLink -Name $Name -Target $Target -Order $Order -LinkEnabled Yes
    Write-Host "    ↳ Linked ($Order): $Name" -ForegroundColor Cyan
}

# ============================================================
# FUNCTION: IMPORT GPO IF BACKUP EXISTS (NO GPMC REQUIRED)
# ============================================================
function Import-GPOIfBackupExists {
    param (
        [string]$BackupName,
        [string]$TargetName,
        [string]$BackupPath
    )

    if (-not (Test-Path $BackupPath)) {
        Write-Host "    [!] Backup path missing: $BackupPath" -ForegroundColor Yellow
        return
    }

    $BackupFolder = Get-ChildItem -Path $BackupPath -Directory -ErrorAction SilentlyContinue |
        Where-Object {
            (Test-Path (Join-Path $_.FullName "gpreport.xml")) -and
            (Select-String -Path (Join-Path $_.FullName "gpreport.xml") `
                           -SimpleMatch $BackupName `
                           -Quiet)
        } | Select-Object -First 1

    if ($BackupFolder) {
        Import-GPO -BackupGpoName $BackupName `
                   -TargetName $TargetName `
                   -Path $BackupPath `
                   -CreateIfNeeded

        Write-Host "    [+] Imported settings: $BackupName" -ForegroundColor Green
    }
    else {
        Write-Host "    [!] Backup not found, skipping import: $BackupName" -ForegroundColor Yellow
    }
}

# ============================================================
# DOMAIN LEVEL GPOS
# ============================================================
Write-Host "`n=== DOMAIN LEVEL GPOS ===" -ForegroundColor Cyan
$Order = 1
foreach ($GPO in $DomainLevelGPOs) {
    if (Ensure-GPO $GPO) { continue }
    Link-GPO $GPO $DomainDN $Order
    $Order++
}

# ============================================================
# DOMAIN CONTROLLERS GPOS
# ============================================================
Write-Host "`n=== DOMAIN CONTROLLERS GPOS ===" -ForegroundColor Cyan
$Order = 1
foreach ($GPO in $DomainControllerGPOs) {
    $Exists = Ensure-GPO $GPO

    if ($GPO -eq "GPO - DC Firewall Rules") {
        Write-Host "    ⚠️ Skipping link (intentional): $GPO" -ForegroundColor Yellow
        continue
    }

    if ($Exists) { continue }

    Link-GPO $GPO $OU_DomainControllers $Order
    $Order++
}

# ============================================================
# WINDOWS MACHINES GPOS
# ============================================================
Write-Host "`n=== WINDOWS MACHINES GPOS ===" -ForegroundColor Cyan
$Order = 1
foreach ($GPO in $WindowsMachineGPOs) {
    if (Ensure-GPO $GPO) { continue }
    Link-GPO $GPO $OU_WindowsMachines $Order
    $Order++
}

Write-Host "`n=== GPO CREATION & LINKING COMPLETE ===" -ForegroundColor Green
Write-Host "NOTE: 'GPO - DC Firewall Rules' was CREATED but NOT LINKED (intentional)." -ForegroundColor Yellow

# ============================================================
# GPO SETTINGS IMPORT
# ============================================================
$BackupPath = "C:\GPO_Backups"

Write-Host "`n=== IMPORTING GPO SETTINGS (IF BACKUPS EXIST) ===" -ForegroundColor Cyan

# DOMAIN
Import-GPOIfBackupExists "GPO - Domain Password Policies" "GPO - Domain Password Policies" $BackupPath
Import-GPOIfBackupExists "GPO - Domain Account Policies"  "GPO - Domain Account Policies"  $BackupPath
Import-GPOIfBackupExists "GPO - Domain Audit Policies"    "GPO - Domain Audit Policies"    $BackupPath

# DOMAIN CONTROLLERS
Import-GPOIfBackupExists "GPO - Tier 0 Logon Restrictions" "GPO - Tier 0 Logon Restrictions" $BackupPath
Import-GPOIfBackupExists "GPO - DC Firewall Rules"         "GPO - DC Firewall Rules"         $BackupPath
Import-GPOIfBackupExists "GPO - WinDefender & Updates"     "GPO - WinDefender & Updates"     $BackupPath
Import-GPOIfBackupExists "GPO - DC Security Hardening"     "GPO - DC Security Hardening"     $BackupPath
Import-GPOIfBackupExists "GPO - DC Audit & Visibility"     "GPO - DC Audit & Visibility"     $BackupPath
Import-GPOIfBackupExists "GPO - DC Credential Protection"  "GPO - DC Credential Protection"  $BackupPath

# WINDOWS MACHINES
Import-GPOIfBackupExists "GPO - Tier 2 Logon Restrictions"     "GPO - Tier 2 Logon Restrictions"     $BackupPath
Import-GPOIfBackupExists "GPO - Tier 2 Local Admin Delegation" "GPO - Tier 2 Local Admin Delegation" $BackupPath
Import-GPOIfBackupExists "GPO - Windows Firewall Security"     "GPO - Windows Firewall Security"     $BackupPath

Write-Host "`n=== GPO SETTINGS IMPORT COMPLETE ===" -ForegroundColor Green
