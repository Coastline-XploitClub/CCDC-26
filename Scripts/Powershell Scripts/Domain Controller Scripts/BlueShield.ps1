# ----------------------------------------------------------
# Helper Output Functions (unified, consistent, no conflicts)
# ----------------------------------------------------------

function Write-Ok {
    param([Parameter(Mandatory=$true)][string]$Message)
    Write-Host "[OK]    $Message" -ForegroundColor Green
}

function Write-Info {
    param([Parameter(Mandatory=$true)][string]$Message)
    Write-Host "[INFO]  $Message" -ForegroundColor Cyan
}

function Write-Warn {
    param([Parameter(Mandatory=$true)][string]$Message)
    Write-Host "[WARN]  $Message" -ForegroundColor Yellow
}

function Write-Err {
    param([Parameter(Mandatory=$true)][string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# ----------------------------------------------------------
# Active Directory Module Load
# ----------------------------------------------------------

Write-Info "Loading ActiveDirectory module..."
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Ok "ActiveDirectory module loaded successfully."
}
catch {
    Write-Err "ActiveDirectory module could NOT be loaded. 
This script must run on a Domain Controller or RSAT-enabled machine."
    exit 1
}

# ----------------------------------------------------------
# Script Header
# ----------------------------------------------------------
Write-Host '=== BlueShield: Domain Controller Security Hardening & Audit ===' -ForegroundColor Cyan
Write-Host ("Running checks on {0} ({1}) ..." -f $env:COMPUTERNAME, $env:USERDOMAIN) -ForegroundColor Yellow
Write-Host ""

# ----------------------------------------------------------
# Result Collector (improved, safe, consistent)
# ----------------------------------------------------------

# Ensure global array exists
if (-not $global:Results) {
    $global:Results = @()
}

function Add-Result {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][ValidateSet("Secure","Warning","Critical","Skipped","Error")][string]$Status,
        [Parameter(Mandatory=$true)][string]$Info,
        [string]$Value = ""
    )

    try {
        # Construct object
        $result = [PSCustomObject]@{
            Check     = $Name
            Status    = $Status
            Info      = $Info
            Value     = $Value
            Timestamp = (Get-Date).ToString("s")
        }

        # Append to global array
        $global:Results += $result

        # Color per status
        $color = switch ($Status) {
            "Secure"   { "Green" }
            "Warning"  { "Yellow" }
            "Critical" { "Red" }
            "Error"    { "Red" }
            "Skipped"  { "DarkYellow" }
            default    { "Gray" }
        }

        # Format message
        if ($Value) {
            Write-Host ("[{0}] {1} - {2} [{3}]" -f $Status,$Name,$Info,$Value) -ForegroundColor $color
        } else {
            Write-Host ("[{0}] {1} - {2}" -f $Status,$Name,$Info) -ForegroundColor $color
        }
    }
    catch {
        Write-Err "Failed to record result for ${Name}: $($_.Exception.Message)"
    }
}
# ----------------------------------------------------------
# INTERACTIVE SECURITY VALIDATION (SMART RECHECK)
# ----------------------------------------------------------
Write-Host "`n[+] Running interactive security validation (NTLM, LLMNR, LSASS, Kerberos, SMB Signing, Anonymous, Guest)..." -ForegroundColor Cyan

function Check-Once {
    param(
        [string]$CheckName,
        [bool]$Condition,
        [ScriptBlock]$FixAction,
        [string]$SecureMsg,
        [string]$WarningMsg
    )

    if ($Condition) {
        Add-Result $CheckName "Secure" $SecureMsg
        return
    }

    Add-Result $CheckName "Warning" $WarningMsg
    $fix = Read-Host "Apply $CheckName fix now? (Y/N)"
    if ($fix -match "^[Yy]$") {
        & $FixAction
        Add-Result $CheckName "Secure" "$CheckName hardened"
    }
}

# =======================
# NTLM Hardening
# =======================
try {
    $lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $lvl = (Get-ItemProperty -Path $lsa -Name LmCompatibilityLevel -ErrorAction SilentlyContinue).LmCompatibilityLevel
    $Condition = ($lvl -ge 5)
    $Fix = { Set-ItemProperty -Path $lsa -Name LmCompatibilityLevel -Value 5 -Type DWord -Force }
    Check-Once "NTLM" $Condition $Fix "NTLMv2 only (Level 5)" "Weak NTLM level detected"
}
catch { Add-Result "NTLM" "Warning" "Cannot verify" }

# =======================
# LLMNR Hardening
# =======================
try {
    $dnsKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    if (-not (Test-Path $dnsKey)) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT" -Name "DNSClient" -Force | Out-Null
    }
    $multicast = (Get-ItemProperty -Path $dnsKey -Name EnableMulticast -ErrorAction SilentlyContinue).EnableMulticast
    $Condition = ($multicast -eq 0)
    $Fix = { New-ItemProperty -Path $dnsKey -Name EnableMulticast -Value 0 -Type DWord -Force }
    Check-Once "LLMNR" $Condition $Fix "Disabled" "Enabled"
}
catch { Add-Result "LLMNR" "Warning" "Cannot verify" }

# =======================
# LSASS Protection (RunAsPPL)
# =======================
try {
    $lsaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $ppl = (Get-ItemProperty -Path $lsaKey -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
    $Condition = ($ppl -eq 1)
    $Fix = { New-ItemProperty -Path $lsaKey -Name RunAsPPL -Value 1 -Type DWord -Force }
    Check-Once "LSASS" $Condition $Fix "Protected (PPL mode)" "Not protected"
}
catch { Add-Result "LSASS" "Warning" "Cannot verify" }

# =======================
# Kerberos Encryption Type Hardening
# =======================
try {
    $kerbPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
    if (-not (Test-Path $kerbPath)) {
        New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "Kerberos" -Force | Out-Null
        New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos" -Name "Parameters" -Force | Out-Null
    }
    $enc = (Get-ItemProperty -Path $kerbPath -Name SupportOldEncryptionTypes -ErrorAction SilentlyContinue).SupportOldEncryptionTypes
    $Condition = ($enc -eq 0)
    $Fix = { New-ItemProperty -Path $kerbPath -Name SupportOldEncryptionTypes -Value 0 -Type DWord -Force }
    Check-Once "Kerberos Encryption" $Condition $Fix "DES/RC4 disabled" "Legacy crypto enabled"
}
catch { Add-Result "Kerberos Encryption" "Warning" "Cannot verify" }

# =======================
# SMB Signing
# =======================
try {
    $srv = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -ErrorAction SilentlyContinue).RequireSecuritySignature
    $cli = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -ErrorAction SilentlyContinue).RequireSecuritySignature

    $Condition = ($srv -eq 1 -and $cli -eq 1)

    $Fix = {
        Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name RequireSecuritySignature -Value 1 -Type DWord
        Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name RequireSecuritySignature -Value 1 -Type DWord
    }

    Check-Once "SMB Signing" $Condition $Fix "Enforced" "Not enforced"
}
catch { Add-Result "SMB Signing" "Warning" "Cannot verify" }

# =======================
# Anonymous Access
# =======================
try {
    $lsaCtrl = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $anon = (Get-ItemProperty -Path $lsaCtrl -Name RestrictAnonymous -ErrorAction SilentlyContinue).RestrictAnonymous
    $Condition = ($anon -eq 1)
    $Fix = { Set-ItemProperty -Path $lsaCtrl -Name RestrictAnonymous -Value 1 -Type DWord -Force }
    Check-Once "Anonymous Access" $Condition $Fix "Restricted" "Unrestricted"
}
catch { Add-Result "Anonymous Access" "Warning" "Cannot verify" }

# =======================
# Guest Account
# =======================
try {
    $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    $Condition = ($guest -and -not $guest.Enabled)
    $Fix = { net user guest /active:no | Out-Null }
    Check-Once "Guest Account" $Condition $Fix "Disabled" "Enabled"
}
catch { Add-Result "Guest Account" "Warning" "Cannot verify" }

# =======================
# NULL SESSION ENUMERATION
# =======================
try {
    Write-Host "`n[+] Checking NULL Session Enumeration Hardening..." -ForegroundColor Cyan

    $lsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $srvPath = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"

    $RestrictAnonymousSAM  = (Get-ItemProperty -Path $lsaPath -Name RestrictAnonymousSAM -ErrorAction SilentlyContinue).RestrictAnonymousSAM
    $RestrictAnonymous     = (Get-ItemProperty -Path $lsaPath -Name RestrictAnonymous -ErrorAction SilentlyContinue).RestrictAnonymous
    $RestrictNullSessAccess = (Get-ItemProperty -Path $srvPath -Name RestrictNullSessAccess -ErrorAction SilentlyContinue).RestrictNullSessAccess

    $Condition = ($RestrictAnonymousSAM -eq 1 -and $RestrictAnonymous -eq 1 -and $RestrictNullSessAccess -eq 1)

    $Fix = {
        Set-ItemProperty -Path $lsaPath -Name "RestrictAnonymousSAM" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $lsaPath -Name "RestrictAnonymous" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $srvPath -Name "RestrictNullSessAccess" -Value 1 -Type DWord -Force
        Restart-Service -Name Server -Force
    }

    Check-Once "NULL Session Enumeration" $Condition $Fix "Fully restricted" "Null session access allowed"
}
catch {
    Add-Result "NULL Session Enumeration" "Warning" "Cannot verify"
}

# ----------------------------------------------------------
# NETWORK & SERVICE HARDENING (SAFE / INTERACTIVE)
# ----------------------------------------------------------
Write-Host "`n[+] Checking network/service hardening..." -ForegroundColor Cyan

# -----------------------------
# NetBIOS Disable (per adapter)
# -----------------------------
try {
    $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE"

    $allDisabled = $true
    foreach ($a in $adapters) {
        if ($a.TcpipNetbiosOptions -ne 2) { $allDisabled = $false }
    }

    if ($allDisabled) {
        Add-Result "NetBIOS" "Secure" "Disabled on all adapters"
    }
    else {
        Add-Result "NetBIOS" "Warning" "NetBIOS enabled on one or more adapters"
        $ans = Read-Host "Disable NetBIOS on ALL adapters? (Y/N)"

        if ($ans -match '^[Yy]$') {
            foreach ($a in $adapters) { $a.SetTcpipNetbios(2) | Out-Null }
            Add-Result "NetBIOS" "Secure" "Disabled globally"
        }
    }
}
catch {
    Add-Result "NetBIOS" "Warning" "Failed to check or set NetBIOS" $_.Exception.Message
}

# ----------------------------------------------------------
# ZeroLogon / Netlogon Hardening
# ----------------------------------------------------------
Write-Host "`n[+] Verifying Netlogon secure channel (Zerologon mitigation)..." -ForegroundColor Cyan

try {
    $netlogonPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"

    # Required secure values
    $expected = @{
        "RequireStrongKey"            = 1
        "RequireSignOrSeal"           = 1
        "RequireSeal"                 = 1
        "RequireSigning"              = 1
        "FullSecureChannelProtection" = 1
        "DisablePasswordChange"       = 0
    }

    # Read existing values
    $vals = Get-ItemProperty -Path $netlogonPath -ErrorAction SilentlyContinue
    $missing = @()

    foreach ($key in $expected.Keys) {
        if ($vals.$key -ne $expected[$key]) {
            $missing += $key
        }
    }

    if ($missing.Count -eq 0) {
        Add-Result "ZeroLogon" "Secure" "Full Netlogon protection enforced"
        Write-Host "[OK] ZeroLogon mitigations fully enforced." -ForegroundColor Green
    }
    else {
        Add-Result "ZeroLogon" "Warning" "Weak or missing settings: $($missing -join ', ')"
        Write-Warn "Missing / weak Netlogon keys:"
        Write-Warn " → $($missing -join ', ')"

        $apply = Read-Host "Apply full ZeroLogon hardening now? (Y/N)"
        if ($apply -match '^[Yy]$') {
            foreach ($key in $expected.Keys) {
                Set-ItemProperty -Path $netlogonPath -Name $key -Value $expected[$key] -Type DWord -Force
            }

            Restart-Service Netlogon -ErrorAction SilentlyContinue

            Add-Result "ZeroLogon" "Secure" "Mitigation applied + Netlogon restarted"
            Write-Host "[+] Applied full ZeroLogon hardening." -ForegroundColor Green
        }
        else {
            Write-Host "[!] Skipped ZeroLogon hardening." -ForegroundColor Yellow
            Add-Result "ZeroLogon" "Warning" "Skipped by admin"
        }
    }
}
catch {
    Add-Result "ZeroLogon" "Error" "Failed: $($_.Exception.Message)"
}

# ----------------------------------------------------------
# PRIVILEGED AD GROUP REVIEW (INTERACTIVE)
# ----------------------------------------------------------
Write-Host "`n[+] Reviewing privileged AD groups..." -ForegroundColor Cyan

$PrivGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Administrators",
    "DnsAdmins",
    "Schema Admins",
    "Group Policy Creator Owners",
    "Key Admins",
    "Enterprise Key Admins"
)

$BuiltInSafe = @("Administrator", "Domain Admins", "Enterprise Admins")

foreach ($group in $PrivGroups) {
    try {
        $members = @( Get-ADGroupMember -Identity $group -ErrorAction Stop )
        $unexpected = $members | Where-Object { $BuiltInSafe -notcontains $_.SamAccountName }

        if ($unexpected.Count -eq 0) {
            Add-Result "AD Group: ${group}" "Secure" "No unauthorized members" "Count=$($members.Count)"
        }
        else {
            foreach ($usr in $unexpected) {
                Write-Warn "Suspicious member in ${group}: $($usr.SamAccountName)"
                $ans = Read-Host "Remove $($usr.SamAccountName) from ${group}? (Y/N)"

                if ($ans -match '^[Yy]$') {
                    try {
                        Remove-ADGroupMember -Identity $group -Members $usr -Confirm:$false
                        Add-Result "AD Group: ${group}" "Secure" "Removed $($usr.SamAccountName)" "Interactive removal"
                    }
                    catch {
                        Add-Result "AD Group: ${group}" "Error" "Failed to remove $($usr.SamAccountName)" $_.Exception.Message
                    }
                }
                else {
                    Add-Result "AD Group: ${group}" "Warning" "Left $($usr.SamAccountName) in group"
                }
            }
        }
    }
    catch {
        Add-Result "AD Group: ${group}" "Warning" "Enumeration failed" $_.Exception.Message
    }
}


# ----------------------------------------------------------
# DISABLE PASSWORD NEVER EXPIRES FOR ALL USERS
# ----------------------------------------------------------
function Enforce-PasswordNeverExpires {
    Write-Host "`n[+] Checking for users with PasswordNeverExpires enabled..." -ForegroundColor Cyan

    try {
        $users = Get-ADUser -Filter * -Properties PasswordNeverExpires |
                 Where-Object { $_.PasswordNeverExpires -eq $true }

        if ($users.Count -eq 0) {
            Write-Ok "No accounts with PasswordNeverExpires enabled."
            Add-Result "PasswordNeverExpires" "Secure" "No insecure accounts"
            return
        }

        Write-Warn "$($users.Count) users have PasswordNeverExpires enabled:"
        $users | Select SamAccountName | Format-Table

        $choice = Read-Host "Disable PasswordNeverExpires for ALL these users? (Y/N)"

        if ($choice -match "^[Yy]$") {
            foreach ($u in $users) {
                Set-ADUser $u -PasswordNeverExpires $false
                Write-Host "  [Fixed] $($u.SamAccountName)" -ForegroundColor Green
            }

            Add-Result "PasswordNeverExpires" "Secure" "Disabled for all affected users"
        }
        else {
            Add-Result "PasswordNeverExpires" "Warning" "Skipped by admin"
        }

    }
    catch {
        Add-Result "PasswordNeverExpires" "Warning" "Failed" ($_.Exception.Message)
    }
}

Enforce-PasswordNeverExpires

# ----------------------------------------------------------
# AS-REP ROASTING PROTECTION (INTERACTIVE FIX)
# ----------------------------------------------------------
function Enforce-ASREPProtection {
    Write-Host "`n[+] Checking AS-REP Roasting vulnerable accounts..." -ForegroundColor Cyan

    try {
        $vulnUsers = Get-ADUser -Filter * -Properties DoesNotRequirePreAuth |
                     Where-Object { $_.DoesNotRequirePreAuth -eq $true }

        if ($vulnUsers.Count -eq 0) {
            Write-Ok "No AS-REP roastable accounts found."
            Add-Result "AS-REP Roasting" "Secure" "All users require pre-authentication"
            return
        }

        Write-Warn "$($vulnUsers.Count) vulnerable accounts found:"
        $vulnUsers | Select SamAccountName, DistinguishedName | Format-Table

        foreach ($u in $vulnUsers) {

            $ans = Read-Host "Fix AS-REP vulnerability for user $($u.SamAccountName)? (Y/N)"

            if ($ans -match '^[Yy]$') {
                try {
                    Set-ADAccountControl -Identity $u.SamAccountName -DoesNotRequirePreAuth $false -ErrorAction Stop
                    Write-Host "  [Fixed] $($u.SamAccountName)" -ForegroundColor Green
                    Add-Result "AS-REP Roasting" "Secure" "Fixed vulnerable account" $u.SamAccountName
                }
                catch {
                    Write-Err "Failed to fix $($u.SamAccountName): $($_.Exception.Message)"
                    Add-Result "AS-REP Roasting" "Error" "Failed to fix account" $u.SamAccountName
                }
            }
            else {
                Add-Result "AS-REP Roasting" "Warning" "Left vulnerable user unmodified" $u.SamAccountName
            }
        }
    }
    catch {
        Add-Result "AS-REP Roasting" "Error" "Failed to enumerate users" ($_.Exception.Message)
    }
}

# Execute
Enforce-ASREPProtection

# ----------------------------------------------------------
# KERBEROS PER-USER ENCRYPTION HARDENING (AES Only)
# ----------------------------------------------------------
function Enforce-KerberosUserEncryption {
    Write-Host "`n[+] Checking Kerberos per-user encryption settings..." -ForegroundColor Cyan

    try {
        # Get users missing AES or allowing DES
        $weakUsers = Get-ADUser -Filter * -Properties "msDS-SupportedEncryptionTypes" | Where-Object {
            # If attribute is missing → RC4 only → insecure
            ($_.{"msDS-SupportedEncryptionTypes"} -eq $null) -or
            # If DES bit enabled (0x1 or 0x2)
            (($_."msDS-SupportedEncryptionTypes" -band 0x3) -ne 0) -or
            # If AES128 (0x8) & AES256 (0x10) not set
            (($_."msDS-SupportedEncryptionTypes" -band 0x18) -eq 0)
        }

        if ($weakUsers.Count -eq 0) {
            Write-Ok "All users already enforce AES-only Kerberos encryption."
            Add-Result "Kerberos Encryption" "Secure" "All users use AES128/AES256"
            return
        }

        # If one user → ask individually
        if ($weakUsers.Count -eq 1) {
            $u = $weakUsers[0]
            Write-Warn "User '$($u.SamAccountName)' has weak Kerberos encryption:"
            Write-Host "SupportedEncryptionTypes = $($u.'msDS-SupportedEncryptionTypes')" -ForegroundColor Yellow

            $ask = Read-Host "Fix Kerberos encryption for user $($u.SamAccountName)? (Y/N)"
            if ($ask -match '^[Yy]$') {
                # AES128 + AES256 only (0x8 + 0x10 = 24)
                Set-ADUser -Identity $u -Replace @{ "msDS-SupportedEncryptionTypes" = 24 }
                Write-Host "  [Fixed] $($u.SamAccountName)" -ForegroundColor Green
                Add-Result "Kerberos Encryption" "Secure" "Fixed weak encryption" $u.SamAccountName
            }
            else {
                Add-Result "Kerberos Encryption" "Warning" "Skipped user" $u.SamAccountName
            }

            return
        }

        # If multiple → list all and confirm mass fix
        Write-Warn "$($weakUsers.Count) users have weak Kerberos encryption:"
        $weakUsers | Select SamAccountName, DistinguishedName | Format-Table

        $askAll = Read-Host "Fix Kerberos encryption for ALL these users? (Y/N)"
        if ($askAll -match '^[Yy]$') {
            foreach ($u in $weakUsers) {
                Set-ADUser -Identity $u -Replace @{ "msDS-SupportedEncryptionTypes" = 24 }
                Write-Host "  [Fixed] $($u.SamAccountName)" -ForegroundColor Green
            }

            Add-Result "Kerberos Encryption" "Secure" "Fixed all weak Kerberos accounts" "Count=$($weakUsers.Count)"
        }
        else {
            Add-Result "Kerberos Encryption" "Warning" "Skipped fixing Kerberos settings" "Count=$($weakUsers.Count)"
        }
    }
    catch {
        Add-Result "Kerberos Encryption" "Error" "Failed to apply Kerberos user hardening" $_.Exception.Message
    }
}

# Execute
Enforce-KerberosUserEncryption

# ----------------------------------------------------------
# USER ENUMERATION BLOCK (Anonymous Access Restriction)
# ----------------------------------------------------------
function Enforce-UserEnumerationBlock {
    Write-Host "`n[+] Enforcing User Enumeration Restrictions..." -ForegroundColor Cyan

    try {
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $srvPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"

        Set-ItemProperty -Path $lsaPath -Name RestrictAnonymousSAM -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $lsaPath -Name RestrictAnonymous -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $srvPath -Name RestrictNullSessAccess -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $lsaPath -Name EveryoneIncludesAnonymous -Value 0 -Type DWord -Force

        Add-Result "User Enumeration" "Secure" "Anonymous SAM, shares, null sessions, and SID lookups blocked"
        Write-Host "User enumeration protections applied." -ForegroundColor Green
    }
    catch {
        Add-Result "User Enumeration" "Warning" "Failed to apply user enumeration ACLs" $_.Exception.Message
        
        $msg = '[WARN] Failed to apply user enumeration restrictions: ' + $_.Exception.Message
        Write-Host $msg -ForegroundColor Yellow
    }
}

function Harden-DomainUsersACL {
    Write-Host "[+] Restricting Domain Users ACL permissions for enumeration..." -ForegroundColor Cyan

    $domainDN = (Get-ADDomain).DistinguishedName
    $domainUsers = (Get-ADGroup "Domain Users").DistinguishedName

    # Get the Domain root ACL
    $acl = Get-ACL "AD:$domainDN"

    # Remove List/Read from Domain Users
    foreach ($ace in $acl.Access) {
        if ($ace.IdentityReference -eq "NT AUTHORITY\Authenticated Users" -or
            $ace.IdentityReference -eq "Domain Users") {

            if ($ace.ActiveDirectoryRights -match "ListContents|ReadProperty|ListObject") {
                Write-Host "[INFO] Removing enumeration rights from $($ace.IdentityReference)" -ForegroundColor Yellow
                $acl.RemoveAccessRule($ace)
            }
        }
    }

    # Apply modified ACL
    Set-ACL -Path "AD:$domainDN" -AclObject $acl

    Add-Result "Directory ACL Hardening" "Secure" "Domain Users cannot enumerate AD via LDAP"
    Write-Host "✓ Domain Users no longer have LDAP enumeration rights." -ForegroundColor Green
}

# ----------------------------------------------------------
# PRINT SPOOLER HARDENING (DC SAFE)
# ----------------------------------------------------------
Write-Host "`n[+] Checking Print Spooler service status (DC hardening)..." -ForegroundColor Cyan

try {
    $spooler = Get-Service -Name Spooler -ErrorAction Stop

    # Secure state: Stopped + Disabled
    $Condition = ($spooler.Status -eq 'Stopped' -and $spooler.StartType -eq 'Disabled')

    $Fix = {
        Write-Info "Stopping Print Spooler service..."
        Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue

        Write-Info "Disabling Print Spooler service..."
        Set-Service -Name Spooler -StartupType Disabled
    }

    Check-Once `
        "Print Spooler" `
        $Condition `
        $Fix `
        "Service stopped and disabled (secure)" `
        "Print Spooler enabled (PrintNightmare risk)"
}
catch {
    Add-Result "Print Spooler" "Error" "Failed to query or modify Print Spooler service" $_.Exception.Message
}
