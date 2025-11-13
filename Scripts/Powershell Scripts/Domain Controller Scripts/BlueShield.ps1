<#
.SYNOPSIS
  BlueShield – Domain Controller Security Hardening & Audit

.DESCRIPTION
  Comprehensive hardening & auditing tool for Windows Server Domain Controllers:
  - Backup: Firewall + DNS zones
  - ZeroLogon / noPAC / SMBv1 / NTLM / LLMNR / LSASS / Kerberos
  - SMB Signing, Anonymous Access, Guest Account, Audit Policy
  - Privileged AD Group Review (with interactive removal)
  - Kerberoast Defense Audit
  - Network & Service Hardening
  - Windows Update Validation (Cumulative Update)
  - Summary report (CSV + console)
#>
# ----------------------------------------------------------
# Helper Output Functions (must appear before first use)
# ----------------------------------------------------------
function Write-Ok($msg)  { Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Info($msg){ Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Write-Warn($msg){ Write-Host "[WARN] $msg" -ForegroundColor Yellow }

Import-Module ActiveDirectory -ErrorAction SilentlyContinue
Write-Host '=== BlueShield: Domain Controller Security Hardening & Audit ===' -ForegroundColor Cyan
Write-Host "Running checks on $env:COMPUTERNAME ($env:USERDOMAIN) ..." -ForegroundColor Yellow
Write-Host ""


# ----------------------------------------------------------
# Result Collector
# ----------------------------------------------------------
$global:Results = @()
function Add-Result {
    param([string]$Name,[string]$Status,[string]$Info,[string]$Value="")
    if (-not $global:Results) { $global:Results = @() }
    $global:Results += [PSCustomObject]@{
        Check=$Name; Status=$Status; Info=$Info; Value=$Value
        Timestamp=(Get-Date).ToString("s")
    }
    $color = switch ($Status) {
        "Secure" {"Green"} "Warning" {"Yellow"} "Critical" {"Red"} Default {"Gray"}
    }
    $msg = if ($Value) { "[{0}] {1} - {2} [{3}]" -f $Status,$Name,$Info,$Value }
           else { "[{0}] {1} - {2}" -f $Status,$Name,$Info }
    Write-Host $msg -ForegroundColor $color
}

# ----------------------------------------------------------
# BACKUPS FIREWALL
# ----------------------------------------------------------
Write-Host "`n[+] Backing up firewall configuration..." -ForegroundColor Cyan
try {
    # Create backup directory if missing
    $BackupDir = "C:\BlueShield_Backups"
    if (-not (Test-Path $BackupDir)) {
        New-Item -ItemType Directory -Path $BackupDir | Out-Null
        Write-Host "Created backup directory: $BackupDir" -ForegroundColor Yellow
    }

    # Export current firewall policy
    $fwFile = Join-Path $BackupDir ("Firewall_{0}.wfw" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    netsh advfirewall export $fwFile | Out-Null

    Add-Result "Firewall Backup" "Secure" "Exported" $fwFile
    Write-Host "Firewall configuration exported successfully to $fwFile" -ForegroundColor Green
}
catch {
    Add-Result "Firewall Backup" "Warning" "Failed" $_.Exception.Message
    Write-Host "Failed to back up firewall configuration: $($_.Exception.Message)" -ForegroundColor Red
}

# ----------------------------------------------------------
# BACKUPS (FULL DOMAIN CONTROLLER)
# ----------------------------------------------------------
Write-Host "`n[+] Starting full backup sequence..." -ForegroundColor Cyan

# Root structure and filenames
$RootBackup = "C:\BlueShield_Backups"
$FullBackup = Join-Path $RootBackup "DC_Full_Backup"
$Timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$ZipPath    = Join-Path $RootBackup ("DC_Backup_{0}.zip" -f $Timestamp)
$Inventory  = Join-Path $FullBackup "Backup_Inventory.txt"

try {
    # Create root folders
    foreach ($folder in @($RootBackup, $FullBackup)) {
        if (-not (Test-Path $folder)) {
            New-Item -ItemType Directory -Path $folder -Force | Out-Null
            Write-Host "Created folder: $folder" -ForegroundColor Yellow
        }
    }

    # --- GROUP POLICY BACKUP ---
    Write-Host "[>] Backing up GPOs..." -ForegroundColor Cyan
    $GpoPath = Join-Path $FullBackup "GPOs"
    New-Item -ItemType Directory -Path $GpoPath -Force | Out-Null
    Backup-Gpo -All -Path $GpoPath -ErrorAction Stop
    Write-Host "✓ GPO backup completed." -ForegroundColor Green

    # --- NTDS IFM BACKUP ---
    Write-Host "[>] Backing up Active Directory database (IFM)..." -ForegroundColor Cyan
    $NtdsPath = Join-Path $FullBackup "NTDS_IFM"
    New-Item -ItemType Directory -Path $NtdsPath -Force | Out-Null
    ntdsutil "activate instance ntds" "ifm" "create full $NtdsPath" quit quit | Out-Null
    Write-Host "✓ NTDS IFM backup completed." -ForegroundColor Green

    # --- SYSVOL BACKUP ---
    Write-Host "[>] Backing up SYSVOL..." -ForegroundColor Cyan
    $SysvolPath = Join-Path $FullBackup "SYSVOL"
    New-Item -ItemType Directory -Path $SysvolPath -Force | Out-Null
    Copy-Item "C:\Windows\SYSVOL" -Destination $SysvolPath -Recurse -Force
    Write-Host "✓ SYSVOL backup completed." -ForegroundColor Green

    # --- REGISTRY HIVES BACKUP ---
    Write-Host "[>] Backing up critical registry hives..." -ForegroundColor Cyan
    $RegPath = Join-Path $FullBackup "Registry"
    New-Item -ItemType Directory -Path $RegPath -Force | Out-Null
    reg export HKLM\SYSTEM   (Join-Path $RegPath "SYSTEM.reg")   /y
    reg export HKLM\SOFTWARE (Join-Path $RegPath "SOFTWARE.reg") /y
    reg export HKLM\SAM      (Join-Path $RegPath "SAM.reg")      /y
    Write-Host "✓ Registry hives exported." -ForegroundColor Green

    # --- ADCS (CERTIFICATE AUTHORITY) BACKUP ---
Write-Host "[>] Backing up ADCS (Certificate Services)..." -ForegroundColor Cyan
$CAPath = Join-Path $FullBackup "ADCS"
New-Item -ItemType Directory -Path $CAPath -Force | Out-Null

if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc") {
    try {
        certutil -backupDB (Join-Path $CAPath "DB") | Out-Null
        certutil -backupKey (Join-Path $CAPath "Keys") | Out-Null
        reg export HKLM\SYSTEM\CurrentControlSet\Services\CertSvc (Join-Path $CAPath "CertSvc.reg") /y | Out-Null
        Write-Host "✓ ADCS backup completed." -ForegroundColor Green
        Add-Result "ADCS Backup" "Secure" "Completed" $CAPath
    }
    catch {
        Write-Host "[WARN] ADCS backup failed: $($_.Exception.Message)" -ForegroundColor Yellow
        Add-Result "ADCS Backup" "Warning" "Failed" $_.Exception.Message
    }
}
else {
    Write-Host "[WARN] Certificate Services not installed — skipping ADCS backup." -ForegroundColor Yellow
    Add-Result "ADCS Backup" "Skipped" "CA not installed" ""
}

    # --- SECURITY POLICY BACKUP ---
    Write-Host "[>] Exporting security policy..." -ForegroundColor Cyan
    $SecPath = Join-Path $FullBackup "SecurityPolicy"
    New-Item -ItemType Directory -Path $SecPath -Force | Out-Null
    secedit /export /cfg (Join-Path $SecPath "SecurityPolicy.inf") | Out-Null
    Write-Host "✓ Security policy exported." -ForegroundColor Green

    # --- TASK SCHEDULER BACKUP ---
    Write-Host "[>] Backing up scheduled tasks..." -ForegroundColor Cyan
    $TaskPath = Join-Path $FullBackup "Tasks"
    New-Item -ItemType Directory -Path $TaskPath -Force | Out-Null
    Copy-Item "C:\Windows\System32\Tasks" -Destination $TaskPath -Recurse -Force
    Write-Host "✓ Task backup completed." -ForegroundColor Green

    # --- SYSTEM INFO & HOTFIXES ---
    Write-Host "[>] Gathering system information..." -ForegroundColor Cyan
    systeminfo | Out-File (Join-Path $FullBackup "SystemInfo.txt")
    Get-HotFix | Out-File (Join-Path $FullBackup "InstalledUpdates.txt")
    Write-Host "✓ System info and update list collected." -ForegroundColor Green

    # --- EVENT LOG BACKUP ---
    Write-Host "[>] Exporting Windows Event Logs..." -ForegroundColor Cyan
    $EvtPath = Join-Path $FullBackup "EventLogs"
    New-Item -ItemType Directory -Path $EvtPath -Force | Out-Null
    foreach ($log in @("Application", "System", "Security", "Directory Service", "DNS Server")) {
        $evtxFile = Join-Path $EvtPath ("{0}.evtx" -f $log.Replace(' ', '_'))
        wevtutil epl $log $evtxFile
    }
    Write-Host "✓ Event logs exported successfully." -ForegroundColor Green

    # --- EXTENDED WMI INVENTORY ---
    Write-Host "[>] Generating WMI inventory (hardware, drivers, services)..." -ForegroundColor Cyan
    $WmiPath = Join-Path $FullBackup "WMI_Inventory"
    New-Item -ItemType Directory -Path $WmiPath -Force | Out-Null


    Get-WmiObject Win32_ComputerSystem |
        Select-Object Name, Manufacturer, Model, NumberOfProcessors, TotalPhysicalMemory |
        Export-Csv (Join-Path $WmiPath "System.csv") -NoTypeInformation

    Get-WmiObject Win32_OperatingSystem |
        Select-Object Caption, Version, BuildNumber, InstallDate, LastBootUpTime |
        Export-Csv (Join-Path $WmiPath "OperatingSystem.csv") -NoTypeInformation

    Get-WmiObject Win32_Service |
        Select-Object Name, DisplayName, StartMode, State, PathName |
        Export-Csv (Join-Path $WmiPath "Services.csv") -NoTypeInformation

    Get-WmiObject Win32_PnPSignedDriver |
        Select-Object DeviceName, DriverVersion, Manufacturer, DriverDate |
        Export-Csv (Join-Path $WmiPath "Drivers.csv") -NoTypeInformation

    Write-Host "✓ WMI inventory completed." -ForegroundColor Green

    # --- INVENTORY & COMPRESSION ---
    Write-Host "[>] Creating backup inventory..." -ForegroundColor Cyan
    Get-ChildItem $FullBackup -Recurse | Select-Object FullName, Length, LastWriteTime |
        Out-File $Inventory
    Write-Host "✓ Inventory file generated." -ForegroundColor Green

    Write-Host "[>] Compressing all backups..." -ForegroundColor Cyan
    Compress-Archive -Path "$FullBackup\*" -DestinationPath $ZipPath -Force
    Write-Host "✓ Backup archive created: $ZipPath" -ForegroundColor Green

    # --- OFFSITE COPY (OPTIONAL) ---
    $RemotePath = "\\tsclient\H\Xsploit Club"
    if (Test-Path $RemotePath) {
        Copy-Item -Path $ZipPath -Destination $RemotePath -Force
        Write-Host "✓ Offsite copy stored to $RemotePath" -ForegroundColor Green
    }
    else {
        Write-Host "[WARN] Offsite path not reachable: $RemotePath" -ForegroundColor Yellow
    }

}  

catch {
    Add-Result "Full Backup" "Warning" "Failed" $_.Exception.Message
    Write-Host "[-] Backup process failed: $($_.Exception.Message)" -ForegroundColor Red
}


# ----------------------------------------------------------
# DNS ZONE BACKUP (STATIC FOLDER)
# ----------------------------------------------------------
<#
.SYNOPSIS
    DNS Zone Backup (Static Folder)
.DESCRIPTION
    Backs up all DNS zones to a fixed location and overwrites previous backups.
    Ideal for competition or recovery use (no timestamps).
#>

# --- Helper function for standalone runs ---
if (-not (Get-Command Add-Result -ErrorAction SilentlyContinue)) {
    function Add-Result($Category, $Status, $Message, $Details=$null) {
        Write-Host "[RESULT] $Category - $Status - $Message" -ForegroundColor Cyan
    }
}

Write-Host "`n[+] Performing DNS zone backup..." -ForegroundColor Cyan
$BackupRoot = "C:\BlueShield_Backups\DNS_Backups"
$BackupDir  = Join-Path $BackupRoot "Latest"
$zipPath    = Join-Path $BackupRoot "DNS_Backup_Latest.zip"

try {
    # Ensure folders exist
    New-Item -Path $BackupDir -ItemType Directory -Force | Out-Null
    Write-Host "Backup folder: $BackupDir" -ForegroundColor Yellow

    # Enumerate zones
    $zones = Get-DnsServerZone -ErrorAction Stop
    if (-not $zones) {
        Add-Result "DNS Zone Backup" "Warning" "No zones found on this server"
        Write-Warning "No zones found! Are you running as Administrator on a DNS server?"
    }
    else {
        # Save manifest
        $manifest = Join-Path $BackupDir "zones-list.csv"
        $zones | Select-Object ZoneName, ZoneType, IsDsIntegrated, IsReverseLookupZone |
            Export-Csv -Path $manifest -NoTypeInformation

        Write-Host ("Found {0} zones to export..." -f $zones.Count) -ForegroundColor Cyan

        foreach ($z in $zones) {
            $zname    = $z.ZoneName
            $safeFile = ($zname -replace '[\\/:\*\?"<>\|]', '_') + ".dns"
            $outPath  = Join-Path $BackupDir $safeFile
            Write-Host ("Backing up zone: {0}" -f $zname) -ForegroundColor Green

            # Try native PowerShell cmdlet first
            try {
                if (Get-Command -Name Export-DnsServerZone -ErrorAction SilentlyContinue) {
                    Export-DnsServerZone -Name $zname -Path $outPath -ErrorAction Stop
                    Write-Host ("[OK] Export-DnsServerZone -> {0}" -f $outPath)
                    continue
                }
            }
            catch {
                Write-Warning ("Export-DnsServerZone failed for {0}: {1}" -f $zname, $_.Exception.Message)
            }

            # Fallback to dnscmd
            try {
                & dnscmd.exe /zoneexport $zname $safeFile 2>$null
                $sysDns = Join-Path $env:windir ("System32\dns\" + $safeFile)
                if (Test-Path $sysDns) {
                    Move-Item -Path $sysDns -Destination $outPath -Force
                    Write-Host ("[OK] dnscmd /zoneexport -> {0}" -f $outPath)
                }
                else {
                    Write-Warning ("dnscmd reported success but file {0} not found" -f $safeFile)
                }
            }
            catch {
                Write-Warning ("dnscmd failed for {0}: {1}" -f $zname, $_.Exception.Message)
            }
        }

        # === Export full DNS record lists (text + CSV) ===
        Write-Host "`n[+] Exporting complete DNS record listings..." -ForegroundColor Cyan
        $recordCsv = Join-Path $BackupDir "AllDnsRecords.csv"
        $zoneTxt   = Join-Path $BackupDir "DnsRecords.txt"

        try {
            # Export full zone print for human-readable backup
            & dnscmd . /ZonePrint your.domain.com > $zoneTxt

            # Export all resource records from every zone to CSV
            Get-DnsServerZone | ForEach-Object {
                Get-DnsServerResourceRecord -ZoneName $_.ZoneName
            } | Export-Csv -Path $recordCsv -NoTypeInformation

            Write-Host ("[OK] DNS records exported to:`n - {0}`n - {1}" -f $recordCsv, $zoneTxt) -ForegroundColor Green
        }
        catch {
            Write-Warning ("Failed to export detailed DNS records: {0}" -f $_.Exception.Message)
        }

        # Compress the backup
        if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
        Compress-Archive -Path "$BackupDir\*" -DestinationPath $zipPath -Force
        Add-Result "DNS Zone Backup" "Secure" "All zones exported" $zipPath

        Write-Host "`nDNS zone backup complete!" -ForegroundColor Cyan
        Write-Host ("ZIP saved to: {0}" -f $zipPath) -ForegroundColor Yellow
    }
}
catch {
    Add-Result "DNS Zone Backup" "Warning" "Failed to back up zones" $_.Exception.Message
    Write-Host ("DNS backup failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
}
# ----------------------------------------------------------
# ADDITIONAL BACKUPS (ADVANCED SYSTEM STATE)
# ----------------------------------------------------------
Write-Host "`n[+] Performing advanced system backups..." -ForegroundColor Cyan

$RootBackup = "C:\BlueShield_Backups"
$AdvBackup  = Join-Path $RootBackup "DC_Advanced_Backup"
$Timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$ZipPath    = Join-Path $RootBackup ("DC_Advanced_{0}.zip" -f $Timestamp)

try {
    # Ensure directory
    if (-not (Test-Path $AdvBackup)) {
        New-Item -ItemType Directory -Path $AdvBackup -Force | Out-Null
        Write-Host "Created backup folder: $AdvBackup" -ForegroundColor Yellow
    }

    # ==========================================================
    # 1. ACTIVE DIRECTORY EXPORTS
    # ==========================================================
    Write-Host "[>] Exporting Active Directory objects..." -ForegroundColor Cyan
    $ADPath = Join-Path $AdvBackup "ActiveDirectory_Export"
    New-Item -ItemType Directory -Path $ADPath -Force | Out-Null
    Get-ADUser -Filter * -Properties * | Export-Csv "$ADPath\AD_Users.csv" -NoTypeInformation
    Get-ADGroup -Filter * -Properties * | Export-Csv "$ADPath\AD_Groups.csv" -NoTypeInformation
    Get-ADComputer -Filter * -Properties * | Export-Csv "$ADPath\AD_Computers.csv" -NoTypeInformation
    Write-Host "✓ AD exports completed." -ForegroundColor Green

    # ==========================================================
    # 2. CERTIFICATES & PRIVATE KEYS
    # ==========================================================
    Write-Host "[>] Exporting local certificates and private keys..." -ForegroundColor Cyan
    $CertExport = Join-Path $AdvBackup "Certificates"
    New-Item -ItemType Directory -Path $CertExport -Force | Out-Null
    $pwd = ConvertTo-SecureString -String "BlueShieldBackup!" -Force -AsPlainText
    Get-ChildItem Cert:\LocalMachine\My | ForEach-Object {
        $file = "$CertExport\$($_.FriendlyName)_$($_.Thumbprint).pfx"
        Export-PfxCertificate -Cert $_ -FilePath $file -Password $pwd -ErrorAction SilentlyContinue
    }
    Write-Host "✓ Certificates exported." -ForegroundColor Green

    # ==========================================================
# 3. EVENT FORWARDING & AUDIT POLICIES
# ==========================================================
Write-Host "[>] Backing up event forwarding subscriptions & audit policy..." -ForegroundColor Cyan
$WEFPath = Join-Path $AdvBackup "EventForwarding"
New-Item -ItemType Directory -Path $WEFPath -Force | Out-Null

# Check if Windows Event Collector service exists
$wecService = Get-Service -Name wecsvc -ErrorAction SilentlyContinue
if ($null -ne $wecService) {
    if ($wecService.Status -ne 'Running') {
        Write-Host "[INFO] Starting Windows Event Collector service..." -ForegroundColor Yellow
        Start-Service wecsvc -ErrorAction SilentlyContinue
    }

    try {
        wecutil es > "$WEFPath\EventSubscriptions.xml" 2>$null
        Write-Host "✓ Event subscriptions exported." -ForegroundColor Green
    }
    catch {
        Write-Host "[WARN] Unable to export event subscriptions: $($_.Exception.Message)" -ForegroundColor Yellow
        Add-Result "Event Forwarding" "Warning" "Failed" $_.Exception.Message
    }
}
else {
    Write-Host "[WARN] Event Collector service not installed — skipping WEF export." -ForegroundColor Yellow
    Add-Result "Event Forwarding" "Skipped" "Service not installed" ""
}

# Always export audit policies
auditpol /get /category:* > "$WEFPath\AuditPolicy.txt" 2>$null
Write-Host "✓ Audit policies exported." -ForegroundColor Green


    # ==========================================================
    # 4. LOCAL SECURITY POLICY
    # ==========================================================
    Write-Host "[>] Exporting local security policy..." -ForegroundColor Cyan
    $SecBackup = Join-Path $AdvBackup "LocalPolicies"
    New-Item -ItemType Directory -Path $SecBackup -Force | Out-Null
    secedit /export /cfg "$SecBackup\LocalSecurityPolicy.inf" | Out-Null
    Write-Host "✓ Local security policy exported." -ForegroundColor Green

    # --- BOOT CONFIGURATION & DRIVER STORE ---
    Write-Host "[>] Backing up boot configuration & driver store..." -ForegroundColor Cyan
    $BootPath = Join-Path $AdvBackup "Boot"
    New-Item -ItemType Directory -Path $BootPath -Force | Out-Null

    # Export BCD cleanly, suppress logs
    bcdedit /export "$BootPath\BCD_Backup.bcd" | Out-Null
    # Remove log files if generated
    Get-ChildItem $BootPath -Filter "*.LOG*" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

    Copy-Item "C:\Windows\System32\DriverStore\FileRepository" -Destination "$BootPath\DriverStore" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "✓ Boot and driver backup complete." -ForegroundColor Green


    # ==========================================================
    # 6. INSTALLED FEATURES & SERVICES
    # ==========================================================
    Write-Host "[>] Exporting installed services and Windows features..." -ForegroundColor Cyan
    $SrvPath = Join-Path $AdvBackup "Services"
    New-Item -ItemType Directory -Path $SrvPath -Force | Out-Null
    Get-Service | Select-Object Name, DisplayName, StartType, Status | Export-Csv "$SrvPath\Services.csv" -NoTypeInformation
    Get-WindowsFeature | Where-Object {$_.Installed} | Export-Csv "$SrvPath\InstalledFeatures.csv" -NoTypeInformation
    Write-Host "✓ Services & features exported." -ForegroundColor Green

    # ==========================================================
    # 7. NETWORK CONFIGURATION
    # ==========================================================
    Write-Host "[>] Capturing network configuration and routes..." -ForegroundColor Cyan
    $NetPath = Join-Path $AdvBackup "Network"
    New-Item -ItemType Directory -Path $NetPath -Force | Out-Null
    ipconfig /all > "$NetPath\IPConfig.txt"
    netstat -ano > "$NetPath\Netstat.txt"
    route print > "$NetPath\RouteTable.txt"
    Get-NetAdapter | Export-Csv "$NetPath\Adapters.csv" -NoTypeInformation
    Write-Host "✓ Network configuration exported." -ForegroundColor Green

    # ==========================================================
    # 9. SMB SHARES & PERMISSIONS
    # ==========================================================
    Write-Host "[>] Exporting SMB share configuration and ACLs..." -ForegroundColor Cyan
    $SharePath = Join-Path $AdvBackup "Shares"
    New-Item -ItemType Directory -Path $SharePath -Force | Out-Null
    Get-SmbShare | Select-Object Name, Path, Description, FolderEnumerationMode, FullAccess, ChangeAccess, ReadAccess |
        Export-Csv "$SharePath\SmbShares.csv" -NoTypeInformation
    if (Test-Path "C:\Shares") {
        Get-Acl -Path "C:\Shares" | Export-Clixml "$SharePath\NTFS_ACL.xml"
    }
    Write-Host "✓ SMB shares and ACLs exported." -ForegroundColor Green

    # ==========================================================
    # 10. POWERSHELL SCRIPTS & SCHEDULED TASKS
    # ==========================================================
    Write-Host "[>] Backing up BlueShield scripts and scheduled tasks..." -ForegroundColor Cyan
    $ScriptsPath = Join-Path $AdvBackup "Scripts"
    New-Item -ItemType Directory -Path $ScriptsPath -Force | Out-Null
    Copy-Item "C:\BlueShield*" -Destination $ScriptsPath -Recurse -Force -ErrorAction SilentlyContinue
    Get-ScheduledTask | Export-Clixml "$ScriptsPath\ScheduledTasks.xml"
    Write-Host "✓ Scripts & tasks exported." -ForegroundColor Green

    # ==========================================================
    # 11. AUTORUNS SNAPSHOT
    # ==========================================================
    Write-Host "[>] Capturing autoruns snapshot (persistence map)..." -ForegroundColor Cyan
    $AutoPath = Join-Path $AdvBackup "Autoruns"
    New-Item -ItemType Directory -Path $AutoPath -Force | Out-Null
    $autorunExe = "C:\Sysinternals\autorunsc.exe"
    if (Test-Path $autorunExe) {
        & $autorunExe -accepteula -a * -ct -h -o "$AutoPath\Autoruns.csv"
        Write-Host "✓ Autoruns snapshot exported." -ForegroundColor Green
    }
    else {
        Write-Host "[WARN] autorunsc.exe not found — skipping Autoruns backup." -ForegroundColor Yellow
    }

    # ==========================================================
    # FINALIZE
    # ==========================================================
    Write-Host "[>] Compressing advanced backups..." -ForegroundColor Cyan
    Compress-Archive -Path "$AdvBackup\*" -DestinationPath $ZipPath -Force
    Write-Host "✓ Archive created: $ZipPath" -ForegroundColor Green

    Add-Result "Advanced Backups" "Secure" "Completed" $ZipPath
}
catch {
    Add-Result "Advanced Backups" "Warning" "Failed" $_.Exception.Message
    Write-Host "[-] Advanced backup process failed: $($_.Exception.Message)" -ForegroundColor Red
}

# ----------------------------------------------------------
# INTERACTIVE SECURITY VALIDATION (SMART RECHECK)
# ----------------------------------------------------------
Write-Host "`n[+] Running interactive security validation (NTLM, LLMNR, LSASS, Kerberos, SMB Signing, Anonymous, Guest)..." -ForegroundColor Cyan

function Check-Once {
    param($CheckName, $Condition, $FixAction, $SecureMsg, $WarningMsg)

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

# --- NTLM ---
try {
    $lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $lvl = (Get-ItemProperty $lsa -ErrorAction SilentlyContinue).LmCompatibilityLevel
    $Condition = ($lvl -ge 5)
    $Fix = { New-ItemProperty -Path $lsa -Name LmCompatibilityLevel -Value 5 -Type DWord -Force | Out-Null }
    Check-Once "NTLM" $Condition $Fix "NTLMv2 only (Level 5)" "Weaker NTLM compatibility detected"
} catch { Add-Result "NTLM" "Warning" "Cannot verify" }

# --- LLMNR ---
try {
    $dnsKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    if (-not (Test-Path $dnsKey)) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT" -Name "DNSClient" -Force | Out-Null
    }
    $multicast = (Get-ItemProperty -Path $dnsKey -ErrorAction SilentlyContinue).EnableMulticast
    $Condition = ($multicast -eq 0)
    $Fix = { New-ItemProperty -Path $dnsKey -Name EnableMulticast -Value 0 -Type DWord -Force | Out-Null }
    Check-Once "LLMNR" $Condition $Fix "Disabled" "Enabled"
} catch { Add-Result "LLMNR" "Warning" "Cannot verify" }

# --- LSASS ---
try {
    $lsaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $ppl = (Get-ItemProperty -Path $lsaKey -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
    $Condition = ($ppl -eq 1)
    $Fix = { New-ItemProperty -Path $lsaKey -Name RunAsPPL -Value 1 -Type DWord -Force | Out-Null }
    Check-Once "LSASS" $Condition $Fix "Protected (PPL mode)" "Not protected (RunAsPPL=0)"
} catch { Add-Result "LSASS" "Warning" "Cannot verify" }

# --- Kerberos Encryption ---
try {
    $kerbPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
    if (-not (Test-Path $kerbPath)) {
        New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "Kerberos" -Force | Out-Null
        New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos" -Name "Parameters" -Force | Out-Null
    }
    $enc = (Get-ItemProperty -Path $kerbPath -Name SupportOldEncryptionTypes -ErrorAction SilentlyContinue).SupportOldEncryptionTypes
    $Condition = ($enc -eq 0)
    $Fix = { New-ItemProperty -Path $kerbPath -Name SupportOldEncryptionTypes -Value 0 -Type DWord -Force | Out-Null }
    Check-Once "Kerberos Encryption" $Condition $Fix "DES/RC4 disabled" "Legacy ciphers enabled"
} catch { Add-Result "Kerberos Encryption" "Warning" "Cannot verify" }
# --- LDAP Client Signing ---
try {
    $ldapKey = "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP"
    if (-not (Test-Path $ldapKey)) {
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services" -Name "LDAP" -Force | Out-Null
    }

    $val = (Get-ItemProperty -Path $ldapKey -Name LDAPClientIntegrity -ErrorAction SilentlyContinue).LDAPClientIntegrity
    # 0=None, 1=Negotiate, 2=Require
    $Condition = ($val -eq 2)

    $Fix = {
        Write-Host "      Applying LDAP client signing fix..." -ForegroundColor Yellow
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" `
            -Name "LDAPClientIntegrity" -Value 2 -Type DWord -Force | Out-Null
        Write-Host "      ✅ LDAP client signing now set to 'Require signing'." -ForegroundColor Green
    }

    Check-Once "LDAP Client Signing" $Condition $Fix "Require signing" "Not required (None or Negotiate)"
} catch {
    Add-Result "LDAP Client Signing" "Warning" "Cannot verify"
}

# --- LDAP Server Signing (optional for Domain Controllers) ---
try {
    $ldapSrvKey = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
    if (Test-Path $ldapSrvKey) {
        $srvVal = (Get-ItemProperty -Path $ldapSrvKey -Name LDAPServerIntegrity -ErrorAction SilentlyContinue).LDAPServerIntegrity
        # 0=None, 1=Negotiate, 2=Require
        $Condition = ($srvVal -eq 2)

        $Fix = {
            Write-Host "      Applying LDAP server signing fix..." -ForegroundColor Yellow
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
                -Name "LDAPServerIntegrity" -Value 2 -Type DWord -Force | Out-Null
            Write-Host "      ✅ LDAP server signing now set to 'Require signing'." -ForegroundColor Green
        }

        Check-Once "LDAP Server Signing" $Condition $Fix "Require signing" "Not required (None or Negotiate)"
    }
} catch {
    Add-Result "LDAP Server Signing" "Warning" "Cannot verify"
}

# --- SMB Signing ---
try {
    $srv = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -ErrorAction SilentlyContinue).RequireSecuritySignature
    $cli = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -ErrorAction SilentlyContinue).RequireSecuritySignature
    $Condition = ($srv -eq 1 -and $cli -eq 1)
    $Fix = {
        Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name RequireSecuritySignature -Value 1 -Type DWord
        Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name RequireSecuritySignature -Value 1 -Type DWord
    }
    Check-Once "SMB Signing" $Condition $Fix "Enforced both client/server" "Not enforced"
} catch { Add-Result "SMB Signing" "Warning" "Cannot verify" }

# --- Anonymous Access ---
try {
    $lsaCtrl = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $anon = (Get-ItemProperty -Path $lsaCtrl -ErrorAction SilentlyContinue).RestrictAnonymous
    $Condition = ($anon -eq 1)
    $Fix = { New-ItemProperty -Path $lsaCtrl -Name RestrictAnonymous -Value 1 -Type DWord -Force | Out-Null }
    Check-Once "Anonymous Access" $Condition $Fix "Restricted" "Unrestricted"
} catch { Add-Result "Anonymous Access" "Warning" "Cannot verify" }

# --- Guest Account ---
try {
    $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    $Condition = ($guest -and -not $guest.Enabled)
    $Fix = { net user guest /active:no | Out-Null }
    Check-Once "Guest Account" $Condition $Fix "Disabled" "Enabled"
} catch { Add-Result "Guest Account" "Warning" "Cannot verify" }

# --- NULL SESSION ENUMERATION HARDENING ---
try {
    Write-Host "`n[+] Checking NULL Session Enumeration Hardening..." -ForegroundColor Cyan

    $lsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $srvPath = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"

    # Collect current values
    $RestrictAnonymousSAM  = (Get-ItemProperty -Path $lsaPath -Name RestrictAnonymousSAM -ErrorAction SilentlyContinue).RestrictAnonymousSAM
    $RestrictAnonymous     = (Get-ItemProperty -Path $lsaPath -Name RestrictAnonymous -ErrorAction SilentlyContinue).RestrictAnonymous
    $RestrictNullSessAccess = (Get-ItemProperty -Path $srvPath -Name RestrictNullSessAccess -ErrorAction SilentlyContinue).RestrictNullSessAccess

    $Condition = ($RestrictAnonymousSAM -eq 1 -and $RestrictAnonymous -eq 1 -and $RestrictNullSessAccess -eq 1)

    $Fix = {
        Write-Host "      Applying NULL Session Enumeration hardening..." -ForegroundColor Yellow
        # 1. Disable anonymous enumeration of local SAM accounts (users/groups)
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -Type DWord -Force
        # 2. Disable anonymous enumeration of SAM accounts and network shares
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1 -Type DWord -Force
        # 3. Restrict anonymous access to Named Pipes and Shares
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -Value 1 -Type DWord -Force
        # 4. Restart Server service to apply
        Restart-Service -Name Server -Force
        Write-Host "      ✅ NULL Session Enumeration hardened successfully." -ForegroundColor Green
    }

    Check-Once "NULL Session Enumeration" $Condition $Fix "All restrictions enforced" "Null session access allowed (insecure)"
}
catch {
    Add-Result "NULL Session Enumeration" "Warning" "Cannot verify"
}

#===========================================================================
#============ Firewall Rules ===============================================
<#
.SYNOPSIS
  BlueShield: Domain-Only Firewall Enforcement Script (idempotent and secure).

.DESCRIPTION
  - Activates and configures the Domain firewall profile only.
  - Disables Private and Public profiles entirely.
  - Allows inbound SMB/RPC ports (445,135,139) from the trusted subnet.
  - Blocks all traffic (any protocol) from untrusted subnets.
  - Ensures default inbound=Block, outbound=Allow.
  - Enables detailed firewall logging.
  - Verifies results with color-coded output.

.NOTES
  Run as Administrator on a domain-joined machine (ideally a DC).
  If Group Policy controls the firewall, local changes may be overridden.
  Author : BlueShield Framework
  Version: 3.5
  Date   : 2025-11-10
#>

# ---------------------------------------------------------------------------
#region Helper Functions
# ---------------------------------------------------------------------------

function Write-Info { param($m) Write-Host "[INFO]  $m" -ForegroundColor Cyan }
function Write-Ok   { param($m) Write-Host "[OK]    $m" -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Write-Err  { param($m) Write-Host "[ERROR] $m" -ForegroundColor Red }

function Ensure-NetFirewallRule {
    param(
        [string]$DisplayName,
        [string]$Direction = "Inbound",
        [string]$Action = "Allow",
        [string]$Protocol = "Any",
        [string]$LocalPort = "",
        [string]$RemoteAddress = "Any",
        [string]$Profile = "Domain",
        [switch]$Enabled = $true
    )

    if (-not $DisplayName) {
        Write-Err "DisplayName parameter cannot be empty."
        return $false
    }

    $existing = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Info "Rule exists: $DisplayName"
        return $true
    }

    try {
        $params = @{
            DisplayName   = $DisplayName
            Direction     = $Direction
            Action        = $Action
            Protocol      = $Protocol
            RemoteAddress = $RemoteAddress
            Profile       = $Profile
            Enabled       = if ($Enabled) { "True" } else { "False" }
            ErrorAction   = "Stop"
        }
        if ($LocalPort -ne "") { $params.LocalPort = $LocalPort }

        New-NetFirewallRule @params | Out-Null
        Write-Ok "Created rule: $DisplayName"
        return $true
    }
    catch {
        Write-Err ("Failed to create rule {0}: {1}" -f $DisplayName, $_.Exception.Message)
        return $false
    }
}

#endregion Helper Functions

# ---------------------------------------------------------------------------
#region Configuration
# ---------------------------------------------------------------------------

$TrustedSubnet   = "192.168.220.0/24"   # internal LAN or management VLAN
$UntrustedSubnet = "10.100.0.0/16"      # red-team or external network

# ✅ Proper rule names defined
$AllowSMB445Name = "Allow_SMB_445_From_$($TrustedSubnet -replace '/','_')"
$AllowSMB135Name = "Allow_RPC_135_From_$($TrustedSubnet -replace '/','_')"
$AllowSMB139Name = "Allow_SMB_139_From_$($TrustedSubnet -replace '/','_')"
$BlockUntrustedName = "Block_All_From_$($UntrustedSubnet -replace '/','_')"

#endregion Configuration

# ---------------------------------------------------------------------------
#region Firewall Initialization
# ---------------------------------------------------------------------------

Write-Info "Starting BlueShield Domain-Only Firewall configuration..."

# Detect if firewall is GPO-controlled
$gpoKey = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall"
if (Test-Path $gpoKey) {
    Write-Warn "Firewall settings appear to be controlled by Group Policy."
    Write-Warn "Local rules may be ignored or overwritten by the domain GPO."
} else {
    Write-Info "No GPO enforcement detected — local configuration will apply."
}

# Ensure Windows Defender Firewall service is running
$svc = Get-Service -Name MpsSvc -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Err "Windows Firewall service (MpsSvc) not found — aborting."
    return
}
if ($svc.Status -ne "Running") {
    Write-Warn "MpsSvc is not running — starting service..."
    try {
        Start-Service MpsSvc -ErrorAction Stop
        Write-Ok "MpsSvc started successfully."
    } catch {
        Write-Err "Failed to start MpsSvc: $($_.Exception.Message)"
        return
    }
}

# Enable and configure Domain profile
Write-Info "Configuring Domain profile defaults..."
Set-NetFirewallProfile -Profile Domain `
    -Enabled True `
    -DefaultInboundAction Block `
    -DefaultOutboundAction Allow `
    -NotifyOnListen False `
    -AllowInboundRules True `
    -AllowLocalFirewallRules True `
    -AllowLocalIPsecRules True `
    -ErrorAction SilentlyContinue
Write-Ok "Domain profile active and hardened."

# Disable Private and Public profiles completely
Write-Info "Disabling Private and Public profiles..."
Set-NetFirewallProfile -Profile Private,Public -Enabled False -ErrorAction SilentlyContinue
Write-Ok "Private and Public profiles disabled."

#endregion Firewall Initialization

# ---------------------------------------------------------------------------
#region Rule Enforcement (Domain Profile Only)
# ---------------------------------------------------------------------------

# 1️⃣ Allow SMB/RPC ports from trusted subnet
Write-Info "Allowing SMB/RPC ports 445,135,139 from trusted subnet $TrustedSubnet ..."
Ensure-NetFirewallRule -DisplayName $AllowSMB445Name `
    -Direction Inbound -Action Allow -Protocol TCP -LocalPort 445 `
    -RemoteAddress $TrustedSubnet -Profile "Domain"

Ensure-NetFirewallRule -DisplayName $AllowSMB135Name `
    -Direction Inbound -Action Allow -Protocol TCP -LocalPort 135 `
    -RemoteAddress $TrustedSubnet -Profile "Domain"

Ensure-NetFirewallRule -DisplayName $AllowSMB139Name `
    -Direction Inbound -Action Allow -Protocol TCP -LocalPort 139 `
    -RemoteAddress $TrustedSubnet -Profile "Domain"

# 2️⃣ Block all inbound traffic (Any protocol) from untrusted subnet
Write-Info "Blocking ALL traffic from untrusted subnet $UntrustedSubnet (Any protocol)..."
Ensure-NetFirewallRule -DisplayName $BlockUntrustedName `
    -Direction Inbound -Action Block -Protocol Any `
    -RemoteAddress $UntrustedSubnet -Profile "Domain"

# 3️⃣ Enable firewall logging
Write-Info "Enabling logging for Domain profile..."
Set-NetFirewallProfile -Profile Domain `
    -LogAllowed True -LogBlocked True `
    -LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall.log" `
    -LogMaxSizeKilobytes 16384 -ErrorAction SilentlyContinue
Write-Ok "Domain profile logging enabled."

#endregion Rule Enforcement

# ---------------------------------------------------------------------------
#region Verification and Reporting
# ---------------------------------------------------------------------------

Write-Host "`n[+] Verification Summary:" -ForegroundColor Cyan
$namesToCheck = @($AllowSMB445Name, $AllowSMB135Name, $AllowSMB139Name, $BlockUntrustedName)

Get-NetFirewallRule -DisplayName $namesToCheck -ErrorAction SilentlyContinue |
    Select DisplayName, Enabled, Action, Profile, Direction |
    Format-Table -AutoSize

Write-Host "`n[+] Firewall Profile States:" -ForegroundColor Cyan
Get-NetFirewallProfile |
    Select Name, Enabled, DefaultInboundAction, DefaultOutboundAction |
    Format-Table -AutoSize

Write-Host "`n[+] Netsh Authoritative Output:" -ForegroundColor Cyan
netsh advfirewall show allprofiles

# ---------------------------------------------------------------------------
# Additional BlueShield Verification (Inbound Policy Check)
# ---------------------------------------------------------------------------

$fw = Get-NetFirewallProfile -Profile Domain
if ($fw.DefaultInboundAction -eq "Block") {
    Write-Ok "Domain Inbound Policy: Block (secure configuration active)"
} else {
    Write-Warn "Domain Inbound Policy: NOT set to Block (weaker posture detected)"
}

if ($fw.DefaultOutboundAction -eq "Allow") {
    Write-Ok "Domain Outbound Policy: Allow (standard configuration active)"
} else {
    Write-Warn "Domain Outbound Policy: NOT set to Allow (restricted mode)"
}

# Optional: confirm logging
if ($fw.LogAllowed -and $fw.LogBlocked) {
    Write-Ok "Firewall logging (Allowed & Blocked) is enabled."
} else {
    Write-Warn "Firewall logging is NOT fully enabled."
}

# ---------------------------------------------------------------------------

Write-Ok "BlueShield Domain-Only Firewall configuration completed successfully."

#endregion Verification and Reporting

# ----------------------------------------------------------
# NETWORK & SERVICE HARDENING
# ----------------------------------------------------------
Write-Host "`n[+] Checking network/service hardening..." -ForegroundColor Cyan
try {
    Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" | ForEach-Object { $_.SetTcpipNetbios(2) | Out-Null }
    Add-Result "NetBIOS" "Secure" "Disabled on all adapters"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value 0xFF -Force
    Add-Result "IPv6" "Secure" "Disabled globally"
}
catch { Add-Result "Network Hardening" "Warning" "Failed" $_.Exception.Message }

# ----------------------------------------------------------
# GPO CREATION
# ----------------------------------------------------------
Write-Host "`n[+] Verifying baseline GPOs..." -ForegroundColor Cyan
try {
    if (-not (Get-GPO -Name "BlueShield_Hardening" -ErrorAction SilentlyContinue)) {
        New-GPO -Name "BlueShield_Hardening" | Out-Null
        Add-Result "GPO" "Secure" "Created BlueShield_Hardening baseline"
    } else {
        Add-Result "GPO" "Secure" "Already exists"
    }
}
catch { Add-Result "GPO" "Warning" "Cannot verify" $_.Exception.Message }

# ----------------------------------------------------------
# IIS HARDENING
# ----------------------------------------------------------
Write-Host "`n[+] Checking IIS configuration..." -ForegroundColor Cyan
try {
    if (Get-WindowsFeature -Name Web-Server -ErrorAction SilentlyContinue) {
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value False -PSPath IIS:\ | Out-Null
        Add-Result "IIS Directory Browsing" "Secure" "Disabled"
    } else {
        Add-Result "IIS" "Secure" "Not installed"
    }
}
catch { Add-Result "IIS Hardening" "Warning" "Cannot verify" $_.Exception.Message }

# ------------------------------
# ZeroLogon / Netlogon Hardening
# ------------------------------

Write-Host "`n[+] Verifying and enforcing Netlogon secure channel settings (Zerologon mitigation)..." -ForegroundColor Cyan

try {
    $netlogonPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"

    # Retrieve current registry values
    $vals = Get-ItemProperty -Path $netlogonPath -ErrorAction SilentlyContinue
    $required = @("RequireStrongKey", "RequireSignOrSeal", "RequireSeal", "RequireSigning", "FullSecureChannelProtection", "DisablePasswordChange")
    $missing = @()

    foreach ($k in $required) {
        # Determine correct expected value
        $expected = if ($k -eq "DisablePasswordChange") { 0 } else { 1 }
        if ($vals.$k -ne $expected) { $missing += $k }
    }

    if (-not $missing) {
        Add-Result "ZeroLogon" "Secure" "All secure Netlogon flags and enforcement configured"
        Write-Host "[OK] ZeroLogon mitigation fully enforced (StrongKey, Seal, Signing, Enforcement, Rotation enabled)" -ForegroundColor Green
    }
    else {
        Add-Result "ZeroLogon" "Warning" "Missing or misconfigured keys: $($missing -join ', ')"
        Write-Host "[!] Missing or weak settings detected: $($missing -join ', ')" -ForegroundColor Yellow
        $apply = Read-Host "Apply full ZeroLogon hardening now? (Y/N)"

        if ($apply -match "^[Yy]$") {
            # Require strong and signed channels
            Set-ItemProperty -Path $netlogonPath -Name "RequireStrongKey" -Type DWord -Value 1 -Force
            Set-ItemProperty -Path $netlogonPath -Name "RequireSignOrSeal" -Type DWord -Value 1 -Force
            Set-ItemProperty -Path $netlogonPath -Name "RequireSeal" -Type DWord -Value 1 -Force
            Set-ItemProperty -Path $netlogonPath -Name "RequireSigning" -Type DWord -Value 1 -Force

            # Enforce Zerologon full protection mode
            Set-ItemProperty -Path $netlogonPath -Name "FullSecureChannelProtection" -Type DWord -Value 1 -Force

            # Ensure computer accounts can rotate passwords
            Set-ItemProperty -Path $netlogonPath -Name "DisablePasswordChange" -Type DWord -Value 0 -Force

            # Restart Netlogon to apply changes
            Restart-Service Netlogon -ErrorAction SilentlyContinue

            Add-Result "ZeroLogon" "Secure" "All mitigations applied and Netlogon restarted"
            Write-Host "[+] Applied full ZeroLogon + Netlogon hardening and restarted service" -ForegroundColor Green
        }
        else {
            Write-Host "[!] Skipped ZeroLogon hardening by user choice" -ForegroundColor Yellow
        }
    }
}
catch {
    Add-Result "ZeroLogon" "Error" "Verification failed: $($_.Exception.Message)"
    Write-Host "[X] Error verifying or applying Netlogon protection: $($_.Exception.Message)" -ForegroundColor Red
}

# ----------------------------------------------------------
# PRIVILEGED AD GROUP REVIEW (INTERACTIVE)
# ----------------------------------------------------------
Write-Host "`n[+] Reviewing privileged AD groups..." -ForegroundColor Cyan
$groups = @("Domain Admins","Enterprise Admins","Administrators","DnsAdmins","Schema Admins","Group Policy Creator Owners","Key Admins","Enterprise Key Admins")
foreach ($group in $groups) {
    try {
        $members = Get-ADGroupMember -Identity $group -ErrorAction Stop
        foreach ($m in $members) {
            if ($m.SamAccountName -notin @("Administrator","Domain Admins","Enterprise Admins")) {
                Write-Host ("[!] Suspicious user in {0}: {1}" -f $group, $m.SamAccountName) -ForegroundColor Yellow
				$ans = Read-Host ("Remove {0} from {1}? (Y/N)" -f $m.SamAccountName, $group)

                if ($ans -match "^[Yy]$") {
                    Remove-ADGroupMember -Identity $group -Members $m -Confirm:$false
                    Add-Result "AD Group: $group" "Secure" "Removed $($m.SamAccountName)" "Manual removal"
                } else {
                    Add-Result "AD Group: $group" "Warning" "Left $($m.SamAccountName) for review"
                }
            }
        }
        if ($members.Count -le 2) { Add-Result "AD Group: $group" "Secure" "No extra members" "Count=$($members.Count)" }
    } catch {
        Add-Result "AD Group: $group" "Warning" "Cannot enumerate" $_.Exception.Message
    }
}
# ----------------------------------------------------------
# ADDITIONAL SECURITY MITIGATIONS (auto-enforce if missing)
# ----------------------------------------------------------

$phaseStart = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Write-Host ("[+] Starting Auto-Enforce Security Phase at $phaseStart") -ForegroundColor Yellow
Write-Host "`n[+] Applying additional domain security mitigations..." -ForegroundColor Cyan

# --- SMBv1 Disable ---
try {
    $smbConfig = Get-SmbServerConfiguration
    if ($smbConfig.EnableSMB1Protocol) {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        Add-Result "SMBv1 Protocol" "Secure" "Disabled SMBv1 on server"
    } else {
        Add-Result "SMBv1 Protocol" "Secure" "Already disabled"
    }
} catch {
    Add-Result "SMBv1 Protocol" "Warning" "Unable to verify or disable" $_.Exception.Message
}

# --- Privileged Group Cleanup (non-interactive enforcement) ---
Write-Host "`n[+] Validating privileged group membership..." -ForegroundColor Cyan
$groups = @("Domain Admins", "Enterprise Admins", "Administrators", "DnsAdmins", "Group Policy Creator Owners", "Schema Admins", "Key Admins", "Enterprise Key Admins")
foreach ($group in $groups) {
    $excludedSamAccountNames = @("Administrator", "Domain Admins", "Enterprise Admins")
    try {
        $members = Get-ADGroupMember -Identity $group | Where-Object { $excludedSamAccountNames -notcontains $_.SamAccountName }
        foreach ($member in $members) {
            try {
                Remove-ADGroupMember -Identity $group -Members $member -Confirm:$false
                Add-Result "Privileged Group Cleanup" "Secure" "Removed $($member.SamAccountName) from $group"
            } catch {
                Add-Result "Privileged Group Cleanup" "Warning" "Failed to remove $($member.SamAccountName) from $group" $_.Exception.Message
            }
        }
    } catch {
        Add-Result "Privileged Group Cleanup" "Warning" "Cannot enumerate $group" $_.Exception.Message
    }
}

# --- Enforce Kerberos Pre-Authentication ---
try {
    Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Set-ADAccountControl -DoesNotRequirePreAuth $false
    Add-Result "Kerberos PreAuth" "Secure" "Pre-authentication enforced for all users"
} catch {
    Add-Result "Kerberos PreAuth" "Warning" "Failed to enforce" $_.Exception.Message
}

# --- Disable Guest Account ---
try {
    $guestAccount = Get-ADUser -Identity "Guest" -ErrorAction Stop
    if ($guestAccount.Enabled) {
        Disable-ADAccount -Identity $guestAccount.SamAccountName
        Add-Result "Guest Account" "Secure" "Disabled guest account"
    } else {
        Add-Result "Guest Account" "Secure" "Already disabled"
    }
} catch {
    Add-Result "Guest Account" "Warning" "Failed to disable" $_.Exception.Message
}

# --- Disable Print Spooler ---
try {
    $spool = Get-Service -Name "Spooler" -ErrorAction Stop
    if ($spool.Status -ne "Stopped") { Stop-Service -Name "Spooler" -ErrorAction SilentlyContinue }
    Set-Service -Name "Spooler" -StartupType Disabled
    Add-Result "Print Spooler" "Secure" "Service disabled"
} catch {
    Add-Result "Print Spooler" "Warning" "Failed to disable" $_.Exception.Message
}

# --- Zerologon FullSecureChannelProtection ---
try {
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v FullSecureChannelProtection /t REG_DWORD /d 1 /f | Out-Null
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    $regName = "vulnerablechannelallowlist"
    if (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $regPath -Name $regName -Force | Out-Null
        Add-Result "ZeroLogon Mitigation" "Secure" "Removed vulnerablechannelallowlist"
    } else {
        Add-Result "ZeroLogon Mitigation" "Secure" "FullSecureChannelProtection active"
    }
} catch {
    Add-Result "ZeroLogon Mitigation" "Warning" "Failed to apply" $_.Exception.Message
}

# --- noPAC Mitigation (MachineAccountQuota = 0) ---
try {
    $domain = Get-ADDomain -Identity $env:USERDNSDOMAIN
    if ($domain["ms-DS-MachineAccountQuota"] -ne 0) {
        Set-ADDomain -Identity $env:USERDNSDOMAIN -Replace @{"ms-DS-MachineAccountQuota" = "0"} | Out-Null
        Add-Result "noPAC Mitigation" "Secure" "MachineAccountQuota set to 0"
    } else {
        Add-Result "noPAC Mitigation" "Secure" "Already set to 0"
    }
} catch {
    Add-Result "noPAC Mitigation" "Warning" "Failed to enforce" $_.Exception.Message
}
# --- LDAP Signing & Channel Binding ---
try {
    # Require LDAP signing
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LDAPServerIntegrity /t REG_DWORD /d 2 /f | Out-Null
    # Require LDAP channel binding (LDAPS)
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LdapEnforceChannelBinding /t REG_DWORD /d 2 /f | Out-Null
    Add-Result "LDAP Hardening" "Secure" "LDAP signing and channel binding enforced"
} catch {
    Add-Result "LDAP Hardening" "Warning" "Failed to enforce" $_.Exception.Message
}

# --- LSASS RunAsPPL Enforcement ---
try {
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f | Out-Null
    Add-Result "LSASS Protection" "Secure" "RunAsPPL enforced (Credential theft prevention)"
} catch {
    Add-Result "LSASS Protection" "Warning" "Failed to enforce" $_.Exception.Message
}
# --- WDigest Credential Cache Disable ---
try {
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f | Out-Null
    Add-Result "WDigest Mitigation" "Secure" "Credential caching disabled"
} catch {
    Add-Result "WDigest Mitigation" "Warning" "Failed to enforce" $_.Exception.Message
}

# --- SMB Signing Enforce ---
try {
    Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force | Out-Null
    Set-SmbClientConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force | Out-Null
    Add-Result "SMB Signing" "Secure" "Server and client signing enforced"
} catch {
    Add-Result "SMB Signing" "Warning" "Failed to enforce" $_.Exception.Message
}

# ----------------------------------------------------------
# DISABLE UNNECESSARY NETWORK SERVICES
# ----------------------------------------------------------
function Disable-Unnecessary-Services {
    Write-Host "`n[+] Disabling unnecessary network services..." -ForegroundColor Cyan
    try {
        $activeAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }

        foreach ($adapter in $activeAdapters) {
            # Disable IPv6
            Disable-NetAdapterBinding -Name $adapter.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue

            # Optional: Disable File and Printer Sharing (uncomment if desired)
            # Disable-NetAdapterBinding -Name $adapter.Name -ComponentID ms_server -ErrorAction SilentlyContinue
        }

        # Disable NetBIOS over TCP/IP (NetbiosOptions = 2)
        $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
        foreach ($adapter in $adapters) {
            $adapter.SetTcpipNetbios(2) | Out-Null
        }

        Add-Result "Disable Unnecessary Services" "Secure" "IPv6 and NetBIOS disabled" "All active adapters"
        Write-Host " IPv6 and NetBIOS disabled on active adapters." -ForegroundColor Green
    } catch {
        Add-Result "Disable Unnecessary Services" "Warning" "Failed" $_.Exception.Message
        Write-Host ("  Error disabling unnecessary services: {0}" -f $_.Exception.Message) -ForegroundColor Red
    }
}

# Execute the function
Disable-Unnecessary-Services


# ----------------------------------------------------------
# CLEAR POWERSHELL HISTORY
# ----------------------------------------------------------
Write-Host "`n[+] Clearing PowerShell history..." -ForegroundColor Cyan
try {
    # Clear the current PowerShell session history
    Clear-History -ErrorAction SilentlyContinue

    # Delete persistent history file from disk
    $historyPath = (Get-PSReadlineOption).HistorySavePath
    if (Test-Path $historyPath) {
        Remove-Item $historyPath -Force -ErrorAction SilentlyContinue
        Add-Result "PowerShell History" "Secure" "Cleared persistent history file" $historyPath
    } else {
        Add-Result "PowerShell History" "Secure" "No history file found"
    }

    Write-Host "PowerShell history cleared successfully." -ForegroundColor Green
}
catch {
    Add-Result "PowerShell History" "Warning" "Failed to clear PowerShell history" $_.Exception.Message
    Write-Host "⚠ Error clearing PowerShell history: $($_.Exception.Message)" -ForegroundColor Red
}


# FINAL SUMMARY
# ----------------------------------------------------------
Write-Host "`n=== Generating BlueShield Summary ===" -ForegroundColor Cyan
$summaryPath = "C:\BlueShield_Summary_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss")
$Results | Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8
$Results | Select Check,Status,Info,Value | Format-Table -AutoSize

$ok  = ($Results | Where {$_.Status -eq "Secure"}).Count
$warn= ($Results | Where {$_.Status -eq "Warning"}).Count
$crit= ($Results | Where {$_.Status -eq "Critical"}).Count

Write-Host ""
Write-Host "========= BlueShield Score Summary =========" -ForegroundColor Cyan
Write-Host ("[OK]    Secure:   {0}" -f $ok) -ForegroundColor Green
Write-Host ("[WARN]  Warning:  {0}" -f $warn) -ForegroundColor Yellow
Write-Host ("[CRIT]  Critical: {0}" -f $crit) -ForegroundColor Red
Write-Host ("-------------------------------------------") -ForegroundColor Cyan
Write-Host ("Total Checks: {0}" -f $Results.Count) -ForegroundColor White
Write-Host ("Report saved to {0}" -f $summaryPath) -ForegroundColor Cyan
Write-Host "===========================================" -ForegroundColor Cyan

