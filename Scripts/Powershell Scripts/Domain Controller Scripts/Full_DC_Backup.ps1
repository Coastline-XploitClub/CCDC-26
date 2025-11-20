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
# FULL DOMAIN CONTROLLER BACKUP (DC_Backup)
# ----------------------------------------------------------

Write-Host "`n[+] Starting FULL Domain Controller backup..." -ForegroundColor Cyan

# Base folder structure
$BackupRoot = "C:\BlueShield_Backups"
$DCBackup   = Join-Path $BackupRoot "DC_Backup"

# Create root structure
foreach ($folder in @($BackupRoot, $DCBackup)) {
    if (-not (Test-Path $folder)) {
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        Write-Warn "Created folder: $folder"
    }
}

# --- GROUP POLICY BACKUP ---
$GpoPath = Join-Path $DCBackup "GPOs"
New-Item -ItemType Directory -Path $GpoPath -Force | Out-Null
Write-Info "Backing up GPOs..."
Backup-Gpo -All -Path $GpoPath -ErrorAction Stop
Write-Ok "GPO backup complete -> $GpoPath"

# --- NTDS IFM BACKUP ---
$NtdsPath = Join-Path $DCBackup "NTDS_IFM"
New-Item -ItemType Directory -Path $NtdsPath -Force | Out-Null
Write-Info "Backing up AD database (IFM)..."
ntdsutil "activate instance ntds" "ifm" "create full $NtdsPath" quit quit | Out-Null
Write-Ok "NTDS IFM backup completed -> $NtdsPath"

# --- SYSVOL BACKUP ---
$SysvolPath = Join-Path $DCBackup "SYSVOL"
New-Item -ItemType Directory -Path $SysvolPath -Force | Out-Null
Write-Info "Backing up SYSVOL..."
Copy-Item "C:\Windows\SYSVOL" -Destination $SysvolPath -Recurse -Force
Write-Ok "SYSVOL backup completed -> $SysvolPath"

# --- REGISTRY HIVES ---
$RegPath = Join-Path $DCBackup "Registry"
New-Item -ItemType Directory -Path $RegPath -Force | Out-Null
Write-Info "Exporting registry hives..."

reg export HKLM\SYSTEM   (Join-Path $RegPath "SYSTEM.reg")   /y
reg export HKLM\SOFTWARE (Join-Path $RegPath "SOFTWARE.reg") /y
reg export HKLM\SAM      (Join-Path $RegPath "SAM.reg")      /y

Write-Ok "Registry hives exported -> $RegPath"

# --- ADCS BACKUP ---
$CAPath = Join-Path $DCBackup "ADCS"
New-Item -ItemType Directory -Path $CAPath -Force | Out-Null
Write-Info "Backing up AD Certificate Services..."

if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc") {
    try {
        certutil -backupDB (Join-Path $CAPath "DB") | Out-Null
        certutil -backupKey (Join-Path $CAPath "Keys") | Out-Null
        reg export HKLM\SYSTEM\CurrentControlSet\Services\CertSvc (Join-Path $CAPath "CertSvc.reg") /y | Out-Null
        Write-Ok "ADCS backup completed -> $CAPath"
    }
    catch {
        Write-Warn "ADCS backup failed: $($_.Exception.Message)"
    }
}
else {
    Write-Warn "Certificate Services not installed - skipping ADCS."
}

# --- SECURITY POLICY ---
$SecPath = Join-Path $DCBackup "SecurityPolicy"
New-Item -ItemType Directory -Path $SecPath -Force | Out-Null
Write-Info "Exporting security policy..."
secedit /export /cfg (Join-Path $SecPath "SecurityPolicy.inf") | Out-Null
Write-Ok "Security policy exported -> $SecPath"

# --- TASK SCHEDULER ---
$TaskPath = Join-Path $DCBackup "Tasks"
New-Item -ItemType Directory -Path $TaskPath -Force | Out-Null
Write-Info "Backing up scheduled tasks..."
Copy-Item "C:\Windows\System32\Tasks" -Destination $TaskPath -Recurse -Force
Write-Ok "Scheduled tasks exported -> $TaskPath"

# --- SYSTEM INFO + HOTFIXES ---
Write-Info "Exporting system info..."
systeminfo | Out-File (Join-Path $DCBackup "SystemInfo.txt")
Get-HotFix | Out-File (Join-Path $DCBackup "InstalledUpdates.txt")
Write-Ok "System info exported"

# --- EVENT LOGS ---
$EvtPath = Join-Path $DCBackup "EventLogs"
New-Item -ItemType Directory -Path $EvtPath -Force | Out-Null
Write-Info "Exporting event logs..."

foreach ($log in @("Application", "System", "Security", "Directory Service", "DNS Server")) {
    wevtutil epl $log (Join-Path $EvtPath ("{0}.evtx" -f $log.Replace(' ','_')))
}
Write-Ok "Event logs exported -> $EvtPath"

# --- WMI INVENTORY ---
$WmiPath = Join-Path $DCBackup "WMI_Inventory"
New-Item -ItemType Directory -Path $WmiPath -Force | Out-Null
Write-Info "Creating WMI inventory..."

Get-WmiObject Win32_ComputerSystem |
    Select Name, Manufacturer, Model, NumberOfProcessors, TotalPhysicalMemory |
    Export-Csv (Join-Path $WmiPath "System.csv") -NoTypeInformation

Get-WmiObject Win32_Service |
    Select Name, DisplayName, StartMode, State, PathName |
    Export-Csv (Join-Path $WmiPath "Services.csv") -NoTypeInformation

Write-Ok "WMI inventory exported -> $WmiPath"

# ----------------------------------------------------------
# DNS BACKUP (DNS_Backup)
# ----------------------------------------------------------

Write-Host "`n[+] Starting DNS backup..." -ForegroundColor Cyan

$DNSRoot   = "C:\BlueShield_Backups\DNS_Backup"
$DNSLatest = Join-Path $DNSRoot "Latest"

New-Item -ItemType Directory -Path $DNSLatest -Force | Out-Null
Write-Info "Backing up DNS -> $DNSLatest"

$zones = Get-DnsServerZone -ErrorAction Stop

# Save manifest
$zones |
    Select ZoneName, ZoneType, IsDsIntegrated |
    Export-Csv (Join-Path $DNSLatest "zones-list.csv") -NoTypeInformation

foreach ($zone in $zones) {

    $zoneName = $zone.ZoneName
    $safeName = ($zoneName -replace '[\\/:*?"<>|]', '_') + ".dns"
    $dest     = Join-Path $DNSLatest $safeName

    Write-Info "Exporting zone: $zoneName"

    # Always use dnscmd on Server 2016
    dnscmd /zoneexport $zoneName $safeName | Out-Null

    $sysFile = Join-Path $env:windir "System32\dns\$safeName"

    if (Test-Path $sysFile) {
        Move-Item -Path $sysFile -Destination $dest -Force
        Write-Ok "Exported -> $dest"
    }
    else {
        Write-Warn "Zone $zoneName did not produce a file (AD-integrated). Normal for Server 2016."
    }
}

# ----------------------------------------------------------
# FIREWALL BACKUP (Firewall folder)
# ----------------------------------------------------------

Write-Info "Backing up firewall configuration..."

$FwRoot = "C:\BlueShield_Backups\Firewall"
New-Item -ItemType Directory -Path $FwRoot -Force | Out-Null

$fwFile = Join-Path $FwRoot ("Firewall_{0}.wfw" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
netsh advfirewall export $fwFile | Out-Null

Write-Ok "Firewall exported: $fwFile"
