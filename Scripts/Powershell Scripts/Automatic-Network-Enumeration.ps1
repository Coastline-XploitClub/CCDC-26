# AutoScript.ps1
# Automatically run Windows hardening checks and export output files to Desktop
# Timestamped files, Windows 7 compatible (uses Get-WmiObject / netsh / netstat)

# Helpers
$desktop = [Environment]::GetFolderPath('Desktop')
$timestamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$folderPath = "$env:USERPROFILE\Desktop\Enumeration_$timestamp"
$logFile = Join-Path $folderPath "$timestamp.log"

# Create the directory
New-Item -ItemType Directory -Force -Path $folderPath | Out-Null

Write-Host "Saving all enumeration results to: $folderPath`n"

function Log {
    param([string]$msg)
    $time = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[$time] $msg"
    $line | Out-File -FilePath $logFile -Append -Encoding UTF8
    Write-Host $line
}

# Ensure script start logged
Log "Starting automatic run."

# 1) System info
try {
    $out = Join-Path  $folderPath "systeminfo-$timestamp.txt"
    Log "Collecting system information -> $out"
    systeminfo | Out-String | Out-File -FilePath $out -Encoding UTF8
} catch {
    Log "ERROR collecting system info: $_"
}

# 2) Network interfaces and IPs
try {
    $out = Join-Path $folderPath "network_interfaces-$timestamp.txt"
    Log "Collecting network interfaces -> $out"
    Get-WmiObject Win32_NetworkAdapterConfiguration |
      Where-Object { $_.IPEnabled -eq $true } |
      Select-Object Description, IPAddress, MACAddress |
      Format-Table -AutoSize | Out-String | Out-File -FilePath $out -Encoding UTF8
} catch {
    Log "ERROR collecting network interfaces: $_"
}

# 3) Open ports and associated processes
try {
    $out = Join-Path $folderPath "open_ports-$timestamp.txt"
    Log "Collecting open ports (netstat) -> $out"
    $results = New-Object System.Collections.Generic.List[string]
    netstat -ano | Select-String "LISTENING" | ForEach-Object {
        $line = $_.ToString().Trim()
        $parts = $line -split '\s+'
        if ($parts.Count -ge 5) {
            $localEndpoint = $parts[1]
            $port = ($localEndpoint -split ':')[-1]
            $processId = $parts[-1]
            $process = Get-WmiObject Win32_Process -Filter "ProcessId=$processId" -ErrorAction SilentlyContinue
            $procName = if ($process) { $process.Name } else { 'N/A' }
            $results.Add("Port: $port - PID: $processId - Process: $procName")
        }
    }
    if ($results.Count -eq 0) { $results.Add("No LISTENING lines found or netstat returned nothing.") }
    $results | Out-File -FilePath $out -Encoding UTF8
} catch {
    Log "ERROR collecting open ports: $_"
}

# 4) Running services
try {
    $out = Join-Path $folderPath "running-services-$timestamp.txt"
    Log "Collecting running services -> $out"
    Get-WmiObject Win32_Service |
      Where-Object { $_.State -eq 'Running' } |
      Select-Object Name, DisplayName, StartMode, ProcessId |
      Format-Table -AutoSize | Out-String | Out-File -FilePath $out -Encoding UTF8
} catch {
    Log "ERROR collecting running services: $_"
}

# 5) User and account information
try {
    $outUsers = Join-Path $folderPath "local_users-$timestamp.txt"
    $outGroups = Join-Path $folderPath "local_groups-$timestamp.txt"
    $outAccounts = Join-Path $folderPath "account_policies-$timestamp.txt"
    Log "Collecting users -> $outUsers"
    net user | Out-String | Out-File -FilePath $outUsers -Encoding UTF8

    Log "Collecting local groups -> $outGroups"
    net localgroup | Out-String | Out-File -FilePath $outGroups -Encoding UTF8

    Log "Collecting account policies -> $outAccounts"
    net accounts | Out-String | Out-File -FilePath $outAccounts -Encoding UTF8
} catch {
    Log "ERROR collecting user/account info: $_"
}

# 6) Scheduled tasks
try {
    $out = Join-Path $folderPath "scheduledtasks-$timestamp.txt"
    Log "Collecting scheduled tasks -> $out"
    schtasks /query /fo LIST | Out-String | Out-File -FilePath $out -Encoding UTF8
} catch {
    Log "ERROR collecting scheduled tasks: $_"
}

# 7) Running processes
try {
    $out = Join-Path $folderPath "running-processes-$timestamp.txt"
    Log "Collecting running processes -> $out"
    Get-Process |
      Sort-Object CPU -Descending |
      Select-Object Id, Name, CPU, StartTime |
      Format-Table -AutoSize | Out-String | Out-File -FilePath $out -Encoding UTF8
} catch {
    Log "ERROR collecting running processes: $_"
}

# 8) Firewall rules
try {
    $out = Join-Path $folderPath "firewall-rules-$timestamp.txt"
    Log "Collecting firewall rules -> $out"
    netsh advfirewall firewall show rule name=all | Out-String | Out-File -FilePath $out -Encoding UTF8
} catch {
    Log "ERROR collecting firewall rules: $_"
}

# 9) Running .exe processes (guards for $null Path)
try {
    $out = Join-Path $folderPath "exe-processes-$timestamp.txt"
    Log "Collecting running .exe processes -> $out"
    Get-Process |
      Where-Object { $_.Path -and $_.Path -like '*.exe' } |
      Select-Object Name, Path, Id, CPU |
      Format-Table -AutoSize | Out-String | Out-File -FilePath $out -Encoding UTF8
} catch {
    Log "ERROR collecting .exe processes: $_"
}

# 10) (Legacy) Open ports simple netstat dump (optional additional view)
try {
    $out = Join-Path $folderPath "netstat_raw-$timestamp.txt"
    Log "[10/11] Writing raw netstat -> $out"
    netstat -ano | Out-File -FilePath $out -Encoding UTF8
} catch {
    Log "ERROR writing raw netstat: $_"
}

#11 Get AD-Users

$ADUsers = Join-Path $folderPath "DomainUsers-$timestamp.txt"
Log "[11/11] Writing Domain Users -> $out"
Get-ADUser -Filter * | Select-Object Name, DistinguishedName, ObjectClass, SamAccountName, EmailAddress, Department | Out-File -FilePath $ADUsers -Encoding UTF8


Log "Automatic run completed. Files saved to Desktop with timestamp $timestamp"
Log "Log file: $logFile"