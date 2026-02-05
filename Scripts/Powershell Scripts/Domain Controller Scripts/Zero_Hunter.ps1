# ==========================================================
# Zero_Hunter.ps1
# Zerologon + DNS + RDP Hunter (Time-Range Enhanced)
# ==========================================================

$BasePort = 8888
$JsonPath = "C:\IR\zero_hunter_data.json"

if (!(Test-Path "C:\IR")) {
    New-Item -Path "C:\IR" -ItemType Directory -Force | Out-Null
}

# ------------------ HELPERS ------------------

function Get-AvailablePort {
    param ($port)
    while ($true) {
        if (-not (Test-NetConnection 127.0.0.1 -Port $port -InformationLevel Quiet)) { return $port }
        $port++
    }
}

function Normalize-IP {
    param ($ip)
    if ($ip -match "::ffff:(\d+\.\d+\.\d+\.\d+)") { return $Matches[1] }
    return $ip
}

function Get-IPVersion {
    param ($ip)
    if ($ip -match ":") { "IPv6" }
    elseif ($ip -match "\.") { "IPv4" }
    else { "UNKNOWN" }
}

function Is-RealRemoteIP {
    param ($ip)
    if ([string]::IsNullOrEmpty($ip) -or
        $ip -eq "::1" -or
        $ip -like "fe80:*" -or
        $ip -eq "0.0.0.0" -or
        $ip -eq "127.0.0.1") { return $false }
    return $true
}

function Format-TimeStamp {
    param ($dt)
    if ($dt -is [DateTime]) {
        return $dt.ToString("yyyy-MM-dd HH:mm:ss.fff zzz")
    }
    return (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff zzz")
}

# ------------------ DATA COLLECTION ------------------

function Update-ZeroHunterData {
    param ([int]$Hours = 24)

    $StartTime = (Get-Date).AddHours(-$Hours)
    $Findings = @()

  # -------- NETWORK (ACTIVE) --------
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
    Where-Object {
        $_.LocalPort -in 135,445,3389 -or
        ($_.LocalPort -ge 49664 -and $_.LocalPort -le 49670)
    } |
    Where-Object {
        # Exclude reverse shells (handled below)
        -not ($_.LocalPort -ge 49152 -and $_.RemotePort -le 5000)
    } |
    ForEach-Object {

        $rip = Normalize-IP $_.RemoteAddress
        if (-not (Is-RealRemoteIP $rip)) { return }

        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue

        $Findings += [PSCustomObject]@{
            time    = Format-TimeStamp (Get-Date)
            ip      = $rip
            ip_type = Get-IPVersion $rip
            phase   = if ($_.LocalPort -eq 3389) { "RDP" } else { "NETWORK" }
            id_pid  = "PID $($_.OwningProcess)"
            desc    = "Process: $($proc.Name) | LocalPort: $($_.LocalPort) | RemotePort: $($_.RemotePort)"
            raw     = ($_ | Out-String)
        }
    }

# -------- METERPRETER / REVERSE SHELL DETECTION --------
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
    Where-Object {
        # High local port (ephemeral) to low remote port (listener)
        $_.LocalPort -ge 49152 -and
        $_.RemotePort -le 5000 -and

        # Ignore loopback / invalid addresses
        $_.RemoteAddress -notin @("127.0.0.1","::1","0.0.0.0")
    } |
    ForEach-Object {

        # Normalize attacker IP
        $rip = Normalize-IP $_.RemoteAddress

        # Resolve owning process
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        if (-not $proc) { return }

        # 🔑 Critical filter: only suspicious execution contexts
        $procName = $proc.Name
        # Filter benign svchost HTTPS traffic
        if ($procName -eq 'svchost' -and $_.RemotePort -eq 443) { return }

        # Keep only suspicious execution contexts
        if ($procName -notmatch 'powershell|cmd|rundll32|svchost') { return }

        # If we reach here → HIGH CONFIDENCE C2
        $Findings += [PSCustomObject]@{
            time    = Format-TimeStamp (Get-Date)
            ip      = $rip
            ip_type = Get-IPVersion $rip
            phase   = "SUCCESS"
            id_pid  = "C2"
            desc    = "Reverse Shell / C2 Connection | Process: $procName | LocalPort: $($_.LocalPort) → RemotePort: $($_.RemotePort)"
            raw     = ($_ | Out-String)
        }
    }

    # -------- RDP EVENTS --------
    Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=$StartTime} -ErrorAction SilentlyContinue |
        Where-Object { $_.Properties[8].Value -eq 10 } |
        ForEach-Object {
            $ip = Normalize-IP $_.Properties[18].Value
            if (Is-RealRemoteIP $ip) {
                $Findings += [PSCustomObject]@{
                    time   = Format-TimeStamp $_.TimeCreated
                    ip     = $ip
                    ip_type= Get-IPVersion $ip
                    phase  = "RDP"
                    id_pid = "4624"
                    desc   = "RDP SUCCESS | User: $($_.Properties[5].Value)"
                    raw    = $_.Message
                }
            }
        }

    # -------- DNS / ZEROLOGON --------
    $LogTasks = @(
        @{Log='System'; ID=7036; Phase='DNS'; Match='DNS Server service.*stopped'; Desc='DNS Stopped'},
        @{Log='System'; ID=7040; Phase='DNS'; Match='DNS Server service'; Desc='DNS Startup Modified'},
	@{Log='System'; ID=7045; Phase='ATTEMPT'; Match=$null; Desc='Service Installed (Possible Metasploit / PsExec)'},
        @{Log='System'; ID=5805; Phase='ATTEMPT'; Match=$null; Desc='Netlogon Auth Failure'}
    )

    foreach ($task in $LogTasks) {
        Get-WinEvent -FilterHashtable @{LogName=$task.Log; ID=$task.ID; StartTime=$StartTime} -ErrorAction SilentlyContinue |
            ForEach-Object {
                if ($null -eq $task.Match -or $_.Message -match $task.Match) {
                    $Findings += [PSCustomObject]@{
                        time   = Format-TimeStamp $_.TimeCreated
                        ip     = "LOCAL"
                        ip_type= "SYSTEM"
                        phase  = $task.Phase
                        id_pid = $task.ID
                        desc   = $task.Desc
                        raw    = $_.Message
                    }
                }
            }
    }

    # -------- ZEROLOGON SUCCESS --------
    Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4742; StartTime=$StartTime} -ErrorAction SilentlyContinue |
        ForEach-Object {
            $xml = [xml]$_.ToXml()
            if (($xml.Event.EventData.Data | Where-Object {$_.Name -eq "SubjectUserName"})."#text" -eq "ANONYMOUS LOGON") {
                $Findings += [PSCustomObject]@{
                    time   = Format-TimeStamp $_.TimeCreated
                    ip     = "CORRELATED"
                    ip_type= "UNKNOWN"
                    phase  = "SUCCESS"
                    id_pid = "4742"
                    desc   = "CRITICAL: Computer Password Reset"
                    raw    = $_.Message
                }
            }
        }

    # -------- EMPTY SAFE --------
    if (-not $Findings -or $Findings.Count -eq 0) {
        $Findings = @(
            [PSCustomObject]@{
                time="N/A"; ip="N/A"; ip_type="N/A"; phase="INFO"; id_pid="N/A"
                desc="No events detected in selected time range"
                raw="EMPTY"
            }
        )
    }

    [PSCustomObject]@{
        dc_name = $env:COMPUTERNAME
        scan_time = Format-TimeStamp (Get-Date)
        lookback_hrs = $Hours
        findings = $Findings | Sort-Object time -Descending
    } | ConvertTo-Json -Depth 6 | Out-File $JsonPath -Encoding UTF8
}

# ------------------ WEB SERVER ------------------

$Port = Get-AvailablePort $BasePort
Update-ZeroHunterData -Hours 24

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://127.0.0.1:$Port/")
$listener.Start()

Write-Host "[+] Zero Hunter Dashboard: http://127.0.0.1:$Port" -ForegroundColor Green

try {
while ($listener.IsListening) {
    $ctx = $listener.GetContext()

    if ($ctx.Request.Url.LocalPath -eq "/refresh") {
        $h = $ctx.Request.QueryString["h"]
        if ([string]::IsNullOrEmpty($h)) { $h = 24 }
        Update-ZeroHunterData -Hours ([int]$h)
        $ctx.Response.Redirect("/")
        $ctx.Response.Close()
        continue
    }

    $filter = $ctx.Request.QueryString["filter"]
    if ([string]::IsNullOrEmpty($filter)) { $filter = "ALL" }

    $data = Get-Content $JsonPath -Raw | ConvertFrom-Json
    $rows = ""

    foreach ($f in $data.findings) {
        if ($filter -ne "ALL" -and $filter -ne $f.phase) { continue }

        $colors = @{
            NETWORK="#6a5acd"; ATTEMPT="#ff8c00"; SUCCESS="#e63946"
            DNS="#2a9d8f"; RDP="#1f7a8c"; INFO="#444"
        }

        $id = [guid]::NewGuid().ToString()

        $rows += @"
<tr class="evt" style="background:$($colors[$f.phase])" onclick="toggle('$id')">
<td>$($f.time)</td><td>$($f.ip)</td><td>$($f.phase)</td><td>$($f.id_pid)</td><td>$($f.desc)</td>
</tr>
<tr id="$id" class="detail">
<td colspan="5">
<b>IP Type:</b> $($f.ip_type)<br><br>
<pre style="white-space:pre-wrap;font-size:0.75em">$($f.raw)</pre>
</td>
</tr>
"@
    }

    $html = @"
<html><head><style>
body{background:#0a0a0a;color:#eee;font-family:Segoe UI;padding:20px}
table{width:100%;border-collapse:collapse;margin-top:15px}
th,td{border:1px solid #333;padding:10px;font-size:0.85em}
th{background:#111;color:#00ffff}
tr.evt:hover{filter:brightness(1.15)}
tr.detail{display:none;background:#111}
.btn{padding:6px 12px;border-radius:4px;text-decoration:none;font-weight:bold;color:#fff;display:inline-block;margin:2px;font-size:0.8em}
.ALL{background:#2c2c2c} .NETWORK{background:#6a5acd} .ATTEMPT{background:#ff8c00} .SUCCESS{background:#e63946} .DNS{background:#2a9d8f} .RDP{background:#1f7a8c}
.timerange{background:#1a1a1a;padding:10px;border-radius:5px;border:1px solid #333;margin-bottom:15px}
</style></head>
<body>
<h2>Zero Hunter Dashboard</h2>
<div class="timerange">
DC: <b>$($data.dc_name)</b> |
Window: <b>$($data.lookback_hrs) hours</b> |
Updated: <b>$($data.scan_time)</b><br><br>
Scan Range:
<a class="btn ALL" href="/refresh?h=1">1h</a>
<a class="btn ALL" href="/refresh?h=4">4h</a>
<a class="btn ALL" href="/refresh?h=24">24h</a>
</div>

<a class="btn ALL" href="/?filter=ALL">ALL</a>
<a class="btn NETWORK" href="/?filter=NETWORK">NETWORK</a>
<a class="btn ATTEMPT" href="/?filter=ATTEMPT">ATTEMPTS</a>
<a class="btn SUCCESS" href="/?filter=SUCCESS">SUCCESS</a>
<a class="btn DNS" href="/?filter=DNS">DNS</a>
<a class="btn RDP" href="/?filter=RDP">RDP</a>

<table>
<tr><th>Timestamp</th><th>IP</th><th>Phase</th><th>ID</th><th>Summary</th></tr>
$rows
</table>

<script>
function toggle(id){
    var r=document.getElementById(id);
    r.style.display=r.style.display==="table-row"?"none":"table-row";
}
</script>
</body></html>
"@

    $buf = [System.Text.Encoding]::UTF8.GetBytes($html)
    $ctx.Response.ContentLength64 = $buf.Length
    $ctx.Response.OutputStream.Write($buf,0,$buf.Length)
    $ctx.Response.OutputStream.Close()
}}
finally {
    $listener.Stop()
    $listener.Close()
}
