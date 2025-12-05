# =====================================================================
# BlueShield Dashboard v25.20 (Competition Master)
# Features:
#   • TIME: Strict 9:00 AM - 5:00 PM Competition Window
#   • VISUALS: Pie Chart Restored (Security vs DNS)
#   • DEFENSE: Zerologon & Concurrent Admin Detection Active
#   • STABILITY: Includes all previous crash fixes
#
# RUN AS ADMINISTRATOR
# =====================================================================

Add-Type -AssemblyName System.Web

# -----------------------------
# 0. CONFIGURATION
# -----------------------------
$Port = 8888
$CompStartHour = 9     # 9:00 AM
$CompEndHour   = 17    # 5:00 PM

# PATH TO TEXT LOG
$DnsTextLogPath = "C:\dns.log" 

# TRUSTED NETWORK
$TrustedNetwork = "192.168.220." 

# ADMIN USERS (Watchlist)
$AdminUsers = @("administrator", "admin", "cesar_la")
$DCName = $env:COMPUTERNAME 

# Noise Filters
$NoiseFilter = @("NT AUTHORITY\SYSTEM", "Window Manager", "192.168.220.70")
$SusKeywords = "powershell|cmd\.exe|psexec|mimikatz|whoami|net\.exe|vssadmin|bitsadmin|certutil"

# -----------------------------
# GLOBAL STATE
# -----------------------------
$Global:AckList      = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
$SecurityEvents      = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
$DnsEvents           = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
$CriticalEvents      = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
$Feed                = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
$Global:ProcessedIDs = [System.Collections.Generic.HashSet[string]]::new()

$Global:ActiveAdminSessions = [System.Collections.Hashtable]::Synchronized(@{})

# -----------------------------
# 1. SETUP & TIME CALC
# -----------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Error "Run as Admin"; exit }

try { $z=Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue; if($z){Stop-Process -Id $z.OwningProcess -Force} } catch {}

# CALCULATE 9AM - 5PM WINDOW
$Today = Get-Date -Hour 0 -Minute 0 -Second 0
$CompStart = $Today.AddHours($CompStartHour)
$CompEnd   = $Today.AddHours($CompEndHour)
$Global:LastPoll = $CompStart # Start fetching from 9 AM

Write-Host "===== BlueShield v25.20 (Master) =====" -ForegroundColor Cyan
Write-Host " [Time] Window: $CompStart to $CompEnd" -ForegroundColor Gray
if (Test-Path $DnsTextLogPath) { Write-Host " [Init] DNS Log found." -ForegroundColor Green }

# -----------------------------
# 2. LOGIC ENGINE
# -----------------------------

function Clean-DnsDomain {
    param($raw)
    try {
        if (-not $raw) { return "-" }
        $clean = $raw -replace '\(\d+\)', '.'
        return $clean.Trim('.')
    } catch { return $raw }
}

function Analyze-IP {
    param($ip)
    if ($ip -eq "-" -or $ip -eq "::1" -or $ip -like "127.*") { return $false }
    if ($ip -like "$TrustedNetwork*") { return $false }
    return $true 
}

function Extract-Regex { param($txt, $pat); if ($txt -match $pat) { return $matches[1].Trim() }; return $null }

function Update-SessionState {
    param($Id, $User, $Msg)
    if ($User -and $User.EndsWith("$")) { return }
    
    if ($Id -eq 4624 -and $Msg -match "Logon Type:\s+10") {
        $lId = Extract-Regex $Msg "Logon ID:\s+(0x[0-9a-fA-F]+)"
        if ($lId -and ($AdminUsers -contains $User.ToLower())) {
            if (-not $Global:ActiveAdminSessions.ContainsKey($lId)) { $Global:ActiveAdminSessions[$lId] = $User }
        }
    }
    if ($Id -eq 4634 -or $Id -eq 4647) {
        $lId = Extract-Regex $Msg "Logon ID:\s+(0x[0-9a-fA-F]+)"
        if ($lId -and $Global:ActiveAdminSessions.ContainsKey($lId)) { $Global:ActiveAdminSessions.Remove($lId) }
    }
}

function Get-Meta {
    param($id,$msg,$ip,$user)
    foreach ($r in $Global:AckList) { if ("$($r.Id)" -eq "$id") { return @{C="suppressed"; L="ACK"} } }

    $m = @{ L="SEC"; C="sec"; Lev="n" }
    
    # ZEROLOGON
    if ($id -eq 5805) { $m.L="ZEROLOGON"; $m.C="critical-badge"; $m.Lev="c"; return $m }
    if ($id -eq 4742) {
        $target = Extract-Regex $msg "Target User Name:\s+(\S+)"
        if ($target -like "$DCName`$*") { $m.L="ZEROLOGON SUCCESS"; $m.C="critical-badge"; $m.Lev="c"; return $m }
    }

    # CONCURRENT ADMINS
    $uniqueAdmins = $Global:ActiveAdminSessions.Values | Select-Object -Unique
    if ($uniqueAdmins.Count -gt 1 -and $AdminUsers -contains $user.ToLower() -and $id -eq 4624) {
        $m.L="MULTIPLE ADMINS"; $m.C="critical-badge"; $m.Lev="c"; return $m
    }

    if ($msg -match "DNS" -or $id -match "^DNS") { 
        $m.L="DNS"; $m.C="dns"
        if (Analyze-IP $ip) { $m.L="EXT DNS"; $m.C="red"; $m.Lev="c" }
    }
    elseif ($id -eq 4720) { $m.L="USER ADD"; $m.C="user-add"; $m.Lev="c" }
    elseif ($id -in 4625,1102) { $m.L="FAIL/CLR"; $m.C="crit"; $m.Lev="c" }
    
    if ($id -eq 4624 -and $msg -match "Logon Type:\s+10") { $m.L="RDP LOGIN"; $m.C="red"; $m.Lev="c" }
    if ($ip -like "10.100.*") { $m.L="RED TEAM"; $m.C="red"; $m.Lev="c" }
    return $m
}

function Format-LogDetails {
    param($msg, $type, $rawLine, $id)
    if ($id -eq 5805) { return "<div class='msg' style='color:red; font-weight:bold'>NETLOGON FAILURE (ZEROLOGON ATTEMPT)</div><div class='msg'>$msg</div>" }
    
    if ($type -eq "DNS" -and $rawLine) {
        try {
            $proto = if ($rawLine -match "UDP|TCP") { $matches[0] } else { "-" }
            $dir   = if ($rawLine -match "Snd|Rcv") { $matches[0] } else { "-" }
            $ip = "-"; if ($rawLine -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') { $ip = $matches[1] }
            $query = "-"; if ($rawLine -match '\(\d+\)[a-zA-Z0-9\-\.]+\(\d+\)') { $query = Clean-DnsDomain $matches[0] }
            $status = "UNKNOWN"; $sc = "#888"; if ($rawLine -match '(NOERROR|NXDOMAIN)') { $status = $matches[1]; if($status -eq "NOERROR"){$sc="#4caf50"}else{$sc="#ff4d4d"} }
            return "<table class='detail-table'><tr><th>Proto</th><th>Dir</th><th>Remote IP</th><th>Status</th><th>Query</th></tr><tr><td>$proto</td><td>$dir</td><td>$ip $(if(Analyze-IP $ip){"<span class='tag-bad'>EXT</span>"})</td><td style='color:$sc'>$status</td><td style='color:#fff'>$query</td></tr></table>"
        } catch { return $msg }
    }
    
    if ($type -eq "SECURITY") {
        $enc = [System.Web.HttpUtility]::HtmlEncode($msg)
        return "<div class='msg'>$enc</div>"
    }
    return "<div class='msg'>$([System.Web.HttpUtility]::HtmlEncode($msg))</div>"
}

function Add-To-Feed {
    param($Type, $Id, $Time, $User, $Ip, $Msg, $RawLine=$null)
    
    $hashKey = "$Id-$Time-$($Msg.GetHashCode())"
    if ($Global:ProcessedIDs.Contains($hashKey)) { return }
    $Global:ProcessedIDs.Add($hashKey) | Out-Null

    if ($NoiseFilter -contains $User -or $NoiseFilter -contains $Ip) { return }

    Update-SessionState $Id $User $Msg
    $meta = Get-Meta -id $Id -msg $Msg -ip $Ip -user $User
    $detailsHTML = Format-LogDetails $Msg $Type $RawLine $Id
    
    if ($Time -is [DateTime]) { $ts = $Time.ToString("HH:mm:ss") } else { $ts = $Time }
    $User = if($User){$User}else{"-"}
    $Ip = if($Ip){$Ip}else{"-"}
    
    $ipDisplay = $Ip
    if ($meta.L -eq "RDP LOGIN") { $ipDisplay = "<span class='ip-danger'>$Ip (RDP)</span>" }
    elseif (Analyze-IP $Ip) { $ipDisplay = "<span class='ip-danger'>$Ip ⚠️</span>" }

    $rowClass = $meta.C
    if ($meta.L -match "ZEROLOGON" -or $meta.L -eq "MULTIPLE ADMINS") { $rowClass = "critical zerologon-alert" }

    $row = @"
<div class='feed-item $rowClass $($meta.Lev)' data-type='$Type' data-user='$User' data-ip='$Ip' data-time='$ts'>
    <div class='head'>
        <span class='time'>$ts</span><span class='badge $($meta.C)'>$($meta.L)</span>
        <span class='meta'>ID:$Id | IP:$ipDisplay</span>
        <button class='btn-ack' onclick='doAck("$Id", this)'>&#10004; ACK</button>
    </div>
    <details><summary>Log Details</summary>$detailsHTML</details>
</div>
"@
    
    if ($Type -eq "SECURITY") { $SecurityEvents.Add($Msg) | Out-Null }
    if ($Type -eq "DNS") { $DnsEvents.Add($Msg) | Out-Null }
    if ($meta.Lev -eq "c") { $CriticalEvents.Add($Msg) | Out-Null }
    
    $Feed.Insert(0, $row) | Out-Null
    if ($Feed.Count -gt 2000) { $Feed.RemoveAt(1999) }
}

function Fetch-WinEvents {
    param($Start, $End)
    
    # 1. SECURITY
    try { 
        $s = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$Start; EndTime=$End} -ErrorAction SilentlyContinue
        if ($s) {
            $s | Sort-Object TimeCreated | ForEach-Object {
                $u="-"; $ip="-"
                try { 
                    $xml = [xml]$_.ToXml()
                    if ($xml.Event.EventData) {
                        $u=($xml.Event.EventData.Data|? Name -eq 'TargetUserName').'#text'
                        $ip=($xml.Event.EventData.Data|? Name -eq 'IpAddress').'#text'
                    }
                } catch {}
                Add-To-Feed "SECURITY" $_.Id $_.TimeCreated $u $ip $_.Message
            }
        }
    } catch {}

    # 2. SYSTEM LOG (Zerologon 5805)
    try {
        $sys = Get-WinEvent -FilterHashtable @{LogName='System'; Id=5805; StartTime=$Start; EndTime=$End} -ErrorAction SilentlyContinue
        if ($sys) {
            $sys | ForEach-Object { Add-To-Feed "SECURITY" $_.Id $_.TimeCreated "SYSTEM" "-" $_.Message }
        }
    } catch {}

    # 3. DNS TEXT LOG
    if (Test-Path $DnsTextLogPath) {
        try {
            $lines = Get-Content $DnsTextLogPath -Tail 500 -ErrorAction SilentlyContinue
            if ($lines) {
                foreach ($line in $lines) {
                    if ([string]::IsNullOrWhiteSpace($line) -or $line -match "^#") { continue }
                    $ip = "-"; if ($line -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') { $ip = $matches[1] }
                    
                    $timestamp = $End 
                    try {
                        $parts = $line -split " "
                        if ($parts.Count -gt 2) {
                            $testDate = $parts[0] + " " + $parts[1] + " " + $parts[2]
                            $timestamp = [DateTime]::Parse($testDate)
                        }
                    } catch {}
                    
                    $pseudoId = "DNS-" + ($line.GetHashCode() % 10000)

                    # Time Window Check (9am-5pm)
                    if ($timestamp -ge $Start -and $timestamp -le $End) {
                         Add-To-Feed "DNS" $pseudoId $timestamp "-" $ip $line $line
                    }
                }
            }
        } catch {}
    }
}

# --- INITIAL LOAD ---
Write-Host " [Status] Loading logs from 9:00 AM..." -ForegroundColor Yellow
Fetch-WinEvents $CompStart (Get-Date)
$Global:LastPoll = Get-Date
Write-Host " [Ready] Dashboard: http://localhost:$Port" -ForegroundColor Green

# -----------------------------
# 3. HTTP SERVER
# -----------------------------
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://+:$Port/")
$listener.Start()
$contextTask = $listener.GetContextAsync()

try {
    while ($listener.IsListening) {
        if ($contextTask.AsyncWaitHandle.WaitOne(200)) {
            $ctx = $contextTask.GetAwaiter().GetResult()
            $contextTask = $listener.GetContextAsync()
            $req = $ctx.Request; $res = $ctx.Response
            
            $path = $req.Url.LocalPath
            $res.AddHeader("Cache-Control","no-cache")
            $res.ContentType = "text/html; charset=utf-8"

            if ($path -eq "/update") {
                $tot = $SecurityEvents.Count + $DnsEvents.Count
                $sec = $SecurityEvents.Count
                $dns = $DnsEvents.Count
                $crit = $CriticalEvents.Count
                $admins = $Global:ActiveAdminSessions.Values | Select -Unique
                $adminCount = $admins.Count
                
                $htmlFeed = $Feed -join ""
                $payload = "$tot|$sec|$dns|$crit|$adminCount|DATA_START|$htmlFeed"
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
                $res.OutputStream.Write($bytes, 0, $bytes.Length)
                $res.Close()
            }
            elseif ($path -eq "/ack") {
                $qs = [System.Web.HttpUtility]::ParseQueryString($req.Url.Query)
                $ackId = $qs["id"]
                if ($ackId) { $Global:AckList.Add(@{ Id=$ackId }) | Out-Null }
                $res.StatusCode = 200; $res.Close()
            }
            else {
                $html = @"
<!DOCTYPE html>
<html>
<head>
<title>BlueShield v25.20</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
    body { background: #0d1117; color: #c9d1d9; font-family: 'Segoe UI', sans-serif; margin:0; padding:20px; display:flex; gap:20px; height:94vh; overflow:hidden; }
    
    .left { width: 260px; background: #161b22; padding:20px; border-radius:8px; border:1px solid #30363d; display:flex; flex-direction:column; gap:15px; }
    .stat-box { background: #21262d; padding:10px; border-radius:6px; border-left:4px solid #555; }
    .stat-box.tot { border-color: #58a6ff; }
    .stat-box.crit { border-color: #ff7b72; }
    .num { font-size: 24px; font-weight: bold; color: #f0f6fc; display:block; }
    .lbl { font-size: 12px; color: #8b949e; text-transform:uppercase; letter-spacing:1px; }

    .chart-container { margin-top: 10px; padding: 10px; background: #21262d; border-radius: 6px; }

    .right { flex-grow:1; display:flex; flex-direction:column; gap:10px; }
    
    .toolbar { background: #161b22; padding:10px; border-radius:8px; border:1px solid #30363d; display:flex; flex-wrap:wrap; gap:10px; align-items:center; }
    
    input[type='text'] { background: #0d1117; border:1px solid #30363d; color:white; padding:5px 10px; border-radius:4px; width:100px; }
    input[type='time'] { background: #0d1117; border:1px solid #30363d; color:white; padding:4px 8px; border-radius:4px; font-family:monospace; }
    button { background: #21262d; border:1px solid #30363d; color: #c9d1d9; padding:5px 15px; border-radius:4px; cursor:pointer; }
    button.active { background: #1f6feb; color:white; border-color:#1f6feb; }
    .btn-refresh { background: #238636; color: white; border: 1px solid #2ea043; font-weight:bold; }
    
    .feed { flex-grow:1; background: #161b22; border:1px solid #30363d; border-radius:8px; overflow-y:auto; padding:10px; }
    .feed-item { background: rgba(255,255,255,0.02); border-left:3px solid #555; padding:8px; margin-bottom:5px; border-radius:0 4px 4px 0; font-size:13px; }
    .feed-item.crit { border-left-color: #ff7b72; background: rgba(255,0,0,0.1); }
    .feed-item.red { border-left-color: #ff0000; border:1px solid red; background: rgba(255,0,0,0.2); }
    .feed-item.dns { border-left-color: #bc8cff; }
    .feed-item.sec { border-left-color: #58a6ff; }
    
    /* ANIMATIONS */
    .feed-item.multiple-admins { border-left: 5px solid #ff00ff; background: rgba(255,0,255,0.15); animation: flash 2s infinite; }
    .feed-item.zerologon-alert { border-left: 5px solid #ff4d4d; border: 2px solid #ff4d4d; background: rgba(255,0,0,0.2); animation: flash 1s infinite; }
    @keyframes flash { 0% {opacity:1;} 50% {opacity:0.6;} 100% {opacity:1;} }
    
    .head { display:flex; align-items:center; gap:10px; }
    .time { background: black; padding:2px 6px; border-radius:4px; font-family:monospace; font-size:11px; color:#8b949e; }
    .badge { font-weight:bold; font-size:10px; padding:2px 6px; border-radius:4px; color:#0d1117; }
    .badge.sec { background: #58a6ff; }
    .badge.dns { background: #bc8cff; }
    .badge.crit { background: #ff7b72; }
    .badge.red { background: #ff0000; color:white; }
    .badge.critical-badge { background: #ff4d4d; color:white; box-shadow: 0 0 5px red; }
    
    .meta { color: #8b949e; font-family:monospace; }
    .ip-danger { color: #ff4d4d; font-weight:bold; }
    .msg { white-space: pre-wrap; font-family: 'Consolas', monospace; color: #d1d5da; padding-top:10px; font-size:12px; line-height: 1.4; }
    .log-key { color: #8b949e; font-weight:bold; }
    .log-ip  { color: #39c5bb; font-weight:bold; }
    .highlight { background: #1f6feb; color: white; padding: 1px 4px; border-radius: 2px; }
    
    .detail-table { width:100%; border-collapse:collapse; margin-bottom:5px; font-family:'Consolas', monospace; font-size:12px; background:rgba(0,0,0,0.2); }
    .detail-table th { text-align:left; color:#8b949e; border-bottom:1px solid #444; padding:4px; background:#1e242e; }
    .detail-table td { color:#d1d5da; padding:4px; border-bottom:1px solid #222; }
    .tag-bad { background: #ff0000; color:white; padding:1px 4px; border-radius:2px; font-size:10px; margin-left:5px; }

    .btn-ack { font-size:10px; padding:3px 8px; margin-left:auto; background: transparent; border: 1px solid #238636; color: #2ea043; font-weight: bold; transition: 0.2s; }
    .btn-ack:hover { background: #238636; color: white; cursor: pointer; }
</style>
</head>
<body>

<div class="left">
    <h2 style="color:#58a6ff; margin:0;">BlueShield</h2>
    <div style="font-size:11px; color:#555; margin-bottom:15px;">v25.20 Master</div>
    <div class="stat-box tot"><span class="num" id="s_tot">0</span><span class="lbl">Total Events</span></div>
    <div class="stat-box tot"><span class="num" id="s_sec">0</span><span class="lbl">Security</span></div>
    <div class="stat-box crit"><span class="num" id="s_crit">0</span><span class="lbl">Critical</span></div>
    
    <div class="stat-box" style="border-color:#ff00ff; margin-top:20px;">
        <span class="num" id="s_active" style="color:#ff00ff">0</span>
        <span class="lbl">Active Admins (RDP)</span>
    </div>

    <div class="chart-container">
        <canvas id="myChart"></canvas>
    </div>

    <div style="margin-top:auto; font-size:11px; color:#555;">v25.20</div>
</div>

<div class="right">
    <div class="toolbar">
        <button onclick="loadData()" class="btn-refresh">&#8635; REFRESH</button>
        <span id="loadStatus" style="font-size:11px; color:#8b949e;"></span>
        
        <div style="width:1px; height:20px; background:#30363d; margin:0 10px;"></div>
        
        <span style="color:#8b949e; font-size:12px;">Time:</span>
        <input type="time" id="time_start" onchange="applyFilters()">
        <span style="color:#8b949e">-</span>
        <input type="time" id="time_end" onchange="applyFilters()">
        <button onclick="clearTime()" style="font-size:10px; padding:2px 8px;">Clear</button>

        <div style="width:1px; height:20px; background:#30363d; margin:0 10px;"></div>

        <button onclick="setFilter('all')" id="btn_all" class="active">All</button>
        <button onclick="setFilter('crit')" id="btn_crit">Crit</button>
        <button onclick="setFilter('sec')" id="btn_sec">Sec</button>
        <button onclick="setFilter('dns')" id="btn_dns">DNS</button>
        
        <div style="width:1px; height:20px; background:#30363d; margin:0 10px;"></div>
        
        <input type="text" id="in_user" placeholder="User..." onkeyup="applyFilters()">
        <input type="text" id="in_ip" placeholder="IP..." onkeyup="applyFilters()">
    </div>
    
    <div class="feed" id="feedArea">Click REFRESH to load events...</div>
</div>

<script>
    let currentType = 'all';
    
    // CHART SETUP
    const ctx = document.getElementById('myChart').getContext('2d');
    const myChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['Security', 'DNS'],
            datasets: [{
                data: [0, 0],
                backgroundColor: ['#58a6ff', '#bc8cff'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { labels: { color: '#8b949e', font: {size: 10} } }
            }
        }
    });

    loadData();

    function loadData() {
        document.getElementById('loadStatus').innerText = "Updating...";
        fetch('/update').then(r => r.text()).then(d => {
            const p = d.split('DATA_START');
            const s = p[0].split('|');
            
            document.getElementById('s_tot').innerText = s[0];
            const sec = parseInt(s[1]);
            const dns = parseInt(s[2]);
            document.getElementById('s_sec').innerText = sec;
            document.getElementById('s_crit').innerText = s[3];
            document.getElementById('s_active').innerText = s[4];

            // Update Pie Chart
            myChart.data.datasets[0].data = [sec, dns];
            myChart.update();

            const fd = document.getElementById('feedArea');
            if (fd.innerHTML.length !== p[1].length) { fd.innerHTML = p[1]; applyFilters(); }
            document.getElementById('loadStatus').innerText = "Last: " + new Date().toLocaleTimeString();
        });
    }

    function setFilter(t) {
        currentType = t;
        document.querySelectorAll('button').forEach(b => { 
            if (b.id.startsWith('btn_')) b.classList.remove('active'); 
        });
        document.getElementById('btn_' + t).classList.add('active');
        applyFilters();
    }
    
    function clearTime() {
        document.getElementById('time_start').value = "";
        document.getElementById('time_end').value = "";
        applyFilters();
    }

    function applyFilters() {
        const u = document.getElementById('in_user').value.toLowerCase();
        const i = document.getElementById('in_ip').value.toLowerCase();
        const tStart = document.getElementById('time_start').value;
        const tEnd = document.getElementById('time_end').value;

        document.querySelectorAll('.feed-item').forEach(el => {
            let v = true;
            if (currentType === 'crit' && !el.classList.contains('c')) v = false;
            if (currentType === 'sec' && el.dataset.type !== 'SECURITY') v = false;
            if (currentType === 'dns' && el.dataset.type !== 'DNS') v = false;
            if (u && !el.dataset.user.toLowerCase().includes(u)) v = false;
            if (i && !el.dataset.ip.toLowerCase().includes(i)) v = false;
            if (tStart || tEnd) {
                const logTime = el.dataset.time.substring(0,5); 
                if (tStart && logTime < tStart) v = false;
                if (tEnd && logTime > tEnd) v = false;
            }
            el.style.display = v ? 'block' : 'none';
        });
    }

    function doAck(id, btn) {
        // Enforce string ID for JS
        fetch('/ack?id=' + encodeURIComponent(id)).then(() => {
            btn.closest('.feed-item').style.opacity = '0.3';
            btn.innerText = 'ACKED';
            btn.style.color = '#555'; btn.style.borderColor = '#555';
        });
    }
</script>
</body>
</html>
"@
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($html)
                $res.OutputStream.Write($buffer, 0, $buffer.Length)
                $res.Close()
            }
        }

        # Background Collection (Only in window)
        $Now = Get-Date
        if ($Now -lt $CompEnd -and $Now -gt $CompStart) {
            Fetch-WinEvents $Global:LastPoll $Now
            $Global:LastPoll = $Now
        }
    }
} finally {
    $listener.Stop(); $listener.Close()
}
