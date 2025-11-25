<#
===============================================================
 SCORE ENGINE DISCOVERY TOOL
 - Reads Windows Firewall Log (pfirewall.log)
 - Extracts DROP entries
 - Shows all ports per IP + hit counts
 - Highlights DNS (53)
 - Flags MOST suspicious IP (⭐)
 - Allows whitelisting into GPO
===============================================================
#>

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "     SCORE ENGINE DISCOVERY – FIREWALL LOG SCANNER" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan


# ==========================================================
#  AUTO-DETECT DOMAIN & ALLOW MANUAL OVERRIDE WITH VALIDATION
# ==========================================================

# Try auto-detect domain
try {
    $AutoDomain = (Get-ADDomain).DNSRoot
} catch {
    Write-Host "[WARN] Unable to auto-detect domain. Machine may not be domain-joined." -ForegroundColor Yellow
    $AutoDomain = $null
}

# Ask user to confirm autodetected domain
if ($AutoDomain) {
    Write-Host "`nDetected domain: $AutoDomain" -ForegroundColor Cyan
    $choice = Read-Host "Use this domain? (Y/N)"

    if ($choice.ToUpper() -eq "Y") {
        $DomainName = $AutoDomain
    }
}

# Manual entry if autodetect not used or declined
if (-not $DomainName) {
    $DomainName = Read-Host "Enter your domain name manually (example: great.cretaceous)"

    if (-not $DomainName) {
        Write-Host "[ERROR] Domain cannot be empty." -ForegroundColor Red
        exit
    }

    # Validate
    try {
        $null = Get-ADDomain -Identity $DomainName -ErrorAction Stop
        Write-Host "[OK] Domain verified: $DomainName" -ForegroundColor Green
    } catch {
        Write-Host "[ERROR] Domain '$DomainName' does not exist or cannot be contacted." -ForegroundColor Red
        exit
    }
}

# Prepare GPO reference
$GpoName     = "Domain Hardening"
$PolicyStore = "$DomainName\$GpoName"

Start-Sleep -Seconds 1


# ==========================================================
# FIREWALL LOG READ
# ==========================================================
$FwLogPath = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"

Write-Host "`n[1] Checking Firewall Log..." -ForegroundColor Yellow
if (-not (Test-Path $FwLogPath)) {
    Write-Host "[WARN] Firewall log not found. Ensure logging is enabled in GPO." -ForegroundColor Yellow
    exit
}

Write-Host "[2] Reading DROP traffic..." -ForegroundColor Yellow
$DropLines = Select-String -Path $FwLogPath -Pattern "DROP"

if (-not $DropLines -or $DropLines.Count -eq 0) {
    Write-Host "[INFO] No DROP entries found yet. Waiting for score engine..." -ForegroundColor Yellow
    exit
}

Write-Host "  → DROP entries found: $($DropLines.Count)" -ForegroundColor Cyan


# ==========================================================
# PARSE DROP ENTRIES (IP + PORT)
# ==========================================================
$ParsedDrops = $DropLines | ForEach-Object {
    $parts = ($_ -split " +")
    if ($parts.Count -ge 8) {
        [PSCustomObject]@{
            SrcIP   = $parts[4]
            DstPort = $parts[7]
        }
    }
}


# ==========================================================
# SORTED IP REPORT WITH PORT BREAKDOWN + COLORS + ⭐
# ==========================================================
Write-Host "`n[3] Blocked IP Report (sorted by hits):" -ForegroundColor Cyan

# Build stats per IP
$IPStats = $ParsedDrops |
    Group-Object SrcIP |
    ForEach-Object {
        $IP = $_.Name
        $PortGroups = $_.Group | Group-Object DstPort
        $TotalHits = ($PortGroups | Measure-Object Count -Sum).Sum

        [PSCustomObject]@{
            IP        = $IP
            TotalHits = $TotalHits
            PortData  = $PortGroups
        }
    }

# Sort greatest → smallest
$SortedIPs = $IPStats | Sort-Object TotalHits -Descending

# Most suspicious = top hitter
$TopIP = $SortedIPs[0].IP

foreach ($entry in $SortedIPs) {

    $ip = $entry.IP
    $star = if ($ip -eq $TopIP) { " ⭐" } else { "" }

    $PortString = ""

    foreach ($pg in $entry.PortData) {
        $port = $pg.Name
        $hits = $pg.Count

        if ($port -eq "53") {
            # Highlight DNS port
            $PortString += " port $port ($hits hits) DNS,"
        } else {
            $PortString += " port $port ($hits hits),"
        }
    }

    $PortString = $PortString.TrimEnd(",")

    Write-Host ("  • {0}{1} → {2}" -f $ip, $star, $PortString)
}


# ==========================================================
# DNS (53) SPECIFIC SUMMARY
# ==========================================================
Write-Host "`n[4] Checking for DNS (53) blocked traffic..." -ForegroundColor Yellow

$DNSHits = $ParsedDrops | Where-Object { $_.DstPort -eq "53" }

if ($DNSHits.Count -eq 0) {
    Write-Host "[INFO] No DNS (53) hits detected." -ForegroundColor Yellow
} else {
    Write-Host "`n[POSSIBLE SCORE ENGINE] DNS attempts:" -ForegroundColor Green

    $DNSHits |
        Group-Object SrcIP |
        ForEach-Object {
            Write-Host ("   → {0} → port 53 ({1} hits)" -f $_.Name, $_.Count) -ForegroundColor Green
        }
}


# ==========================================================
# WHITELIST INPUT
# ==========================================================
$WL = Read-Host "`nEnter an IP to whitelist (or press ENTER to skip)"
if (-not $WL) {
    Write-Host "[INFO] No IP selected for whitelisting." -ForegroundColor Yellow
    exit
}

Write-Host "  → Creating DNS allow rules for $WL ..." -ForegroundColor Cyan

# ==========================================================
# APPLY GPO FIREWALL RULES
# ==========================================================
New-NetFirewallRule `
    -DisplayName "Allow ScoreEngine DNS TCP $WL" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 53 `
    -RemoteAddress $WL `
    -Action Allow `
    -Profile Domain `
    -PolicyStore $PolicyStore `
    -ErrorAction SilentlyContinue | Out-Null

New-NetFirewallRule `
    -DisplayName "Allow ScoreEngine DNS UDP $WL" `
    -Direction Inbound `
    -Protocol UDP `
    -LocalPort 53 `
    -RemoteAddress $WL `
    -Action Allow `
    -Profile Domain `
    -PolicyStore $PolicyStore `
    -ErrorAction SilentlyContinue | Out-Null

Write-Host "`n[OK] Whitelisted $WL for DNS (TCP/UDP 53) in GPO '$GpoName'" -ForegroundColor Green


# ==========================================================
# FORCE APPLY GPO CHANGES
# ==========================================================
Write-Host "`n[INFO] Applying updated GPO to the system..." -ForegroundColor Yellow

try {
    gpupdate /force | Out-Null
    Write-Host "[OK] GPO Updated Successfully." -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to apply GPO. Run 'gpupdate /force' manually." -ForegroundColor Red
}


Write-Host "`n====================================================" -ForegroundColor Cyan
Write-Host "   SCORE ENGINE DISCOVERY COMPLETED" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

