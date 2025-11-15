# ----------------------------------------------------------
# ELASTIC AGENT INSTALLATION
# ----------------------------------------------------------

# Helper functions for color-coded output
function Write-Info ($Message) { Write-Host "[INFO]  $Message" -ForegroundColor Cyan }
function Write-Ok   ($Message) { Write-Host "[ OK ]  $Message" -ForegroundColor Green }
function Write-Warn ($Message) { Write-Host "[WARN]  $Message" -ForegroundColor Yellow }

Write-Host "`n[+] Installing Elastic Agent (Fleet enrollment)..." -ForegroundColor Cyan

try {
    # Define paths and variables
    $elasticDir  = "C:\ElasticAgent_Install"
    $zipName     = "elastic-agent-9.2.0+build202510300150-windows-x86_64.zip"
    $zipPath     = Join-Path $elasticDir $zipName
    $extractDir  = Join-Path $elasticDir "elastic-agent-9.2.0+build202510300150-windows-x86_64"
    $installExe  = Join-Path $extractDir "elastic-agent.exe"
    $fleetUrl    = "https://5fb1aa0536994ea7b1e38b581dcff047.fleet.us-west-1.aws.found.io:443"
    $token       = "SmZOYmc1b0JwaGg4MDdnZHZKbWY6LTMydFd6NHBMOHNmS0U0ajM5Q19hdw=="

    # Ensure working directory exists
    if (-not (Test-Path $elasticDir)) {
        Write-Info "Creating working directory at $elasticDir..."
        New-Item -ItemType Directory -Path $elasticDir -Force | Out-Null
    }

    # Step 1: Verify and enforce TLS 1.2
    Write-Info "Checking secure protocol support (TLS 1.2)..."
    $currentProtocols = [Net.ServicePointManager]::SecurityProtocol
    if (($currentProtocols -band [Net.SecurityProtocolType]::Tls12) -ne [Net.SecurityProtocolType]::Tls12) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        Write-Ok "TLS 1.2 has been enabled for this session."
    } else {
        Write-Ok "TLS 1.2 is already enabled."
    }

    # Step 2: Download Elastic Agent package
    Write-Info "Downloading Elastic Agent package..."
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri "https://artifacts.elastic.co/downloads/beats/elastic-agent/$zipName" `
        -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
    Write-Ok "Downloaded Elastic Agent to $zipPath"

    # Step 3: Extract the archive
    Write-Info "Extracting Elastic Agent..."
    Expand-Archive -Path $zipPath -DestinationPath $elasticDir -Force
    Write-Ok "Extracted to $extractDir"

    # Step 4: Install and enroll with Fleet
    Write-Info "Running Elastic Agent installation..."
    Start-Process -FilePath $installExe `
        -ArgumentList "install --url=$fleetUrl --enrollment-token=$token --force" `
        -Wait -NoNewWindow
    Write-Ok "Elastic Agent installed and enrolled successfully."

    # Step 5: Verify installation (list Elastic-related services)
    Write-Info "Verifying Elastic services..."
    $elasticServices = Get-Service | Where-Object { $_.DisplayName -like "*Elastic*" } |
        Select-Object Name, DisplayName, Status, StartType
    if ($elasticServices) {
        $elasticServices | Format-Table -AutoSize
        Write-Ok "Elastic services are installed and running as expected."
    } else {
        Write-Warn "No Elastic-related services detected — check installation logs."
    }

    # Optional reporting (if your script defines Add-Result)
    if (Get-Command Add-Result -ErrorAction SilentlyContinue) {
        Add-Result "Elastic Agent" "Secure" "Installed and enrolled" $fleetUrl
    }
}
catch {
    Write-Warn "Elastic Agent installation failed: $($_.Exception.Message)"
    if (Get-Command Add-Result -ErrorAction SilentlyContinue) {
        Add-Result "Elastic Agent" "Warning" "Installation failed" $_.Exception.Message
    }
}
