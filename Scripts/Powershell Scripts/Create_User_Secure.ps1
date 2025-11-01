# ---------------------------------------------
# Secure multi-machine user creation
# ---------------------------------------------

# Enter target computers (comma-separated)
$RemoteComputers = (Read-Host "Enter remote computer(s) (comma-separated)") -split ',' |
    ForEach-Object { $_.Trim() } | Where-Object { $_ }

if (-not $RemoteComputers) {
    Write-Error "No target hosts specified. Exiting."
    return
}

# Connection credentials for remote WinRM session

$ConnCred = Get-Credential -Message 'Credentials to connect to remote hosts (use .\Administrator)'

# Define users to create or update
$UserNames = @('cesar_la', 'ruby_la', 'peter_la')

# Prompt for password for the new users
$UserPasswordSecure = Read-Host -AsSecureString "Enter password for the new users"

# Throttle limit for parallel remoting
$ThrottleLimit = 12
$Jobs = @()

foreach ($TargetComputer in $RemoteComputers) {
    $Jobs += Start-Job -ScriptBlock {
        param($Computer, $Cred, $UserPassSecure, $UserList)

        try {
            Invoke-Command -ComputerName $Computer -Credential $Cred -Authentication Negotiate -ScriptBlock {
                param(
                    [System.Security.SecureString]$RemoteUserPass,
                    [string[]]$RemoteUserList
                )

                $Results = @()

                # Convert SecureString to plaintext ON REMOTE HOST ONLY
                $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($RemoteUserPass)
                $PlainUserPass = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)

                try {
                    foreach ($name in $RemoteUserList) {
                        # Check if user exists
                        cmd /c "net user `"$name`"" > $null 2>&1
                        if ($LASTEXITCODE -eq 0) {
                            # user exists — update password
                            cmd /c "net user `"$name`" `"$PlainUserPass`""
                            if ($LASTEXITCODE -eq 0) {
                                $Results += [PSCustomObject]@{
                                    Computer = $env:COMPUTERNAME
                                    User     = $name
                                    Result   = "🔁 Password updated (user already existed)"
                                }
                            } else {
                                $Results += [PSCustomObject]@{
                                    Computer = $env:COMPUTERNAME
                                    User     = $name
                                    Result   = "❌ Failed to update password (exit code $LASTEXITCODE)"
                                }
                            }
                        } else {
                            # create new user
                            cmd /c "net user `"$name`" `"$PlainUserPass`" /add"
                            if ($LASTEXITCODE -eq 0) {
                                cmd /c "net localgroup Administrators `"$name`" /add"
                                
                                $Results += [PSCustomObject]@{
                                    Computer = $env:COMPUTERNAME
                                    User     = $name
                                    Result   = "✅ Created and added to groups"
                                }
                            } else {
                                $Results += [PSCustomObject]@{
                                    Computer = $env:COMPUTERNAME
                                    User     = $name
                                    Result   = "❌ Failed to create user (exit code $LASTEXITCODE)"
                                }
                            }
                        }
                    }
                }
                finally {
                    # Zero and clear password from memory
                    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                }

                return $Results

            } -ArgumentList $UserPassSecure, $UserList -ErrorAction Stop

        } catch {
            [PSCustomObject]@{
                Computer = $Computer
                User     = "N/A"
                Result   = "❌ Connection or script failed: $($_.Exception.Message)"
            }
        }

    } -ArgumentList $TargetComputer, $ConnCred, $UserPasswordSecure, $UserNames

    while (($Jobs | Where-Object { $_.State -eq 'Running' }).Count -ge $ThrottleLimit) {
        Start-Sleep -Seconds 1
    }
}

# Wait for all jobs and collect output
Wait-Job -Job $Jobs
$AllResults = Receive-Job -Job $Jobs
Remove-Job -Job $Jobs

# Display formatted output
$AllResults | Sort-Object Computer, User | Format-Table Computer, User, Result -AutoSize


