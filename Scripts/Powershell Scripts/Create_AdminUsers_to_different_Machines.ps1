# ---------------------------------------------
# Remote user create / change password on multiple machines via WinRM
# ---------------------------------------------

# Enter remote computers as comma-separated list, e.g. "192.168.220.111,192.168.220.112"
$RemoteComputersInput = Read-Host "Enter remote computer(s) (comma-separated, no spaces required)"
$RemoteComputers = $RemoteComputersInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }

if (-not $RemoteComputers) {
    Write-Error "No remote computers specified. Exiting."
    return
}

# Prompt for the Administrator password securely (used to connect to remote machines)
$Password = Read-Host -AsSecureString "Enter the password for Administrator"
$Credential = New-Object System.Management.Automation.PSCredential ("Administrator", $Password)

# Define user accounts to create / change password for
$Names = @('cesar_la', 'ruby_la', 'peter_la')   # adjust as needed

# Prompt for the new users' password securely
$UserPasswordSecure = Read-Host -AsSecureString "Enter the password for the new users"

# Convert SecureString to plain text (required for net user command)
$Ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($UserPasswordSecure)
$PlainUserPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Ptr)
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Ptr)  # clear memory securely

# Script block to execute on each remote machine
$ScriptBlock = {
    param (
        [string[]]$UserNames,
        [string]$PasswordPlain
    )

    foreach ($name in $UserNames) {
        try {
            # Check if user exists (net user returns non-zero if not found)
            cmd /c "net user `"$name`"" > $null 2>&1
            if ($LASTEXITCODE -eq 0) {
                # User exists -> change password
                cmd /c "net user `"$name`" `"$PasswordPlain`""
                if ($LASTEXITCODE -eq 0) {
                    Write-Output "🔁 Password changed for existing user '$name'."
                }
                else {
                    Write-Error "❌ Failed to change password for '$name' (net user returned $LASTEXITCODE)."
                }
            }
            else {
                # User does not exist -> create and add to groups
                cmd /c "net user `"$name`" `"$PasswordPlain`" /add"
                if ($LASTEXITCODE -ne 0) {
                    Write-Error "❌ Failed to create user '$name' (net user returned $LASTEXITCODE)."
                    continue
                }

                # Add to Administrators and Remote Desktop Users
                cmd /c "net localgroup Administrators `"$name`" /add" > $null 2>&1
                cmd /c "net localgroup `"Remote Desktop Users`" `"$name`" /add" > $null 2>&1

                Write-Output "✅ User '$name' created and added to groups."
            }
        }
        catch {
            Write-Error "❌ Exception for user '$name': $($_.Exception.Message)"
        }
    }
}

# Run the script on all remote machines
# -ThrottleLimit controls how many parallel connections will run at once (adjust for your environment)
Invoke-Command -ComputerName $RemoteComputers -Credential $Credential `
    -Authentication Negotiate `
    -ScriptBlock $ScriptBlock `
    -ArgumentList ($Names, $PlainUserPassword) `
    -ThrottleLimit 12 -ErrorAction Stop |
    ForEach-Object { Write-Host $_ }
