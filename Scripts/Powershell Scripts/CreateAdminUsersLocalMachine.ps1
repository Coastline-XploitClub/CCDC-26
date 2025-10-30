# ---------------------------------------------
# Remote user creation via WinRM 
# ---------------------------------------------

# Define the remote machine
#Change the IP address with the target machine that will be created the admin users 
$RemoteComputer = "192.168.220.111" 

# Prompt for the Administrator password securely
$Password = Read-Host -AsSecureString "Enter the password for Administrator"
$Credential = New-Object System.Management.Automation.PSCredential ("Administrator", $Password)

# Define user accounts to create
$Names = @('cesar_la', "ruby_la","peter_la")

# Prompt for the new users' password securely
$UserPasswordSecure = Read-Host -AsSecureString "Enter the password for the new users"

# Convert SecureString to plain text (needed for net user)
$Ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($UserPasswordSecure)
$PlainUserPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Ptr)
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Ptr)  # clear memory securely

# Script block to execute on the remote machine
$ScriptBlock = {
    param (
        [string[]]$UserNames,
        [string]$Password
    )

    foreach ($name in $UserNames) {
        try {
            # Create user (quote password to handle special characters safely)
            cmd /c "net user `"$name`" `"$Password`" /add"
            
            # Add to Administrators group
            cmd /c "net localgroup Administrators `"$name`" /add"

            # Add to Remote Desktop Users group
            cmd /c "net localgroup `"Remote Desktop Users`" `"$name`" /add"

            Write-Output "✅ User '$name' created and added to groups successfully."
        }
        catch {
            Write-Error "❌ Failed to create user '$name': $($_.Exception.Message)"
        }
    }
}

# Invoke the script block on the remote computer
Invoke-Command -ComputerName $RemoteComputer -Credential $Credential `
    -Authentication Negotiate `
    -ScriptBlock $ScriptBlock `
    -ArgumentList $Names, $PlainUserPassword
