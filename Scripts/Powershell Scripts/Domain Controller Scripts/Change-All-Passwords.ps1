Import-Module ActiveDirectory

function New-StrongPassword {
    $length = 14
    $upper   = (65..90   | ForEach-Object {[char]$_})   # A-Z
    $lower   = (97..122  | ForEach-Object {[char]$_})   # a-z
    $numbers = (48..57   | ForEach-Object {[char]$_})   # 0-9
    $special = "@$%^&*()-_=+[]{}<>?".ToCharArray()       # Special chars
    $all     = $upper + $lower + $numbers + $special

    # Guarantee at least 1 of each category
    $passwordArray = @(
        ($upper   | Get-Random -Count 1)
        ($lower   | Get-Random -Count 1)
        ($numbers | Get-Random -Count 1)
        ($special | Get-Random -Count 1)
    )

    # Fill the remaining length with fully random characters
    $remaining = $length - $passwordArray.Count
    $passwordArray += ($all | Get-Random -Count $remaining)

    # Shuffle the final password
    $shuffledPassword = ($passwordArray | Sort-Object {Get-Random}) -join ''

    return $shuffledPassword
}
# Output file path (Excel compatible)
$OutputFile = "C:\Users\Administrator\Documents\Domain_Passwords_$((Get-Date).ToString('yyyyMMdd_HHmm')).csv"

# Excluded groups and users
$excludedGroups = @("Domain Admins", "Enterprise Admins")
$excludedUsers = foreach ($group in $excludedGroups) {
    Get-ADGroupMember -Identity $group -Recursive | Select-Object -ExpandProperty SamAccountName
}
$excludedUsers += @("Administrator", "krbtgt", "Guest", "DefaultAccount")
$excludedUsers = $excludedUsers | Select-Object -Unique

# Collect users
$users = Get-ADUser -Filter * | Where-Object {
    $_.SamAccountName -notin $excludedUsers
}

# Array to hold results
$results = @()

foreach ($u in $users) {
    $user = $u.SamAccountName
    $pwd  = New-StrongPassword
    $secure = ConvertTo-SecureString $pwd -AsPlainText -Force

    try {
        Set-ADAccountPassword -Identity $user -Reset -NewPassword $secure -ErrorAction Stop
        Write-Host "✅ Password changed for $user" -ForegroundColor Green
        $results += [PSCustomObject]@{
            Username    = $user
            Password    = $pwd
            Combined    = "$user,$pwd"
        }
    } catch {
        Write-Host "❌ Failed to change password for $user" -ForegroundColor Red
        $results += [PSCustomObject]@{
            Username    = $user
            Password    = "FAILED"
            Combined    = "$user,FAILED"
        }
    }
}

# Export to Excel (CSV)
$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "`nAll results saved to: $OutputFile" -ForegroundColor Cyan
