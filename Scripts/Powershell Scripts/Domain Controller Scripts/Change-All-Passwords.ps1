Import-Module ActiveDirectory

$ExcludeGroup = "Domain Admins"
$OutputFile = "\\tsclient\H\Xsploit Club\DomainPasswordChanges_$((Get-Date).ToString('yyyyMMdd_HHmm')).csv"

function New-StrongPassword {
    $Length = Get-Random -Minimum 14 -Maximum 17
    $lower   = 'abcdefghjkmnpqrstuvwxyz'.ToCharArray()
    $upper   = 'ABCDEFGHJKMNPQRSTUVWXYZ'.ToCharArray()
    $digits  = '23456789'.ToCharArray()
    $special = '!@#$%^&*()-_=+'.ToCharArray()

    $pw = @()
    $pw += ($lower | Get-Random -Count 2)
    $pw += ($upper | Get-Random -Count 2)
    $pw += ($digits | Get-Random -Count 2)
    $pw += ($special| Get-Random -Count 2)
    $all = $lower + $upper + $digits + $special
    $pw += ($all | Get-Random -Count ($Length - $pw.Count))
    return -join ($pw | Get-Random -Count $pw.Count)
}

Write-Host "Gathering enabled users except Domain Admins..." -ForegroundColor Cyan
$excludeUsers = (Get-ADGroupMember $ExcludeGroup -Recursive |
                 Where-Object {$_.objectClass -eq 'user'}).SamAccountName
$excludeUsers += @('Administrator','krbtgt','Guest')

$users = Get-ADUser -Filter {Enabled -eq $true} -Properties SamAccountName |
         Where-Object { $excludeUsers -notcontains $_.SamAccountName }

Write-Host "Found $($users.Count) users to process." -ForegroundColor Green
$results = @()

foreach ($u in $users) {
    $user = $u.SamAccountName
    $pwd = New-StrongPassword
    $secure = ConvertTo-SecureString $pwd -AsPlainText -Force
    try {
        Set-ADAccountPassword -Identity $user -Reset -NewPassword $secure -ErrorAction Stop
        Write-Host "Password changed for $user" -ForegroundColor Green
        $results += [PSCustomObject]@{UserName=$user;NewPassword=$pwd;Combined="$user`:$pwd"}
    } catch {
        Write-Host "Failed to change password for $user" -ForegroundColor Red
    }
}

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "`nAll results saved to: $OutputFile" -ForegroundColor Cyan
