$accountname = Read-Host "Please enter the username for the password you want to change"
$NewPassword = Read-Host -AsSecureString "Enter the temporary password for the user"
Set-ADAccountPassword -Identity $accountname -NewPassword $NewPassword -Reset
