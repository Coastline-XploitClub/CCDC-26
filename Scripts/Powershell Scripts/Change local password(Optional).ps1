#Use if you want to.  If not, just use GUI instead.

$accountname = Read-Host "Please enter the username for the password you want to change"
$NewPassword = Read-Host -AsSecureString "Enter the temporary password for the user"

Set-LocalUser -Name $accountname -Password $NewPassword
