Import-Module ActiveDirectory

$LockoutThreshold = 5  
$LockoutDuration = 30  
$LockoutObservationWindow = 30


Set-ADDefaultDomainPasswordPolicy -Identity "YourDomainName" `
   -LockoutThreshold $LockoutThreshold `
   -LockoutDuration $LockoutDuration `
   -LockoutObservationWindow $LockoutObservationWindow

Set-ADDefaultDomainPasswordPolicy -Identity "Wobblys.world" -MinPasswordLength 8
Set-ADDefaultDomainPasswordPolicy -Identity "Wobblys.world" -ComplexityEnabled $true
