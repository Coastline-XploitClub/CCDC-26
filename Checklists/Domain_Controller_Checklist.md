# 🛡️ First 15 Minutes – Domain Controller Checklist (CCDC)

This checklist outlines the actions to secure and stabilize the Domain Controller during the first 15 minutes of the competition.

## 1. Log in to the Domain Controller
		• Use the default password provided by CCDC.
		• Immediately change the Administrator password to the team-approved password.
	Example:
		• Default password: OMGaTREX1?
		• New team password: Lily-hen-seminar123?
		• Update the PCRs if required

## 2. Change All User Passwords (Except Administrator)
		a. Follow the next url to find the script: https://github.com/Coastline-XploitClub/CCDC-26/blob/main/Scripts/Powershell%20Scripts/Domain%20Controller%20Scripts/Change-All-Passwords.ps1
		   or you can use the following command to download it directly to the machine:
			Invoke-WebRequest -Uri "https://github.com/Coastline-XploitClub/CCDC-26/blob/main/Scripts/Powershell%20Scripts/Domain%20Controller%20Scripts/Change-All-Passwords.ps1" -OutFile "Change-All-Passwords.ps1"
		b. Update the PCRs if it is required. 
	• This rotates passwords for every domain user.
	• Administrator uses the password you manually set earlier.

## 3. Initial Recon – Identify Open Ports
	Run an Nmap scan from the Kali machine:
	
	sudo nmap 192.168.220.12
	
	This confirms what services are exposed before hardening begins.

## 4. Run the Full Domain Controller Backup. 
		a. Execute Full_DC_Backup.ps1 to generate a full backup: https://github.com/Coastline-XploitClub/CCDC-26/blob/main/Scripts/Powershell%20Scripts/Domain%20Controller%20Scripts/Full_DC_Backup.ps1
		   or you can use the following command to download it directly to the machine:
			Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Coastline-XploitClub/CCDC-26/refs/heads/main/Scripts/Powershell%20Scripts/Domain%20Controller%20Scripts/Full_DC_Backup.ps1"  -OutFile "Full_DC_Backup.ps1"

## 5. Run the Firewall_Rules.ps1 script, this will anable all the GPOs for Windows Clients machines and the Doamin Controller.
		a.  Follow the next url to find the script: https://raw.githubusercontent.com/Coastline-XploitClub/CCDC-26/refs/heads/main/Scripts/Powershell%20Scripts/Domain%20Controller%20Scripts/Firewall_Rules.ps1
			or you can use the following command to download it directly to the machine:
			Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Coastline-XploitClub/CCDC-26/refs/heads/main/Scripts/Powershell%20Scripts/Domain%20Controller%20Scripts/Firewall_Rules.ps1" -OutFile "Firewall_Rules.ps1"
     Harden the DNS Manually by doing the following
		a. Delect all users or group on the DNS manager ACL section and setup the new user created to handle all DNS. 
		b. Enable DNS logging and set the location to C:\dns
		c. Enable DNSSEC Manually
			After running the script, enable DNSSEC using DNS Manager:
				1. Right-click your zone → DNSSEC → Sign the Zone.
				2. Follow the wizard:
					○ All settings can remain default.
					○ Click Add to generate keys.
				3. At the last screen, enable both options (required for Domain Controllers).
				4. Refresh the zone. DNSSEC should now show as Enabled.

## 6. Configure Logging for the Domain Hardening GPO 
		After the GPO is created:
			1. Open Group Policy Management.
			2. Navigate to Domain Controllers → Domain Hardening.
			3. Go to:
            		Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy
			4. Enable the required logging settings (follow your internal logging guide).
		
		
## 9. Run BlueShield Hardening
	Execute BlueShield.ps1 to apply overall AD, Kerberos, LSASS, Defender, and service hardening:
		a. You can find the script by following the next url: https://github.com/Coastline-XploitClub/CCDC-26/blob/main/Scripts/Powershell%20Scripts/Domain%20Controller%20Scripts/BlueShield.ps1
		• Follow the interactive prompts and apply secure defaults.
		• Do not disable IPv6 unless absolutely necessary for the competition.
	
## 10. Begin Full Enumeration
	Once hardening is complete:
		• Check running services
		• Review inbound/outbound firewall rules
		• Validate DNS / LDAP / SMB functionality
		• Confirm users can still authenticate
Check Windows event logs for early red team activity
