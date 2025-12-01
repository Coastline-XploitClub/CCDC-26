## 🛡️ First 15 Minutes – Domain Controller Checklist (Domain Reset Scenario)

This version is used when the domain has been fully reset or rebuilt, requiring full stabilization, password changes, and a complete backup.

## 1. Log in to the Domain Controller

  Use the default competition password after reset.

Immediately change the Administrator password to the secure team password.

  Example:
  
  Default: OMGaTREX1?
  
  New Admin Password: Lily-hen-seminar123?
  
  🔥 Absolutely do this first.

## 2. Change All Domain User Passwords (Except Administrator)

  Run this immediately after changing Administrator’s password.

  Download
 
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Coastline-XploitClub/CCDC-26/main/Scripts/Powershell%20Scripts/Domain%20Controller%20Scripts/Change-All-Passwords.ps1" -OutFile "Change-All-Passwords.ps1"

  Run
  
    .\Change-All-Passwords.ps1


  Purpose:
  
  Resets every domain user password
  
  Prevents Red Team from using default credentials
  
  Administrator retains the password you manually set

## 3. Initial Recon – Identify Services Before Hardening

  From Kali:
    sudo nmap 192.168.220.12
    
    This confirms the baseline service exposure before applying firewall or GPO changes.


## 4. Apply Firewall_Rules.ps1 (Enables GPOs + Locks Down Services)
Download

    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Coastline-XploitClub/CCDC-26/main/Scripts/Powershell%20Scripts/Domain%20Controller%20Scripts/Firewall_Rules.ps1" -OutFile "Firewall_Rules.ps1"
  
  Run
  
    .\Firewall_Rules.ps1


  This:
  
  Enables GPOs for Domain Controllers + Windows machines
  
  Applies port restrictions
  
 

## 4A. DNS Hardening (Manual Steps)
  a. Fix DNS ACL

    Open DNS Manager
    
    Remove all accounts except your dedicated DNS admin
    
    Add your DNS admin (example: cesar_la)
    
    Give Full Control

b. Enable DNS Debug Logging

  Set location:

  C:\dns

c. Enable DNSSEC

  Right-click your zone → DNSSEC → Sign the Zone
  
  Keep default settings
  
  Click Add to generate keys
  
  Enable both checkboxes in final step
  
  Confirm DNSSEC shows as Enabled

## 5. Configure Logging inside the Domain Hardening GPO

  Open Group Policy Management
  
  Navigate:
  
    Domain Controllers → Domain Hardening
  
  
    Open:
    
    Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration


  Enable all categories required by your logging guide.

## 6. Run BlueShield.ps1 (Full Hardening)
  Download
  
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Coastline-XploitClub/CCDC-26/main/Scripts/Powershell%20Scripts/Domain%20Controller%20Scripts/BlueShield.ps1" -OutFile "BlueShield.ps1"
  
  Run
  
    .\BlueShield.ps1


  Follow secure defaults
  
  Do NOT disable IPv6 or LDAP unless absolutely required

## 7. Post-Hardening Enumeration

  After hardening:
  
  Check services
  
  Validate DNS / LDAP / SMB / Kerberos
  
  Review inbound firewall rules
  
  Confirm users can log in
  
  Review Event Viewer for Red Team indicators:

Key Event IDs:

  4624 (Successful logon)
  
  4625 (Failed logon)
  
  4672 (Admin logon)
  
  4688 (New process)
  
  4697 (New service installed)
