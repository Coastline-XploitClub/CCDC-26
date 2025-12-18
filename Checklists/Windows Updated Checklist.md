## Windows Updated Checklist For CCDC 26

## Windows First 30 minute checklist

## 1. Change Default Passwords (Password Change Request)
    a. Run Cesar’s script 
    b.Make changes in Active Directory Users and Computers

## 2. Audit user accounts/changing permissions
    a. Run  Automatic-Network-Enumeration.ps1
    b.Check permissions for Groups for Active Directory and Users

## 3. Check for low-hanging fruit vulnerabilities
    a. Check for SMBv1, Zerologon

## 4. Check group policies 
    a. Local Group Policy Editor by pressing Win + R, typing gpedit.msc

## 5. Grab back ups of everything
    a. Users/Groups/OUs/Services/GPO’s/DNS/NTDS

## 6. Stop/Disable unused/unscored services
    a.Check services required for machine to be up
    b. Disable services through GUI

## 7. Apply patches (if time permits) 
    a. Run windows update

## 8. Check for Firewall rules

## 9. Enable host firewalls to allow only scored ports and management access
    a.Go to control panel → check to see if firewalls are enabled
    b. Make sure Windows Defender is enabled

## 10. Monitor connections (netstat)

## 11. Explore the services or webapps and how they work

## 12. Sysmon installation (powershell)
## 1. Download
    wget -O Sysmon.zip https://download.sysinternals.com/files/Sysmon.zip
## 2. unzip the file
    unzip expand-Archive -Path Sysmon.Zip -DestinationPath .\Sysmon
## 3. Download the configureation file. SysmonConfig.xml tells Sysmon what is “important enough” to record and what should be ignored so your system stays secure and stable.
    wget -O sysmonconfig.xml https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml
## 4. Move the sysmonconfig.xml to sysmon folder. sysmonconfig.xml and Sysmon.exe must be in the same folder. 
    mv sysmonconfig.xml .\sysmon
## 5. You need to be in the Sysmon's folder in order to Run the following command to install sysmon. Use cd sysmon to be there. 
    cd Sysmom
    .\Sysmon.exe -accepteula -i .\sysmonconfig.xml
## 6. TOP Sysmon Event IDs FOR HUNTING
  ## Event ID 1 – Process Create

 ## What it shows:
 ## A program started.

 ## Almost everything malicious starts a process.

 ## What to hunt:
 ## cmd.exe, powershell.exe, wscript.exe, mshta.exe

 ## Processes running from Temp, Downloads, AppData
  
 ## Example red flags:
          powershell.exe -enc
          rundll32.exe suspicious.dll
          cmd.exe /c whoami
 ## Event ID 3 – Network Connection

 ## What it shows:
 ## A process opened a network connection.

 ## Why it’s gold:
 ## Shows who is talking to whom and why.

  ## What to hunt:
 ## LDAP (389) abuse

 ## Beaconing patterns

 ## Connections to unknown IPs

 ## Example red flags:

 ## powershell.exe making outbound connections

 ## vent ID 7 – Image Load

 ## Use carefully (noisy)

 ## What it shows:
 ## A DLL was loaded into a process.

 ## What to hunt (filtered):

 ## DLLs from Temp/AppData

 ## Unsigned DLLs

 ## DLLs loaded into lsass.exe

## Event ID 11 – File Create

 ## What it shows:
 ## A file was created.

 ## Good for:
 ## Dropped payloads
 ## Webshells
 ## EXEs in Temp folders
