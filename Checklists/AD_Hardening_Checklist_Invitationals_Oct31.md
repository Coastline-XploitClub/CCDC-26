# AD Hardening & Maintenance Checklist

Companion to the First 15 Minutes playbook. Use this for ongoing hardening and account cleanup once the initial lockdown is done. Work top to bottom; tick items off as you go. Document every change with a timestamp so you can tell your changes from the red team's.

## Account audit

Find every account that can log in, then flag anything you did not create. Backdoor accounts are the red team's first move.

- [ ] List all enabled users and scan for names you do not recognize:

```
Get-ADUser -Filter {Enabled -eq $true} | Select Name, SamAccountName
```

- [ ] Find recently created or modified accounts (likely backdoors):

```
Get-ADUser -Filter * -Properties whenCreated, whenChanged | Sort whenCreated -Descending | Select Name, whenCreated, whenChanged -First 20
```

- [ ] Find accounts set to never expire:

```
Get-ADUser -Filter {PasswordNeverExpires -eq $true} | Select Name
```

- [ ] Find accounts with Kerberos pre-auth disabled (AS-REP roasting targets):

```
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Select Name
```

- [ ] Find service accounts with an SPN set (Kerberoasting targets) and make sure their passwords are strong:

```
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName | Select Name, ServicePrincipalName
```

### Handling accounts set to never expire

Never-expire is not automatically bad, so judge each one:

- A **service account** running a scored service often needs this on purpose. Leave the flag, just confirm the password is strong. Resetting or expiring it can knock a scored service offline.
- A **normal user** with never-expire usually should not have it. The real risk is the password, so reset it (if the rules allow), then clear the flag: `Set-ADUser -Identity <name> -PasswordNeverExpires $false`.
- An account you **do not recognize at all** matters more than the setting. Treat it as a possible backdoor: check whenCreated, its groups, and whether it has admin rights.

## Hunt for persistence

If the red team got in before you locked things down, they left a way back. Common hiding spots:

- [ ] **Review every GPO.** A malicious GPO that runs a script, creates a scheduled task, or adds members to Administrators is a classic backdoor:

```
Get-GPO -All | Select DisplayName, CreationTime, ModificationTime
```

- [ ] **Check for unexpected delegation** (a privilege-escalation path):

```
Get-ADComputer -Filter {TrustedForDelegation -eq $true} | Select Name
Get-ADUser -Filter {TrustedForDelegation -eq $true} | Select Name
```

- [ ] **Check AdminSDHolder / adminCount.** Look for accounts with `adminCount=1` that are not currently in a privileged group:

```
Get-ADUser -Filter {adminCount -eq 1} -Properties adminCount | Select Name
```

- [ ] **Look for DCSync rights** granted to non-admin accounts (Replicating Directory Changes on the domain object).
- [ ] **krbtgt / Golden Ticket.** If the domain may have been compromised before you arrived, reset the `krbtgt` password **twice**, with a wait between resets, if the rules allow.
- [ ] **Local Administrators group on every machine**, not just the domain: `net localgroup Administrators` on each box.
- [ ] **Startup folders and Run registry keys** on each machine (`HKLM\...\Run` and `HKCU\...\Run`).
- [ ] **Scheduled tasks and services** on the DC and members that you did not create.
- [ ] **Firewall rules someone added** to let themselves back in.
- [ ] **RDP and WinRM access** scoped to only the groups that should have it.

## SMB hardening

- [ ] Confirm SMBv1 is actually off (not just that the command ran): `Get-SmbServerConfiguration | Select EnableSMB1Protocol` should return `False`.
- [ ] Disable SMBv1 if present: `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`.
- [ ] Require SMB signing so sessions cannot be tampered with or relayed: `Set-SmbServerConfiguration -RequireSecuritySigning $true -Force`.
- [ ] Audit shares and their permissions, watching for Everyone / Full Control: `Get-SmbShare | Select Name, Path` then `Get-SmbShareAccess -Name <share>`.
- [ ] Look for unexpected shares someone may have added as a foothold.
- [ ] On a scored-SMB box (a file server), keep the scoring check and legitimate users able to reach it. Signing and removing SMBv1 are safe; tightening share permissions needs care.

## Other network hardening

- [ ] **Disable LLMNR and NBT-NS** (defense against Responder / credential poisoning). LLMNR via GPO under DNS Client; NBT-NS per adapter or by GPO/script.
- [ ] **IPv6 / mitm6.** Keep IPv6 enabled (Microsoft recommends it on DCs) but block rogue DHCPv6 and router advertisements with firewall rules, so an attacker cannot become your IPv6 DNS server.

## Password and lockout policy

Set these in the **Default Domain Policy**: Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies.

- [ ] Minimum password length 14 or more
- [ ] Password complexity enabled
- [ ] Account lockout threshold set (for example 5 bad attempts)
- [ ] Lockout duration and reset counter set
- [ ] Run `gpupdate /force` on the DC afterward and confirm it applied

One caution: a lockout threshold can be used against you. If the red team deliberately locks out a scored service account, that service can go down. Watch for mass lockouts and know how to unlock quickly.

## Ongoing during the competition

Hardening is not one-and-done. The red team keeps trying, so keep checking.

- [ ] Re-check **Domain Admins** and the other privileged groups periodically; attackers re-add themselves.
- [ ] Watch for **new accounts** appearing that you did not create.
- [ ] Keep an eye on the **Security event log** for logon anomalies and mass lockouts.
- [ ] Re-confirm your **scored services** are still up after any change you make.
- [ ] **Document every change** with a timestamp.

### Key event IDs to watch

- 4624 — successful logon
- 4625 — failed logon
- 4672 — admin logon
- 4688 — new process created
- 4697 — new service installed
