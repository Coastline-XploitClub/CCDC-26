# How to use a configured machine

## Login information
- Username: `ccdcadmin` (see baseline-security/vars/main.yaml for configured admin_user)
- Password: None. Use SSH key-based authentication (contact Ansible team member for the key)

## Reading Auditd logs
Each auditd rule has a tag to identify categories of suspicious behavior.
Usage:
```
# Searching by event name
ausearch -i -k <event_name>

# Searching by parent process
ausearch -i -pp <PPID>

# Correlating with running processes
ps ef | grep <PPID>
ps ef --forest

# Summary of all events
aureport --summary

# Reading raw logs
cat /var/log/audit/audit.log
```

### Critical events

> 🛑 These events most likely require investigation

**`etcgroup`, `etcpasswd`, `opasswd`, `group_modification`, `passwd_modification`, `user_modification`**
- Modifying group, passwd, gshadow, shadow, or /etc/security/opasswd files
- Using passwd command
- Using and user modification commands

**`actions`**
- Editing sudoers files

**`remote_shell`**
- Remote shell use (bash)

**`sbin_susp`**
- Suspicious sbin usage (ex. iptables, ufw, traceroute)

**`susp_shell`**
- Suspicious shell usage (ex. tmux)

**`recon`**
- Common reconnaissance commands (ex. whoami)
- Some `id` commands may be false positives--check PPID in `ps`

**`susp_activity`**
- Suspicious activity (ex. netcat, nmap, wireshark)

**`power`**
- Messing with power state (reboot, shutdown, etc.)

**`sshd`, `rootkey`**
- Changing SSH configs
- Tampering with root and admin user SSH key

### Important events

> ⚠️ These events **may or may not** require investigation

**`sysctl`, `modules`, `modprobe`**
- Changing kernel settings and modules

**`mount`, `T1078_Valid_Accounts`**
- Changing moint settings
- NFS mounts
- SSSD (`T1078_Valid_Accounts`)

**`stunnel`**
- Using [stunnel](https://www.stunnel.org/)

**`cron`**
- Modifying crontabs (user or system)

**`login`**
- Editing login settings (login.defs, securetty, faillog, tallylog)

**`network_modifications`**
- Changing network settings

**`init`, `systemd`, `systemd_generator`**
- Changing scripts for startup

**`session`**
- Creating sessions (utmp, btmp, wtmp)

**`shell_profiles`**
- Modifying shell configurations (ex. bashrc)

**`code_injection`, `data_injection`, `register_injection`, `tracing`**
- Using injection via ptrace

**`network_socket_created`**
- Creation of ipv4 and ipv6 sockets

### Other events

> ℹ️ These events may be false positives, use judgement to determine if they warrant investigation

**`auditlog`**
- Attempts to change the auditd settings

**`audittools`**
- Attempts to read/access auditd logs/trails

**`unauthedfileaccess`**
- Permission denied on file access when using `open` command

**`power_abuse`**
- When admin user looks in another user's home dir 
- False positive if user is `ccdcadmin`

**`priv_esc`, `pkexec`**
- Privilege escalation
- Using sudo or su
- Using [pkexec](https://linux.die.net/man/1/pkexec)

**`perm_mod`**
- Modifying file permissions
- Modifying file attributes

**`software_mgmt`**
- Using package managers (ex. apt, dnf, yum)

**`string_search`**
- Using grep and similar programs

**`Data_Compressed`**
- Using compression programs (ex. zip, tar)

