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

**`high`**
- High criticality events
- Cron/user/group changes
- Network/SSHD/root SSH key changes

**`power`**
- Messing with power state (reboot, shutdown, etc.)

**`ps`**
- Forked processes and network activity

### Important events

> ⚠️ These events **may or may not** require investigation

**`medium`**
- Medium severity rules
- Changing system startup scripts (init)
- Modifying/viewing firewall rules
- Modifying shell/profile configurations
- Use of ptrace
- Linking operations (ex. symlinks)

**`sudo`**
- Use of sudo and su

**`stunnel`**
- Using [stunnel](https://www.stunnel.org/)

**`bins`**
- Using suspicious binaries (`ccdcadmin` user is exempt)

### Other events

> ℹ️ Informational events that are low severity or can be used to correlate other activity 

**`low`**
- Low criticalifty events
- Failed permissions access on common directories
- Recon commands (ex. `id`)
- PAM changes

**`tamper`**
- Attempts to change the auditd settings

**`session`**
- Logins and login attempts

**`perms`**
- Modifying file permissions
- Modifying file attributes

**`systemd`, `modules`**
- Modifying systemd stuff
- Loading modules

**`docker`**
- Docker changes

**`kubelet`**
- Changes to the kubelet file

**`software_mgmt`, `third_party_sfotware_mgmt`**
- Using package managers (ex. apt, dnf, yum)