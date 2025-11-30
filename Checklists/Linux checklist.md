✅ **CCDC Checklist**

---

### **0 Pre-Game**

- [ ] Confirm all team roles and communication channels
- [ ] Identify scored services and assign watchers (scoring engine may appear as an unknown user)
- [ ] Define credential change plan and change order
- [ ] Prepare inject submission templates and documentation format

---

### **1 Assessment** (15 minutes MAX)
> ℹ️ Be able to answer "what does your box do?"

- [ ] Change root password for system (`root` never scored)
```bash
# Change any users password
passwd <username>

# Change root password
passwd root
```
- [ ] Record initial host state: hostname, IPs, services, and abnormalities (dump info in team spreadsheet if not already filled)
> ✅ can use `enumerator.sh` for this! https://github.com/Coastline-XploitClub/CCDC-26/blob/6001824dd56db71ed9d314ffadd6cbb01649f5a1/Scripts/ansible/baseline-role/files/enumerator.sh
```bash
# Get hostname
hostname

# Get ip address(es)
ip a
ifconfig

# Check open ports
## Option 1:
ss -tulnp
## Option 2:
netstat -tunalp

# Get running services
systemctl --type=service --state=running
```
- [ ] Enumeration/understanding of web services and services running (what is their purpose? What does it do? Is it necessary? Can it be abused?)

## Service Inspection
- For web services, run netstat -tunalp and look for ports like 80 443 8080 9000 and common web ports.
- Navigate to the IP of your box with the ports in a browser to investigate the web apps

👁️‍🗨️ Document:
  - Service name and port (reference `systemctl` or `ps aux`)
  - Administrative default creds (combination of Googling and default competition creds)
✏️ Change:
  - Adminsitrative default creds
👁️‍🗨️ Document:
  - Config location and/or data location to back up
  - If sensitive data/PII stored and where
  - If anonymous/no-password login
  - Are there domain accounts?

- [ ] IF you have a docker container, enumerate the container info
```bash
# Get list of running containers
docker ps

# Get additional information about any container
docker inspect <container ID>

# Search for yaml (or .yml) files for docker compose:
find / \( -iname "*.yaml" -o -iname "*.yml" \)

# Backup docker volumes
docker run --rm --volumes-from <CONTAINER NAME> -v $(pwd):/backup ubuntu tar cvf /backup/backup.tar /<VOLUME_NAME>
```
- [ ] Backups of all default configuration files and databases
```bash
#  Backup a folder
tar -cvf archive.tar /path/to/directory

# We want to check /opt, /etc, /var, home directories

# Backup databases
## MySQL
mysqldump -u root -p --all-databases > mysql_backup.sql

## Postgres
pg_dumpall -U postgres > postgres_backup.sql

## MongoDB
mongodump --out /path/to/backup/

## Redis
redis-cli SAVE
cp /var/lib/redis/dump.rdb ./redis_backup.rdb

```
- [ ] Stop any obvious unnecessary services. Ensure scored services remain up on scoring engine.
```bash
# Stop/disabling service (systemd)
systemctl stop <service>
systemctl disable <service>

# Stop service (SysV Init)
service <service> stop
update-rc.d <service-name> disable

# Stop service (Alpine)
rc-service <service> stop
rc-update del <service> default
```
- [ ] Evaluate common vulnerabilities (anonymous login, critical/high CVEs, exposed filesystems in file shares, etc.)

- Check version of service running, and cross-check with release notes (look for security patches in later updates), or search for CVEs for service.
- Take a note if you have to update the service to patch, or if there are any mitigations available that don't require updating.

- [ ] Find out if any other boxes rely upon a scored service

- Look in service's access logs (ex. web server logs), or run a tcpdump to listen on a port
```bash
tcpdump -i <interface> tcp and src net 192.168.220.0/24 and port <PORT> 
```

- [ ] List adminsitrative users
> ✅ can use `enumerator.sh` for this!
```bash
# Check /etc/sudoers and /etc/sudoers.d/*
cat /etc/sudoers
cat /etc/sudoers.d/*
```

> ⚠️ START DOCUMENTING ANY CHANGES MADE FROM THIS POINT ON!

### **2 Access Control**

- [ ] Apply easiest mitigations for high-impact vulnerabilities (critical/high CVEs, critical misconfigurations, etc.)
- [ ] Secure network shares and restrict anonymous access
- [ ] Treat unknown accounts as potentially scored; avoid deletions without validation
- [ ] Apply strong password and lockout policies
- [ ] Change passwords for other privileged user accounts, tokens, etc. (submit PCRs where necessary)
- [ ] Review and remove sketchy access (sudo, Administrators)
```bash
# One-liner SSH audit
for u in /home/* /root; do echo "=== $u/.ssh ==="; grep -R --line-number -E "id_rsa|id_ed25519|-----BEGIN.*PRIVATE KEY|ssh-ed25519|ssh-rsa|authorized_keys|Host|IdentityFile|User|Port" "$u" 2>/dev/null; find "$u" -type s -name "agent.*" 2>/dev/null; done; echo "=== /etc/ssh/sshd_config ==="; grep -R --line-number -E "PermitRootLogin|PasswordAuthentication|PubkeyAuthentication" /etc/ssh/sshd_config 2>/dev/null; echo "=== /etc/ssh/ssh_config ==="; grep -R --line-number -E "Host|IdentityFile" /etc/ssh/ssh_config 2>/dev/null
```

### **3 Hardening**

- [ ] Restrict management access paths and enforce access control
- [ ] Disable all non-essential or redundant services
- [ ] Enable host firewalls to allow only scored ports and management access
- [ ] Locate and remove persistence mechanisms (cron, systemd, startup tasks)
- [ ] Terminate suspicious or unnecessary sessions without impacting scoring
- [ ] Rotate all application and database secrets (submit PCRs where necessary)
- [ ] Understand startup tasks and scheduled jobs
```
Marcel
```

---

### **4 Sanity check**

- [ ] Enable system logging and auditing on every host
- [ ] Verify open ports align with the scoreboard
- [ ] Configure firewalls for default-deny inbound; allow only scored and management traffic
- [ ] Inspect routing tables, ARP cache, and gateways for anomalies

---

### **5 File System**

- [ ] Identify dangerous permissions, SUID/SGID files, and recent unauthorized changes
- [ ] Clean webroots of shells, backdoors, or unsafe upload handlers
- [ ] Verify file permissions across critical directories

---

### **6 Logging & Monitoring**

- [ ] Enable and centralize logs
- [ ] Configure log rotation and retention
- [ ] Monitor authentication and service activity continuously

---

### **7 Advanced Hardening**

- [ ] Apply remaining patches to critical and remotely exploitable services
- [ ] Enforce secure OS and service defaults
- [ ] Disable insecure protocols and legacy features (e.g., SMBv1, Telnet)
- [ ] Disable dangerous functions, directory listings, and sample apps

---

### **Incident Response**

- [ ] Maintain service availability while responding to incidents
- [ ] Isolate compromised systems through host or network controls
- [ ] Capture volatile data and logs before remediation
- [ ] Identify IOCs, remove persistence, rotate credentials
- [ ] Restore affected services and verify scoring functionality
- [ ] Document all findings and report to the white team

---

### **Every 15 Minutes**

- [ ] Confirm all scored services are green
- [ ] Review logs and detect new IOCs
- [ ] Check inject assignments and progress
- [ ] Update team log with current system changes and handoffs
