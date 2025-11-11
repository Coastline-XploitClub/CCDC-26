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
```
passwd root
```
- [ ] Record initial host state: hostname, IPs, services, and abnormalities
```
hostname
ip a
ss -tulnp or netstat -tunalp
systemctl --type=service --state=running
```
- [ ] Enumeration/understanding of web services and services running (what is their purpose? What does it do? Is it necessary? Can it be abused?)
```
For web services, run netstat -tunalp and look for ports like 80 443 8080 9000 and common web ports. 
Then! Navigate to the IP of your box with the ports in a browser to investigate the web apps

👁️‍🗨️ Document:
  - Service name and port
  - Administrative default creds
✏️ Change:
  - Adminsitrative default creds
👁️‍🗨️ Document:
  - Config location and/or data location to back up
  - If sensitive data/PII stored and where
  - If anonymous/no-password login
  - Are there domain accounts?
```
- [ ] Backups of all default configuration files and databases
```
tar -cvf archive.tar /path/to/directory
Check /opt, /etc, /var, home directories
```
- [ ] Evaluate common vulnerabilities (anonymous login, critical/high CVEs, exposed filesystems in file shares, etc.)
```
Marcel
```
- [ ] Find out if any other boxes rely upon a scored service
```
tcpdump -i <interface> tcp and src net 192.168.220.0/24 and port <PORT> 
```
- [ ] List adminsitrative users
```
Check /etc/sudoers and /etc/sudoers.d/*
```

---

> ⚠️ START DOCUMENTING ANY CHANGES MADE FROM THIS POINT ON!

### **2 Access Control**

- [ ] Apply easiest mitigations for high-impact vulnerabilities (critical/high CVEs, critical misconfigurations, etc.)
- [ ] Secure network shares and restrict anonymous access
- [ ] Treat unknown accounts as potentially scored; avoid deletions without validation
- [ ] Apply strong password and lockout policies
- [ ] Change passwords for other privileged user accounts, tokens, etc. (submit PCRs where necessary)
- [ ] Review and remove sketchy access (sudo, Administrators)
```
Check for keys stored under ~/.ssh for each user
grep -R --line-number -E <phrase> <directories>
```

---

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
