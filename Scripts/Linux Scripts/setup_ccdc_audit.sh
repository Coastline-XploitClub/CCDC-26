#!/bin/bash
# ==============================================================================
# CCDC Auditd Quick-Deploy & Beginner-Friendly Log Viewer (v5 - Cross-Distro)
# Supports: Rocky Linux, RHEL, CentOS, AlmaLinux, Ubuntu, Debian, Kali Linux
# Usage:    sudo bash setup_ccdc_audit.sh
# ==============================================================================

set -e

if [ "$EUID" -ne 0 ]; then
    echo "[-] Please run as root: sudo bash $0"
    exit 1
fi

echo "[*] Checking for auditd installation..."
if ! command -v auditctl >/dev/null 2>&1; then
    echo "[*] Installing auditd..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y && apt-get install -y auditd audispd-plugins
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y audit
    elif command -v yum >/dev/null 2>&1; then
        yum install -y audit
    else
        echo "[-] Could not detect package manager. Please install auditd manually."
        exit 1
    fi
fi

echo "[*] Building cross-distro CCDC audit rules in /etc/audit/rules.d/ccdc.rules..."
mkdir -p /etc/audit/rules.d

cat << 'RULES' > /etc/audit/rules.d/ccdc.rules
# Clear existing rules and set buffer size
-D
-b 8192

# 0. Noise Exclusions (Ignore routine GUI/desktop sandbox & PAM check helpers)
-a never,exit -F dir=/usr/libexec/ -S execve
-a never,exit -F exe=/usr/bin/bwrap -S execve
-a never,exit -F exe=/usr/sbin/unix_chkpwd -S execve

# 1. Identity & Privilege Escalation Persistence (RED ALERTS)
-w /etc/passwd -p wa -k identity_change
-w /etc/shadow -p wa -k identity_change
-w /etc/group -p wa -k identity_change
-w /etc/sudoers -p wa -k sudo_change
-w /etc/sudoers.d/ -p wa -k sudo_change
-w /root/.ssh/ -p wa -k ssh_backdoor

# 2. Scheduled Tasks, Service & Login Persistence (PURPLE ALERTS)
-w /etc/crontab -p wa -k persistence
-w /etc/cron.d/ -p wa -k persistence
-w /var/spool/cron/ -p wa -k persistence
-w /etc/systemd/system/ -p wa -k persistence
-w /etc/update-motd.d/ -p wa -k persistence
-w /etc/profile.d/ -p wa -k persistence

# 3. Webserver Configuration Tampering (PURPLE ALERTS)
-w /etc/httpd/ -p wa -k web_config
-w /etc/apache2/ -p wa -k web_config
-w /etc/nginx/ -p wa -k web_config
RULES

# 4. Webshell / RCE Detection (Placed BEFORE user_cmd so first-match rule priority catches it)
for web_user in apache www-data nginx; do
    if id -u "$web_user" >/dev/null 2>&1; then
        web_uid=$(id -u "$web_user")
        echo "[+] Detected webserver user '$web_user' (UID: $web_uid) -> Adding RED webshell RCE rule..."
        cat << RULES >> /etc/audit/rules.d/ccdc.rules

# Webshell / RCE Detection for $web_user (UID $web_uid)
-a always,exit -F arch=b64 -S execve -F uid=$web_uid -F success=1 -k webshell_cmd
-a always,exit -F arch=b32 -S execve -F uid=$web_uid -F success=1 -k webshell_cmd
RULES
    fi
done

cat << 'RULES' >> /etc/audit/rules.d/ccdc.rules

# 5. Interactive Human Command Execution (YELLOW ALERTS - auid>=1000)
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=4294967295 -F success=1 -k user_cmd
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=4294967295 -F success=1 -k user_cmd

# 6. Audit Tampering Detection (RED ALERTS)
-w /etc/audit/ -p wa -k audit_tamper
-w /sbin/auditctl -p x -k audit_tamper
-w /usr/sbin/auditctl -p x -k audit_tamper
RULES

echo "[*] Loading audit rules into kernel..."
systemctl enable auditd >/dev/null 2>&1 || true
service auditd restart >/dev/null 2>&1 || systemctl restart auditd >/dev/null 2>&1 || true
augenrules --load >/dev/null 2>&1 || true
auditctl -R /etc/audit/rules.d/ccdc.rules >/dev/null 2>&1 || true

echo "[*] Creating color-coded 'audit-live' stream viewer..."
cat << 'LIVE' > /usr/local/bin/audit-live
#!/bin/bash
if [ "$EUID" -ne 0 ]; then
    exec sudo "$0" "$@"
fi

echo -e "\033[1;32m=== CCDC Live Audit Stream v5 (Press Ctrl+C to exit) ===\033[0m"
echo -e "Colors: \033[1;31m[RED = Webshell / Account / SSH Tamper]\033[0m  \033[1;35m[PURPLE = Persistence / Config]\033[0m  \033[1;33m[YELLOW = User Cmd]\033[0m\n"

tail -Fn0 /var/log/audit/audit.log | while read -r line; do
    echo "$line"
done | ausearch -i 2>/dev/null | awk '
function extract(str, key,    idx, tmp) {
    idx = index(str, key)
    if (idx == 0) return ""
    tmp = substr(str, idx + length(key))
    sub(/ .*/, "", tmp)
    return tmp
}
/^----/ {
    if (tag != "" && tag != "(null)" && skip == 0 && detail != "") {
        display_user = auser
        if (euser != "" && euser != auser && auser != "system") {
            display_user = auser "->" euser
        } else if (auser == "system" && euser != "") {
            display_user = euser
        }

        if (tag == "webshell_cmd" || tag == "identity_change" || tag == "sudo_change" || tag == "ssh_backdoor" || tag == "audit_tamper") {
            # Bright Red for critical threats
            printf "\033[1;36m[%s]\033[0m \033[1;31m%-16s\033[0m User:\033[1;31m%-16s\033[0m \033[1;31m%s\033[0m\n", time, tag, display_user, detail
        } else if (tag == "persistence" || tag == "web_config") {
            # Bright Purple for persistence/config changes
            printf "\033[1;36m[%s]\033[0m \033[1;35m%-16s\033[0m User:\033[1;35m%-16s\033[0m \033[1;35m%s\033[0m\n", time, tag, display_user, detail
        } else {
            # Yellow/Green for standard commands
            printf "\033[1;36m[%s]\033[0m \033[1;33m%-16s\033[0m User:\033[1;32m%-16s\033[0m %s\n", time, tag, display_user, detail
        }
    }
    time=""; tag=""; auser="system"; euser=""; detail=""; skip=0
}
/msg=audit\(/ {
    tmp = $0
    sub(/.*msg=audit\(/, "", tmp)
    sub(/\).*/, "", tmp)
    sub(/\.[0-9]+:[0-9]+$/, "", tmp)
    time = tmp
}
/ key=/ {
    k = extract($0, " key=")
    if (k != "") tag = k
}
/ auid=/ {
    u = extract($0, " auid=")
    if (u != "" && u != "unset") auser = u
    eu = extract($0, " uid=")
    if (eu != "") euser = eu
}
/^type=EXECVE/ {
    tmp = $0
    sub(/^type=EXECVE msg=audit\([^)]+\)[ :]+/, "", tmp)
    sub(/argc=[0-9]+ /, "", tmp)
    gsub(/a[0-9]+=/, "", tmp)
    gsub(/^ +| +$/, "", tmp)

    # Filter Kali desktop widget, ausearch viewer self-noise, & login boilerplate
    if (index(tmp, "xfce4-panel-genmon-vpnip.sh") || \
        index(tmp, "/etc/update-motd.d") || \
        index(tmp, "/usr/bin/kali-motd") || \
        index(tmp, "kali-linux-headless") || \
        index(tmp, "ausearch -i") || \
        index(tmp, "ip addr show") || \
        index(tmp, "ip tuntap show") || \
        index(tmp, "head -n 1") || \
        index(tmp, "cut -d : -f1") || \
        index(tmp, "dircolors -b") || \
        index(tmp, "tput setaf 1") || \
        index(tmp, "(?<=inet )[0-9]{1,3}")) {
        skip = 1
    }
    if (tmp == "-zsh" || tmp == "-bash") {
        detail = "\033[1;35m[NEW LOGIN SHELL STARTED: " tmp "]\033[0m"
    } else {
        detail = "CMD:  " tmp
    }
}
/^type=PATH/ && detail == "" && tag != "user_cmd" && tag != "webshell_cmd" {
    p = extract($0, " name=")
    if (p != "") detail = "FILE: " p
}
'
LIVE
chmod +x /usr/local/bin/audit-live

echo "[*] Creating search & summary commands in /usr/local/bin/..."

cat << 'CMDS' > /usr/local/bin/audit-cmds
#!/bin/bash
echo -e "\033[1;36m=== Interactive User & Webshell Commands Executed (Recent, Filtered) ===\033[0m"
sudo ausearch -k user_cmd -k webshell_cmd -i 2>/dev/null \
    | awk -v RS="----\n" '
      !/xfce4-panel-genmon-vpnip\.sh/ && \
      !/a0=ip a1=(addr|tuntap) a2=show/ && \
      !/a0=head a1=-n a2=1/ && \
      !/a0=cut a1=-d a2=: a3=-f1/ && \
      !/\(\?<=inet \)\[0-9\]/ { printf "----\n%s", $0 }' \
    | grep -E "^----|type=SYSCALL|type=EXECVE" \
    | tail -n 60
CMDS

cat << 'FILES' > /usr/local/bin/audit-files
#!/bin/bash
echo -e "\033[1;33m=== Critical File, Web Config & Persistence Modifications ===\033[0m"
sudo ausearch -k identity_change -k sudo_change -k ssh_backdoor -k persistence -k web_config -k audit_tamper -i 2>/dev/null | grep -E "^----|type=SYSCALL|type=PATH" | tail -n 60
FILES

cat << 'LOGINS' > /usr/local/bin/audit-logins
#!/bin/bash
echo -e "\033[1;32m=== Authentication & Login Report ===\033[0m"
sudo aureport -au -i
LOGINS

cat << 'SUMMARY' > /usr/local/bin/audit-summary
#!/bin/bash
echo -e "\033[1;35m=== Triggered Alert Summary by Rule Key ===\033[0m"
sudo aureport -k -i
SUMMARY

chmod +x /usr/local/bin/audit-cmds /usr/local/bin/audit-files /usr/local/bin/audit-logins /usr/local/bin/audit-summary

echo ""
echo "=========================================================="
echo "[+] CCDC Auditd Setup (v5) Complete!"
echo "=========================================================="
echo "Available commands for your team (run from any terminal):"
echo "  audit-live     -> Live color-coded feed (Red = Webshell/PrivEsc, Purple = Persistence, Yellow = Cmd)"
echo "  audit-summary  -> High-level scoreboard of triggered rule tags"
echo "  audit-cmds     -> Recent interactive & webshell commands"
echo "  audit-files    -> Recent edits to passwd, sudoers, ssh, cron, systemd, web configs"
echo "  audit-logins   -> Table of successful and failed logins"
echo "=========================================================="