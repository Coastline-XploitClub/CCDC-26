#!/bin/sh

# ==============================================================================
# Script Name: enum_system.sh
# Description: Enumerates basic system info, users, groups, and sudo privileges.
# Author:      dsub
# Note:        Run as root for full visibility (shadow file, sudoers).
# ==============================================================================

# POSIX-compliant color setup
if [ -t 1 ]; then
  GREEN=$(printf '\033[0;32m')
  YELLOW=$(printf '\033[1;33m')
  RED=$(printf '\033[0;31m')
  NC=$(printf '\033[0m') # No Color
else
  GREEN=""
  YELLOW=""
  RED=""
  NC=""
fi

printf "%s========================================================%s\n" "$GREEN" "$NC"
printf "%s              Basic System Enumeration                  %s\n" "$GREEN" "$NC"
printf "%s========================================================%s\n" "$GREEN" "$NC"
printf "\n"

# Check if user is root
if [ "$(id -u)" -ne 0 ]; then
  printf "%s========================WARNING=========================%s\n" "$RED" "$NC"
  printf "%sNOT RUNNING AS ROOT. THIS SCRIPT SHOULD BE RUN AS ROOT! %s\n" "$RED" "$NC"
  printf "%s========================================================%s\n" "$RED" "$NC"
fi

# --- 1. OS & Kernel Info ---
printf "%s## 1. System Information ##%s\n" "$YELLOW" "$NC"
printf "Hostname: %s\n" "$(hostname)"
printf "Kernel:   %s\n" "$(uname -r)"

if [ -f /etc/os-release ]; then
    # Extract PRETTY_NAME safely
    os_name=$(grep '^PRETTY_NAME=' /etc/os-release | cut -d= -f2 | tr -d '"')
    printf "OS:       %s\n" "$os_name"
elif [ -f /etc/issue ]; then
    # Read first line of issue file
    printf "OS:       %s\n" "$(head -n 1 /etc/issue)"
else
    printf "OS:       Unknown\n"
fi
printf "\n"

# --- 2. Network Info ---
printf "%s## 2. Network Interfaces ##%s\n" "$YELLOW" "$NC"
# Use 'ip' if available, fallback to 'ifconfig'
if command -v ip > /dev/null 2>&1; then
    ip -brief addr
elif command -v ifconfig > /dev/null 2>&1; then
    ifconfig -a | grep -E 'Link|inet'
else
    printf "No network command found.\n"
fi
printf "\n"

# --- 3. ARP Cache (Neighbors) ---
printf "%s## 3. ARP Cache (Neighbors) ##%s\n" "$YELLOW" "$NC"
if command -v ip > /dev/null 2>&1; then
    printf "==> Using 'ip neigh':\n"
    ip neigh
elif command -v arp > /dev/null 2>&1; then
    printf "==> Using 'arp -n':\n"
    arp -n
elif [ -f /proc/net/arp ]; then
    printf "==> Reading /proc/net/arp:\n"
    cat /proc/net/arp
else
    printf "No tools found to read ARP cache.\n"
fi
printf "\n"

# --- 4. Open Ports (Listening) ---
printf "%s## 4. Open Ports (Listening) ##%s\n" "$YELLOW" "$NC"
# Try ss (Socket Stats) - modern replacement
if command -v ss > /dev/null 2>&1; then
    printf "==> Using 'ss -tulpn' (TCP/UDP Listening Numeric):\n"
    ss -tulpn | grep -v 127.0.0
    printf "\n"
# Fallback to netstat if ss is not available
elif command -v netstat > /dev/null 2>&1; then
    printf "==> Using 'netstat -tulpn':\n"
    netstat -tulpn | grep -v 127.0.0
    printf "\n"
else
    printf "Neither 'ss' nor 'netstat' commands were found.\n"
fi
printf "\n"

# --- 5. Running Services ---
printf "%s## 5. Running Services ##%s\n" "$YELLOW" "$NC"
if command -v systemctl > /dev/null 2>&1; then
    printf "==> Systemd detected (Active Services):\n"
    systemctl list-units --type=service --state=running --no-pager
elif command -v rc-status > /dev/null 2>&1; then
    printf "==> OpenRC detected (rc-status):\n"
    rc-status
elif command -v service > /dev/null 2>&1; then
    printf "==> SysVinit detected (service --status-all):\n"
    # Filter for running services (+) usually denoted by [ + ]
    service --status-all 2>/dev/null | grep '+'
else
    printf "No common service manager found (systemd, OpenRC, or SysVinit).\n"
fi
printf "\n"

# --- 6. Superusers (UID 0) ---
printf "%s## 6. Users with UID 0 (Root Access) ##%s\n" "$YELLOW" "$NC"
# Look for '0' in the 3rd field (UID) of /etc/passwd
awk -F: '($3 == "0") {print $1}' /etc/passwd
printf "\n"

# --- 7. Users with Login Shells ---
printf "%s## 7. Users with Valid Shells ##%s\n" "$YELLOW" "$NC"
# Filter out nologin/false shells to find actual humans or service accounts
if [ -f /etc/shells ]; then
    # Build regex from /etc/shells: remove comments/empty lines, replace newline with pipe
    shell_regex=$(grep -Ev '^#|^$' /etc/shells | tr '\n' '|' | sed 's/|$//')
else
    shell_regex=""
fi

# Fallback to common shells if /etc/shells is missing or empty
if [ -z "$shell_regex" ]; then
    shell_regex="/bin/bash|/bin/sh|/bin/zsh|/bin/ash|/bin/tcsh|/bin/ksh"
fi

grep -E "$shell_regex" /etc/passwd | awk -F: '{printf "%-15s UID:%s Shell:%s\n", $1, $3, $7}'
printf "\n"

# --- 8. Registered Shells & Multiplexers ---
printf "%s## 8. Registered Shells & Multiplexers ##%s\n" "$YELLOW" "$NC"
printf "==> Shell Versions (from /etc/shells):\n"
if [ -f /etc/shells ]; then
    # Filter out comments and empty lines
    grep -Ev '^#|^$' /etc/shells | while read -r shell_path; do
        if [ -x "$shell_path" ]; then
            # Determine shell name to handle specific version flags
            shell_name=$(basename "$shell_path")
            case "$shell_name" in
                sh|dash|ash|tcsh)
                    # These shells typically don't support --version or -v
                    ver="Version flag not supported"
                    ;;
                tmux)
                    # Tmux uses -V (capital)
                    ver=$("$shell_path" -V 2>&1 | head -n 1)
                    ;;
                *)
                    # Default: try --version
                    ver=$("$shell_path" --version 2>&1 | head -n 1)
                    # Clean up if the shell returned an error message about the flag
                    if echo "$ver" | grep -q -E "Illegal option|usage:|invalid option|not found"; then
                        ver="Version flag not supported"
                    fi
                    ;;
            esac
            
            # Print formatted output
            printf "  %-20s: %s\n" "$shell_path" "$ver"
        fi
    done
else
    printf "  /etc/shells not found.\n"
fi
printf "\n"

printf "==> Terminal Multiplexers:\n"
if command -v screen > /dev/null 2>&1; then
    printf "Screen detected: "
    screen -v 2>&1 | head -n 1 | awk '{print "Screen " $3 " (" $4 ")"}'
else
    printf "Screen: Not found\n"
fi

if command -v tmux > /dev/null 2>&1; then
    printf "Tmux detected:   "
    tmux -V
else
    printf "Tmux:   Not found\n"
fi
printf "\n"

# --- 9. Empty Password Fields ---
printf "%s## 9. Accounts with Empty Passwords ##%s\n" "$YELLOW" "$NC"
printf "==> Checking for null passwords in /etc/shadow:\n"
if [ -r /etc/shadow ]; then
    # Look for empty password field (field 2 is empty)
    awk -F: '($2 == "") {print $1 " has NO PASSWORD!"}' /etc/shadow
    if [ $? -ne 0 ]; then
         printf "None found (Good).\n"
    fi
else
    printf "%sCannot read /etc/shadow (Run as root).%s\n" "$RED" "$NC"
fi

printf "==> Checking for null / compromised passwords in /etc/passwd:\n"
printf "==> If field is empty [] user can login without a password.\n"
printf "==> If field contains a [hash], that hash is compromised.\n"
# Check if 2nd field is NOT 'x'
awk -v red="$RED" -v nc="$NC" -F: '($2 != "x") {print red "RISK: User " $1 " has [" $2 "] in /etc/passwd (Should be x)" nc}' /etc/passwd
printf "\n"

# --- 10. Sudoers Configuration ---
printf "%s## 10. Sudoers Configuration ##%s\n" "$YELLOW" "$NC"
if [ -r /etc/sudoers ]; then
    printf "==> Entries with 'NOPASSWD' (Risky):\n"
    # Grep recursively in /etc/sudoers and the .d directory
    grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null
    if [ $? -ne 0 ]; then
        printf "None found.\n"
    fi
    printf "\n"

    # Consolidate all sudoers file content for parsing
    # Use find to safely cat existing files in both locations
    sudo_content=$(find /etc/sudoers /etc/sudoers.d -type f -exec cat {} + 2>/dev/null)

    printf "==> Users with 'ALL' Privileges:\n"
    # Regex: Start of line, optional space, username, space, ALL
    printf "%s\n" "$sudo_content" | grep -E '^\s*[a-zA-Z0-9_-]+\s+ALL' | awk '{print $1}' | sort -u
    printf "\n"

    printf "==> Groups with 'ALL' Privileges:\n"
    # Regex: Start of line, optional space, %groupname, space, ALL
    printf "%s\n" "$sudo_content" | grep -E '^\s*%[a-zA-Z0-9_-]+\s+ALL' | awk '{print $1}' | sed 's/%//' | sort -u
    printf "\n"
    
    printf "==> Checking for relative paths in sudoers (Security Risk):\n"
    # Find non-comment lines containing '=' (assignments) inside sudoers files
    grep -r "^[^#]" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep "=" | grep -v "Defaults" | while IFS=':' read -r filename line; do
        # Extract text after last ')'
        raw_cmd=$(echo "$line" | awk -F')' '{print $NF}')
        
        # Trim leading whitespace
        cmd=$(echo "$raw_cmd" | sed 's/^[[:space:]]*//')
        
        # Remove NOPASSWD: or PASSWD: tags if present
        cmd=$(echo "$cmd" | sed 's/^\(NO\)*PASSWD:[[:space:]]*//')
        
        # Check if the remaining command is valid
        if [ "$cmd" != "ALL" ] && [ -n "$cmd" ]; then
            case "$cmd" in
                /*) ;; # Starts with /, so it's an absolute path (Good)
                *) printf "%sRISK: Relative path detected in %s: %s%s\n" "$RED" "$filename" "$line" "$NC" ;;
            esac
        fi
    done
else
    printf "%sCannot read /etc/sudoers (Run as root).%s\n" "$RED" "$NC"
fi
printf "\n"

# --- 11. Admin Group Members ---
printf "%s## 11. Members of Admin Groups ##%s\n" "$YELLOW" "$NC"
# Check standard admin groups:
for group in root wheel sudo adm disk docker lxd shadow; do
    # Only verify if group exists in /etc/group
    if grep -q "^$group:" /etc/group; then
        members=$(grep "^$group:" /etc/group | cut -d: -f4)
        if [ -n "$members" ]; then
            printf "Group %s%s%s: %s\n" "$GREEN" "$group" "$NC" "$members"
        else
            printf "Group %s%s%s: (Empty)\n" "$GREEN" "$group" "$NC"
        fi
    fi
done
printf "\n"

# --- 12. Currently Logged In Users ---
printf "%s## 12. Currently Logged In ##%s\n" "$YELLOW" "$NC"
if command -v w > /dev/null 2>&1; then
    w
elif command -v who > /dev/null 2>&1; then
    printf "==> Using 'who' (w command not found):\n"
    who -a
elif command -v users > /dev/null 2>&1; then
    printf "==> Using 'users' (w/who commands not found):\n"
    users
else
    printf "No standard tools found to list logged in users.\n"
fi
printf "\n"
printf "Failsafe method to list sessions using /dev/pts/ if above doesn't work\n"
ls -l /dev/pts/ | grep -E '^[c]' | awk '{print "User: " $3 " (TTY: pts/" $NF ")"}'
printf "\n"

# --- 13. Environment Variables ---
printf "%s## 13. Environment Variables ##%s\n" "$YELLOW" "$NC"
# Listing all environment variables. Useful for finding malicious PATHs or LD_PRELOAD.
env
printf "\n"

# --- 14. Private Encryption Key Files ---
printf "%s## 14. Private Encryption Key Files ##%s\n" "$YELLOW" "$NC"
# Searches filesystem for private keyfiles. Should find most SSH keys on system.
find /root /home /etc /opt /mnt /srv /var /tmp -type f \( -name "id_*" -o -name "*.pem" -o -name "*.key" \) ! -name "*.pub" 2>/dev/null | \
while read -r path; do
  head -1 "$path" 2>/dev/null | grep -q -- '-----BEGIN.*PRIVATE KEY-----' && echo "$path"
done
printf "\n"

printf "%s========================================================%s\n" "$GREEN" "$NC"
printf "%s                  Enumeration Complete                  %s\n" "$GREEN" "$NC"
# Another root user check
if [ "$(id -u)" -ne 0 ]; then
  printf "%sNOT RUNNING AS ROOT. THIS SCRIPT SHOULD BE RUN AS ROOT! %s\n" "$RED" "$NC"
fi
printf "%s========================================================%s\n" "$GREEN" "$NC"
