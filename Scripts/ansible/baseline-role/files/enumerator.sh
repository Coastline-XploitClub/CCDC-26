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

printf "%s==================================================%s\n" "$GREEN" "$NC"
printf "%s           Basic System Enumeration               %s\n" "$GREEN" "$NC"
printf "%s==================================================%s\n" "$GREEN" "$NC"
printf "\n"

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

# --- 3. Open Ports (Listening) ---
printf "%s## 3. Open Ports (Listening) ##%s\n" "$YELLOW" "$NC"
# Try ss (Socket Stats) - modern replacement
if command -v ss > /dev/null 2>&1; then
    printf "--> Using 'ss -tulpn' (TCP/UDP Listening Numeric):\n"
    ss -tulpn | grep -v 127.0.0
    printf "\n"
fi

# Try netstat - legacy tool, but often available
if command -v netstat > /dev/null 2>&1; then
    printf "--> Using 'netstat -tulpn':\n"
    netstat -tulpn | grep -v 127.0.0
    printf "\n"
fi

if ! command -v ss > /dev/null 2>&1 && ! command -v netstat > /dev/null 2>&1; then
    printf "Neither 'ss' nor 'netstat' commands were found.\n"
fi
printf "\n"

# --- 4. Running Services ---
printf "%s## 4. Running Services ##%s\n" "$YELLOW" "$NC"
if command -v systemctl > /dev/null 2>&1; then
    printf "--> Systemd detected (Active Services):\n"
    systemctl list-units --type=service --state=running --no-pager
elif command -v rc-status > /dev/null 2>&1; then
    printf "--> OpenRC detected (rc-status):\n"
    rc-status
elif command -v service > /dev/null 2>&1; then
    printf "--> SysVinit detected (service --status-all):\n"
    # Filter for running services (+) usually denoted by [ + ]
    service --status-all 2>/dev/null | grep '+'
else
    printf "No common service manager found (systemd, OpenRC, or SysVinit).\n"
fi
printf "\n"

# --- 5. Superusers (UID 0) ---
printf "%s## 5. Users with UID 0 (Root Access) ##%s\n" "$YELLOW" "$NC"
# Look for '0' in the 3rd field (UID) of /etc/passwd
awk -F: '($3 == "0") {print $1}' /etc/passwd
printf "\n"

# --- 6. Users with Login Shells ---
printf "%s## 6. Users with Valid Shells ##%s\n" "$YELLOW" "$NC"
# Filter out nologin/false shells to find actual humans or service accounts
grep -E "/bin/bash|/bin/sh|/bin/zsh" /etc/passwd | awk -F: '{printf "%-15s UID:%s Shell:%s\n", $1, $3, $7}'
printf "\n"

# --- 7. Empty Password Fields ---
printf "%s## 7. Accounts with Empty Passwords (/etc/shadow) ##%s\n" "$YELLOW" "$NC"
if [ -r /etc/shadow ]; then
    # Look for empty password field (field 2 is empty)
    awk -F: '($2 == "") {print $1 " has NO PASSWORD!"}' /etc/shadow
    if [ $? -ne 0 ]; then
         printf "None found (Good).\n"
    fi
else
    printf "%sCannot read /etc/shadow (Run as root).%s\n" "$RED" "$NC"
fi
printf "\n"

# --- 8. Sudoers Configuration ---
printf "%s## 8. Sudoers Configuration ##%s\n" "$YELLOW" "$NC"
if [ -r /etc/sudoers ]; then
    printf "--> Entries with 'NOPASSWD' (Risky):\n"
    # Grep recursively in /etc/sudoers and the .d directory
    grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null
    if [ $? -ne 0 ]; then
        printf "None found.\n"
    fi
    printf "\n"

    # Consolidate all sudoers file content for parsing
    # Use find to safely cat existing files in both locations
    sudo_content=$(find /etc/sudoers /etc/sudoers.d -type f -exec cat {} + 2>/dev/null)

    printf "--> Users with 'ALL' Privileges:\n"
    # Regex: Start of line, optional space, username, space, ALL
    printf "%s\n" "$sudo_content" | grep -E '^\s*[a-zA-Z0-9_-]+\s+ALL' | awk '{print $1}' | sort -u
    printf "\n"

    printf "--> Groups with 'ALL' Privileges:\n"
    # Regex: Start of line, optional space, %groupname, space, ALL
    printf "%s\n" "$sudo_content" | grep -E '^\s*%[a-zA-Z0-9_-]+\s+ALL' | awk '{print $1}' | sed 's/%//' | sort -u
else
    printf "%sCannot read /etc/sudoers (Run as root).%s\n" "$RED" "$NC"
fi
printf "\n"

# --- 9. Admin Group Members ---
printf "%s## 9. Members of Admin Groups ##%s\n" "$YELLOW" "$NC"
# Check standard admin groups: wheel, sudo, adm, root
for group in wheel sudo adm root; do
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

# --- 10. Currently Logged In Users ---
printf "%s## 10. Currently Logged In ##%s\n" "$YELLOW" "$NC"
if command -v w > /dev/null 2>&1; then
    w
elif command -v who > /dev/null 2>&1; then
    printf "--> Using 'who' (w command not found):\n"
    who -a
elif command -v users > /dev/null 2>&1; then
    printf "--> Using 'users' (w/who commands not found):\n"
    users
else
    printf "No standard tools found to list logged in users.\n"
fi
printf "\n"

# --- 11. Environment Variables ---
printf "%s## 11. Environment Variables ##%s\n" "$YELLOW" "$NC"
# Listing all environment variables. Useful for finding malicious PATHs or LD_PRELOAD.
env
printf "\n"

printf "%s==================================================%s\n" "$GREEN" "$NC"
printf "%s               Enumeration Complete               %s\n" "$GREEN" "$NC"
printf "%s==================================================%s\n" "$GREEN" "$NC"
