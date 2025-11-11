#!/bin/sh

# ==============================================================================
# Script Name: list_firewall.sh (POSIX-Compliant)
# Description: Enumerates firewall rules from UFW, firewalld, nftables,
#              and iptables.
# Author:      dsub
# Note:        This script must be run as root.
# ==============================================================================

# POSIX-compliant color setup
# Check if stdout is a terminal (tty) before using color codes
if [ -t 1 ]; then
  # printf interprets the octal \033 for ESC
  GREEN=$(printf '\033[0;32m')
  YELLOW=$(printf '\033[1;33m')
  RED=$(printf '\033[0;31m')
  NC=$(printf '\033[0m') # No Color
else
  # Disable colors if not a tty (e.g., piping to a file)
  GREEN=""
  YELLOW=""
  RED=""
  NC=""
fi

# Use printf for all output
printf "%s==================================================%s\n" "$GREEN" "$NC"
printf "%s            Firewall Rules Enumeration             %s\n" "$GREEN" "$NC"
printf "%s==================================================%s\n" "$GREEN" "$NC"
printf "\n"

# --- 1. UFW (Uncomplicated Firewall) ---
# A common, easy-to-use frontend for iptables/nftables.
printf "%s## 1. UFW (Uncomplicated Firewall) Status ##%s\n" "$YELLOW" "$NC"
if command -v ufw > /dev/null 2>&1; then
    # The status command will report if UFW is active or inactive.
    ufw status verbose
else
    printf "UFW command not found. Skipping.\n"
fi
printf "--------------------------------------------------\n"
printf "\n"

# --- 2. firewalld ---
# The default firewall manager on RHEL-based systems (CentOS, Fedora).
printf "%s## 2. firewalld Status ##%s\n" "$YELLOW" "$NC"
if command -v firewall-cmd > /dev/null 2>&1; then
    # Check if the service is actually running. Requires systemd, but so does firewalld.
    if command -v systemctl > /dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        printf "firewalld service is %sactive%s.\n" "$GREEN" "$NC"
        printf "\n"
        printf "--> Default and Active Zone Details:\n"
        firewall-cmd --list-all
    else
        printf "firewalld service is %snot running%s.\n" "$RED" "$NC"
    fi
else
    printf "firewall-cmd command not found. Skipping.\n"
fi
printf "--------------------------------------------------\n"
printf "\n"

# --- 3. nftables ---
# The modern replacement for iptables. A single command lists the full ruleset.
printf "%s## 3. nftables Ruleset ##%s\n" "$YELLOW" "$NC"
if command -v nft > /dev/null 2>&1; then
    # Check if the nftables service is running and if there are rules
    # This command structure is POSIX-compliant
    if [ -n "$(nft list ruleset 2>/dev/null)" ]; then
        nft list ruleset
    else
        printf "nftables service may not be running or has no rules.\n"
    fi
else
    printf "nft command not found. Skipping.\n"
fi
printf "--------------------------------------------------\n"
printf "\n"

# --- 4. iptables (Legacy Firewall) ---
# It's crucial to check iptables directly.
printf "%s## 4. iptables Rules (IPv4 & IPv6) ##%s\n" "$YELLOW" "$NC"
if command -v iptables > /dev/null 2>&1; then
    printf "--> IPv4 Rules (iptables):\n"
    printf "%sFilter Table (Default):%s\n" "$GREEN" "$NC"
    iptables -L -v -n
    printf "\n"
    printf "%sNAT Table:%s\n" "$GREEN" "$NC"
    iptables -t nat -L -v -n
    printf "\n"
    printf "%sMangle Table:%s\n" "$GREEN" "$NC"
    iptables -t mangle -L -v -n
    printf "\n"
else
    printf "iptables command not found. Skipping IPv4.\n"
fi

if command -v ip6tables > /dev/null 2>&1; then
    printf "--> IPv6 Rules (ip6tables):\n"
    printf "%sFilter Table (Default):%s\n" "$GREEN" "$NC"
    ip6tables -L -v -n
    printf "\n"
    printf "%sMangle Table:%s\n" "$GREEN" "$NC"
    ip6tables -t mangle -L -v -n
    printf "\n"
else
    printf "ip6tables command not found. Skipping IPv6.\n"
fi
printf "--------------------------------------------------\n"
printf "\n"

printf "%s==================================================%s\n" "$GREEN" "$NC"
printf "%s                 Enumeration Complete             %s\n" "$GREEN" "$NC"
printf "%s==================================================%s\n" "$GREEN" "$NC"
