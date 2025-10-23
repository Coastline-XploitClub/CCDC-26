#!/bin/bash

# ==============================================================================
# Script Name: list_firewall.sh
# Description: Enumerates firewall rules from UFW, firewalld, nftables,
#              and iptables.
# Author:      Gemini
# Note:        This script must be run as root.
# ==============================================================================

# Use colors for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}==================================================${NC}"
echo -e "${GREEN}            Firewall Rule Enumeration             ${NC}"
echo -e "${GREEN}==================================================${NC}"
echo

# --- 1. UFW (Uncomplicated Firewall) ---
# A common, easy-to-use frontend for iptables/nftables.
echo -e "${YELLOW}## 1. UFW (Uncomplicated Firewall) Status ##${NC}"
if command -v ufw &> /dev/null; then
    # The status command will report if UFW is active or inactive.
    ufw status verbose
else
    echo "UFW command not found. Skipping."
fi
echo "--------------------------------------------------"
echo

# --- 2. firewalld ---
# The default firewall manager on RHEL-based systems (CentOS, Fedora).
echo -e "${YELLOW}## 2. firewalld Status ##${NC}"
if command -v firewall-cmd &> /dev/null; then
    # Check if the service is actually running
    if systemctl is-active --quiet firewalld; then
        echo -e "firewalld service is ${GREEN}active${NC}."
        echo
        echo "--> Default and Active Zone Details:"
        firewall-cmd --list-all
    else
        echo -e "firewalld service is ${RED}not running${NC}."
    fi
else
    echo "firewall-cmd command not found. Skipping."
fi
echo "--------------------------------------------------"
echo

# --- 3. nftables ---
# The modern replacement for iptables. A single command lists the full ruleset.
echo -e "${YELLOW}## 3. nftables Ruleset ##${NC}"
if command -v nft &> /dev/null; then
    # Check if the nftables service is running and if there are rules
    if [ -n "$(nft list ruleset)" ]; then
        nft list ruleset
    else
        echo "nftables service may not be running or has no rules."
    fi
else
    echo "nft command not found. Skipping."
fi
echo "--------------------------------------------------"
echo

# --- 4. iptables (Legacy Firewall) ---
# It's crucial to check iptables directly, as rules can exist here
# even if a frontend like UFW is managing the firewall.
echo -e "${YELLOW}## 4. iptables Rules (IPv4 & IPv6) ##${NC}"
if command -v iptables &> /dev/null; then
    echo "--> IPv4 Rules (iptables):"
    echo -e "${GREEN}Filter Table (Default):${NC}"
    iptables -L -v -n
    echo
    echo -e "${GREEN}NAT Table:${NC}"
    iptables -t nat -L -v -n
    echo
    echo -e "${GREEN}Mangle Table:${NC}"
    iptables -t mangle -L -v -n
    echo
else
    echo "iptables command not found. Skipping IPv4."
fi

if command -v ip6tables &> /dev/null; then
    echo "--> IPv6 Rules (ip6tables):"
    echo -e "${GREEN}Filter Table (Default):${NC}"
    ip6tables -L -v -n
    echo
    echo -e "${GREEN}Mangle Table:${NC}"
    ip6tables -t mangle -L -v -n
    echo
else
    echo "ip6tables command not found. Skipping IPv6."
fi
echo "--------------------------------------------------"
echo

echo -e "${GREEN}==================================================${NC}"
echo -e "${GREEN}                 Enumeration Complete             ${NC}"
echo -e "${GREEN}==================================================${NC}"
