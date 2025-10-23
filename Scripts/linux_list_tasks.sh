#!/bin/bash

# ==============================================================================
# Script Name: list_tasks.sh
# Description: Enumerates all scheduled tasks on a Linux system, including
#              cron jobs, at jobs, and systemd timers.
# Author:      Gemini
# Note:        This script should be run as root for complete visibility.
# ==============================================================================

# Use colors for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}==================================================${NC}"
echo -e "${GREEN}      Scheduled Task & Cron Job Enumeration       ${NC}"
echo -e "${GREEN}==================================================${NC}"
echo

# --- 1. System-Wide Crontab ---
echo -e "${YELLOW}## 1. System-Wide Crontab (/etc/crontab) ##${NC}"
if [ -f /etc/crontab ]; then
    # Print non-commented, non-empty lines for clarity
    grep -Ev '^#|^$' /etc/crontab
else
    echo -e "${RED}/etc/crontab not found.${NC}"
fi
echo "--------------------------------------------------"
echo

# --- 2. Cron Jobs in /etc/cron.d/ ---
echo -e "${YELLOW}## 2. Additional System Cron Jobs (/etc/cron.d/) ##${NC}"
if [ -d /etc/cron.d ]; then
    # List all files and then print their active cron entries
    for cronfile in /etc/cron.d/*; do
        if [ -f "$cronfile" ]; then
            echo -e "--> Contents of ${GREEN}$cronfile${NC}:"
            grep -Ev '^#|^$' "$cronfile"
            echo
        fi
    done
else
    echo -e "${RED}/etc/cron.d directory not found.${NC}"
fi
echo "--------------------------------------------------"
echo

# --- 3. Cron Scripts (hourly, daily, weekly, monthly) ---
echo -e "${YELLOW}## 3. Scheduled Scripts (/etc/cron.*) ##${NC}"
for dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    if [ -d "$dir" ]; then
        echo -e "--> Listing scripts in ${GREEN}$dir${NC}:"
        # Using ls -l to show permissions and ownership
        ls -l "$dir" | tail -n +2 # tail removes the "total" line
        echo
    fi
done
echo "--------------------------------------------------"
echo

# --- 4. User-Specific Crontabs ---
echo -e "${YELLOW}## 4. User-Specific Cron Jobs (/var/spool/cron/) ##${NC}"
echo "(Requires root privileges for full visibility)"
SPOOL_DIR="/var/spool/cron/crontabs"
# Fallback for older systems like CentOS/RHEL
if [ ! -d "$SPOOL_DIR" ]; then
    SPOOL_DIR="/var/spool/cron"
fi

if [ -d "$SPOOL_DIR" ]; then
    for user_crontab in $(find "$SPOOL_DIR" -type f); do
        user=$(basename "$user_crontab")
        echo -e "--> Crontab for user: ${GREEN}$user${NC}"
        grep -Ev '^#|^$' "$user_crontab"
        echo
    done
else
    echo -e "${RED}Cron spool directory not found.${NC}"
fi
echo "--------------------------------------------------"
echo

# --- 5. systemd Timers (Modern Cron Alternative) ---
echo -e "${YELLOW}## 5. systemd Timers ##${NC}"
if command -v systemctl &> /dev/null; then
    # --all shows inactive/disabled timers as well, which is important
    systemctl list-timers --all
else
    echo -e "${RED}'systemctl' command not found. System may not use systemd.${NC}"
fi
echo "--------------------------------------------------"
echo

echo -e "${GREEN}==================================================${NC}"
echo -e "${GREEN}                 Enumeration Complete             ${NC}"
echo -e "${GREEN}==================================================${NC}"
