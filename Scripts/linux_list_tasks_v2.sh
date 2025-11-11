#!/bin/sh

# ==============================================================================
# Script Name: list_tasks.sh (POSIX-Compliant)
# Description: Enumerates scheduled tasks on a Linux system, including
#              cron jobs and systemd timers.
# Author:      dsub
# Note:        This script should be run as root for complete visibility.
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

# Use printf for all output, as 'echo -e' is not POSIX
printf "%s==================================================%s\n" "$GREEN" "$NC"
printf "%s      Scheduled Tasks & Cron Jobs Enumeration       %s\n" "$GREEN" "$NC"
printf "%s==================================================%s\n" "$GREEN" "$NC"
printf "\n"

# --- 1. System-Wide Crontab ---
printf "%s## 1. System-Wide Crontab (/etc/crontab) ##%s\n" "$YELLOW" "$NC"
if [ -f /etc/crontab ]; then
    # grep -Ev is POSIX-compliant (ERE)
    grep -Ev '^#|^$' /etc/crontab
else
    printf "%s/etc/crontab not found.%s\n" "$RED" "$NC"
fi
printf "--------------------------------------------------\n"
printf "\n"

# --- 2. Cron Jobs in /etc/cron.d/ ---
printf "%s## 2. Additional System Cron Jobs (/etc/cron.d/) ##%s\n" "$YELLOW" "$NC"
if [ -d /etc/cron.d ]; then
    # Use find to properly handle all filenames
    find /etc/cron.d/ -type f -exec sh -c '
        for cronfile do
            if [ -f "$cronfile" ]; then
                printf "--> Contents of %s%s%s:\n" "$GREEN" "$cronfile" "$NC"
                grep -Ev "^#|^$" "$cronfile"
                printf "\n"
            fi
        done
    ' sh {} +
else
    printf "%s/etc/cron.d directory not found.%s\n" "$RED" "$NC"
fi
printf "--------------------------------------------------\n"
printf "\n"

# --- 3. Cron Scripts (hourly, daily, weekly, monthly) ---
printf "%s## 3. Scheduled Scripts (/etc/cron.*) ##%s\n" "$YELLOW" "$NC"
for dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    if [ -d "$dir" ]; then
        printf "--> Listing scripts in %s%s%s:\n" "$GREEN" "$dir" "$NC"
        # ls -l and tail -n +2 are POSIX-compliant
        ls -l "$dir" | tail -n +2 # tail removes the "total" line
        printf "\n"
    fi
done
printf "--------------------------------------------------\n"
printf "\n"

# --- 4. User-Specific Crontabs ---
printf "%s## 4. User-Specific Cron Jobs (/var/spool/cron/) ##%s\n" "$YELLOW" "$NC"
printf "(Requires root privileges for full visibility)\n"

# Check standard locations (e.g., Ubuntu/Debian)
SPOOL_DIR="/var/spool/cron/crontabs"

# Fallback for older systems or Alpine/RHEL
if [ ! -d "$SPOOL_DIR" ]; then
    SPOOL_DIR="/var/spool/cron"
fi

if [ -d "$SPOOL_DIR" ]; then
    # Use find -exec for robust handling of all filenames (incl. spaces)
    find "$SPOOL_DIR" -type f -exec sh -c '
        user=$(basename "$1")
        printf "--> Crontab for user: %s%s%s\n" "$GREEN" "$user" "$NC"
        grep -Ev "^#|^$" "$1"
        printf "\n"
    ' sh {} \;
else
    printf "%sCron spool directory not found.%s\n" "$RED" "$NC"
fi
printf "--------------------------------------------------\n"
printf "\n"

# --- 5. systemd Timers (Modern Cron Alternative) ---
printf "%s## 5. systemd Timers ##%s\n" "$YELLOW" "$NC"
# 'command -v' is POSIX. ' > /dev/null 2>&1' is the POSIX way to redirect
if command -v systemctl > /dev/null 2>&1; then
    # --all shows inactive/disabled timers as well, which is important
    systemctl list-timers --all
else
    printf "%s'systemctl' command not found. System may not use systemd (e.g., Alpine).%s\n" "$RED" "$NC"
fi
printf "--------------------------------------------------\n"
printf "\n"

printf "%s==================================================%s\n" "$GREEN" "$NC"
printf "%s                 Enumeration Complete             %s\n" "$GREEN" "$NC"
printf "%s==================================================%s\n" "$GREEN" "$NC"
