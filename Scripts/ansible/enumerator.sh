#!/bin/sh

# Function to show the menu with an ASCII banner
show_menu() {
    echo "========================================="
    echo "    Coastline Xploit Club"
    echo "    Advanced Shell Framework"
    echo "========================================="
    echo "Choose an option:"
    echo "1) Display IPs of all interfaces, hostname, and OS version"
    echo "2) List all user accounts, sudo users, and groups with elevated privileges"
    echo "3) Show open ports and associated processes"
    echo "4) Display crontabs"
    echo "5) List firewall rules (iptables, ufw, or firewalld)"
    echo "6) Change passwords for users in privileged groups and save them"
    echo "7) List all installed software"
    echo "8) Exit"
}

# Function to execute the corresponding command based on the user's choice
execute_option() {
    case "$1" in
        1)
            echo "IP Addresses of All Network Interfaces:"

            # Display IPs for each network interface
            ip -o -f inet addr show | awk '{print $2, $4}'

            echo "Hostname:"
            hostname

            echo "Operating System Version:"
            # Check if lsb_release is available
            if command -v lsb_release > /dev/null 2>&1; then
                lsb_release -a
            else
                # Fall back to /etc/os-release if lsb_release is not available
                cat /etc/os-release
            fi
            ;;
        2)
            echo "Listing All User Accounts:"

            # List all user accounts (using cat /etc/passwd if getent is not available)
            if command -v getent > /dev/null 2>&1; then
                getent passwd | cut -d: -f1  # Get list of all usernames
            else
                cat /etc/passwd | cut -d: -f1  # Fallback to /etc/passwd if getent is not available
            fi
            echo ""

            # Listing users and groups with sudo privileges
            echo "Listing Users with Sudo Privileges:"

            # Get users with sudo privileges from /etc/sudoers
            sudo_users=$(grep -E '^\s*([a-zA-Z0-9_-]+)\s+ALL' /etc/sudoers | awk '{print $1}')

            if [ -n "$sudo_users" ]; then
                # Only list users, excluding group names (exclude %)
                sudo_user_list=$(echo "$sudo_users" | grep -v '^%')
                if [ -n "$sudo_user_list" ]; then
                    echo "Users with sudo privileges:"
                    echo "$sudo_user_list"
                else
                    echo "No users with sudo privileges found."
                fi
            else
                echo "No users with sudo privileges found in /etc/sudoers."
            fi

            echo ""

            echo "Listing Groups with Sudo Privileges:"

            # Get groups with sudo privileges from /etc/sudoers (groups prefixed with %)
            sudo_groups=$(grep -E '^\s*%([a-zA-Z0-9_-]+)\s+ALL' /etc/sudoers | awk '{print $1}' | sed 's/%//')

            if [ -n "$sudo_groups" ]; then
                echo "Groups with sudo privileges:"
                echo "$sudo_groups"
            else
                echo "No groups with sudo privileges found in /etc/sudoers."
            fi
            echo ""

            echo "Listing All Users in Privileged Groups:"

            # For each group that has sudo privileges, list users in that group
            if [ -n "$sudo_groups" ]; then
                for group in $sudo_groups; do
                    users_in_group=$(getent group "$group" | cut -d: -f4)
                    if [ -n "$users_in_group" ]; then
                        echo "Users in group '$group': $users_in_group"
                    else
                        echo "No users found in group '$group'."
                    fi
                done
            else
                echo "No privileged groups found."
            fi
            ;;
        3)
            echo "Open Ports and Associated Processes:"

            # Check if ss is installed
            if command -v ss > /dev/null 2>&1; then
                # Using ss to show open ports with process name and PID
                ss -tulnp | awk 'NR > 1 {print "Protocol: " $1 "\tLocal Address: " $4 "\tPID/Program: " $6}'
            elif command -v netstat > /dev/null 2>&1; then
                # Fallback to netstat if ss is not installed
                netstat -tulnp | awk 'NR > 2 {print "Protocol: " $1 "\tLocal Address: " $4 "\tPID/Program: " $7}'
            else
                echo "Neither 'ss' nor 'netstat' is installed. Cannot display open ports."
            fi
            ;;
        4)
            echo "Listing All Crontabs:"

            # List all cron jobs from various locations with full paths

            # User-specific crontabs from /var/spool/cron/
            if [ -d /var/spool/cron ]; then
                for user_crontab in /var/spool/cron/*; do
                    echo "Cron jobs for user $(basename "$user_crontab") - Full Path: $user_crontab"
                    cat "$user_crontab"
                    echo ""
                done
            else
                echo "No user crontabs found in /var/spool/cron/"
            fi

            # System-wide cron jobs from /etc/cron.d/
            if [ -d /etc/cron.d ]; then
                for system_cron in /etc/cron.d/*; do
                    echo "System cron job from /etc/cron.d/ - Full Path: $system_cron"
                    cat "$system_cron"
                    echo ""
                done
            else
                echo "No cron jobs found in /etc/cron.d/"
            fi

            # System-wide cron jobs from /etc/crontab
            if [ -f /etc/crontab ]; then
                echo "System cron jobs from /etc/crontab - Full Path: /etc/crontab"
                cat /etc/crontab
                echo ""
            else
                echo "No cron jobs found in /etc/crontab"
            fi
            ;;
        5)
            echo "Listing Firewall Rules:"

            # Check for iptables
            if command -v iptables > /dev/null 2>&1; then
                echo "iptables rules:"
                iptables -L -v
                echo ""
            else
                echo "iptables is not installed or not in use."
            fi

            # Check for ufw
            if command -v ufw > /dev/null 2>&1; then
                echo "ufw rules:"
                ufw status verbose
                echo ""
            else
                echo "ufw is not installed or not in use."
            fi

            # Check for firewalld
            if command -v firewall-cmd > /dev/null 2>&1; then
                echo "firewalld rules:"
                firewall-cmd --list-all
                echo ""
            else
                echo "firewalld is not installed or not in use."
            fi
            ;;
        6)
            echo "Changing passwords for users in privileged groups and saving them to $(hostname)_pcr.txt"

            # Initialize the output file
            output_file="$(hostname)_pcr.txt"
            > "$output_file"

            # Generate a random password for each user in each privileged group
            if [ -n "$sudo_groups" ]; then
                for group in $sudo_groups; do
                    users_in_group=$(getent group "$group" | cut -d: -f4)
                    if [ -n "$users_in_group" ]; then
                        for user in $users_in_group; do
                            # Generate a random 16-character alphanumeric password
                            password=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)

                            # Change the user's password
                            echo "$user:$password" | chpasswd

                            # Save the username and password to the output file
                            echo "$user,$password" >> "$output_file"
                        done
                    fi
                done
                echo "Passwords changed and saved to $output_file"
            else
                echo "No privileged groups found."
            fi
            ;;
        7)
            echo "Listing All Installed Software:"

            # List installed software from different package managers

            # For systems with apt (Debian/Ubuntu-based)
            if command -v apt > /dev/null 2>&1; then
                echo "Installed software via apt:"
                apt list --installed
                echo ""
            fi

            # For systems with zypper (openSUSE-based)
            if command -v zypper > /dev/null 2>&1; then
                echo "Installed software via zypper:"
                zypper search --installed-only
                echo ""
            fi

            # For systems with dnf (Fedora-based)
            if command -v dnf > /dev/null 2>&1; then
                echo "Installed software via dnf:"
                dnf list installed
                echo ""
            fi

            # For systems with pacman (Arch Linux-based)
            if command -v pacman > /dev/null 2>&1; then
                echo "Installed software via pacman:"
                pacman -Q
                echo ""
            fi

            # For systems with apk (Alpine Linux-based)
            if command -v apk > /dev/null 2>&1; then
                echo "Installed software via apk:"
                apk info
                echo ""
            fi
            ;;
        8)
            echo "Exiting the script."
            exit 0
            ;;
        *)
            echo "Invalid option. Please try again."
            ;;
    esac
}

# Main loop to show the menu and prompt for user input
while true; do
    show_menu
    echo "Please choose an option (1-8): "
    read option
    execute_option "$option"
    echo ""
done
