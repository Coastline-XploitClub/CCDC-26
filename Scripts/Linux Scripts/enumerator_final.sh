#!/bin/sh

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

# Function to show the menu with an ASCII banner
show_menu() {
    printf "%s" "$YELLOW"
    printf "=========================================\n"
    printf "    Coastline Xploit Club\n"
    printf "    Advanced Shell Framework\n"
    printf "=========================================\n"
    printf "Choose an option:\n"
    printf "1) Display IPs of all interfaces, hostname, and OS version\n"
    printf "2) List all user accounts, sudo users, and groups with elevated privileges\n"
    printf "3) Show open ports and associated processes\n"
    printf "4) Display crontabs\n"
    printf "5) List firewall rules (iptables, ufw, or firewalld)\n"
    printf "6) List all installed software\n"
    printf "7) Show running Docker containers\n"
    printf "8) Exit\n"
    printf "%s" "$NC"
}

# Function to execute the corresponding command based on the user's choice
execute_option() {
    # Establish sudo users and groups
    sudo_users=$(grep -E '^\s*([a-zA-Z0-9_-]+)\s+ALL' /etc/sudoers | awk '{print $1}' | sort -u)
    sudo_groups=$(grep -E '^\s*%([a-zA-Z0-9_-]+)\s+ALL' /etc/sudoers | awk '{print $1}' | sed 's/%//' | sort -u)

    case "$1" in
        1)
            printf "%sIP Addresses of All Network Interfaces:%s\n" "$GREEN" "$NC"

            # Display IPs for each network interface
            ip -o -f inet addr show | awk '{print $2, $4}'

            printf "%sHostname:%s\n" "$GREEN" "$NC"
            hostname

            printf "%sOperating System Version:%s\n" "$GREEN" "$NC"
            # Check if lsb_release is available
            if command -v lsb_release > /dev/null 2>&1; then
                lsb_release -a
            else
                # Fall back to /etc/os-release if lsb_release is not available
                cat /etc/os-release
            fi
            ;;
        2)
            printf "%sListing all user accounts:%s\n" "$GREEN" "$NC"

            # List all user accounts (using cat /etc/passwd if getent is not available)
            if command -v getent > /dev/null 2>&1; then
                getent passwd | grep -v /bin/false | grep -v /sbin/nologin | grep -v /sbin/shutdown | grep -v /bin/sync | grep -v /sbin/halt | cut -d: -f1  # Get list of all usernames
            else
                cat /etc/passwd | grep -v /bin/false | grep -v /sbin/nologin | grep -v /sbin/shutdown | grep -v /bin/sync | grep -v /sbin/halt | cut -d: -f1   # Fallback to /etc/passwd if getent is not available
            fi
            echo ""

            # Listing users and groups with sudo privileges
            printf "%sListing users with sudo privileges:%s\n" "$GREEN" "$NC"

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

            printf "%sListing groups with sudo privileges:%s\n" "$GREEN" "$NC"

            if [ -n "$sudo_groups" ]; then
                echo "Groups with sudo privileges:"
                echo "$sudo_groups"
            else
                echo "No groups with sudo privileges found in /etc/sudoers."
            fi
            echo ""

            printf "%sListing all users in privileged groups:%s\n" "$GREEN" "$NC"

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
            printf "%sOpen ports and processes:%s\n" "$GREEN" "$NC"

            # Check if ss is installed
            if command -v ss > /dev/null 2>&1; then
                # Using ss to show open ports with process name and PID
                ss -tulnp | awk 'NR > 1 {print "Protocol: " $1 "\tLocal Address: " $5 "\tPID/Program: " $7}' | grep -v "127.0.0"
            elif command -v netstat > /dev/null 2>&1; then
                # Fallback to netstat if ss is not installed
                netstat -tulnp | awk 'NR > 2 {print "Protocol: " $1 "\tLocal Address: " $4 "\tPID/Program: " $7}' | grep -v "127.0.0"
            else
                echo "Neither 'ss' nor 'netstat' is installed. Cannot display open ports."
            fi
            ;;
        4)
            printf "%sListing all crontabs:%s\n" "$GREEN" "$NC"

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
            printf "%sListing all firewall rules:%s\n" "$GREEN" "$NC"

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
            printf "%sListing all installed software:%s\n" "$GREEN" "$NC"

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
        7) 
            echo "Enumerating Docker containers..."
            if command -v docker > /dev/null 2>&1; then
                echo "Docker found!"
                docker ps
            else
                echo "Docker not installed."
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

# Automatically run all non-destructive enumeration and save each category
# to a separate file. Password changes are intentionally NOT included.
run_all_safe_options() {
    # Create a timestamped enumeration folder inside the CURRENT directory.
    # Date/time first so enumeration folders sort chronologically.
    # Example: ./20261023_004044_enumeration_WEB01
    current_dir=$(pwd)
    output_dir="$current_dir/$(date +%Y%m%d_%H%M%S)_enumeration_$(hostname)"

    if ! mkdir -p "$output_dir"; then
        echo "Failed to create output directory: $output_dir"
        echo "The current directory is not writable by this user."
        echo "Try running the script with sudo or move it to a writable directory."
        exit 1
    fi

    echo "Saving enumeration results to: $output_dir"

    # Network / host / operating system information combined into one file
    {
        echo "===== IP Addresses ====="
        if command -v ip > /dev/null 2>&1; then
            ip -o -f inet addr show 2>&1 | awk '{print $2, $4}'
        else
            echo "ip command not available."
        fi

        echo ""
        echo "===== Hostname ====="
        hostname 2>&1

        echo ""
        echo "===== Operating System ====="
        if command -v lsb_release > /dev/null 2>&1; then
            lsb_release -a 2>&1
        elif [ -f /etc/os-release ]; then
            cat /etc/os-release 2>&1
        else
            uname -a 2>&1
        fi
    } > "$output_dir/system_info.txt"

    # User accounts + privileged users/groups combined into one file
    {
        echo "===== User Accounts ====="
        if command -v getent > /dev/null 2>&1; then
            getent passwd | grep -v /bin/false | grep -v /sbin/nologin | \
                grep -v /sbin/shutdown | grep -v /bin/sync | grep -v /sbin/halt | \
                cut -d: -f1
        else
            grep -v /bin/false /etc/passwd | grep -v /sbin/nologin | \
                grep -v /sbin/shutdown | grep -v /bin/sync | grep -v /sbin/halt | \
                cut -d: -f1
        fi

        sudo_users=$(grep -E '^\s*([a-zA-Z0-9_-]+)\s+ALL' /etc/sudoers 2>/dev/null | awk '{print $1}' | sort -u)
        sudo_groups=$(grep -E '^\s*%([a-zA-Z0-9_-]+)\s+ALL' /etc/sudoers 2>/dev/null | awk '{print $1}' | sed 's/%//' | sort -u)

        echo ""
        echo "===== Users with Direct Sudo Privileges ====="
        if [ -n "$sudo_users" ]; then
            echo "$sudo_users" | grep -v '^%' || true
        else
            echo "None found in /etc/sudoers."
        fi

        echo ""
        echo "===== Groups with Sudo Privileges ====="
        if [ -n "$sudo_groups" ]; then
            echo "$sudo_groups"
        else
            echo "None found in /etc/sudoers."
        fi

        echo ""
        echo "===== Users in Privileged Groups ====="
        if [ -n "$sudo_groups" ] && command -v getent > /dev/null 2>&1; then
            for group in $sudo_groups; do
                members=$(getent group "$group" | cut -d: -f4)
                echo "$group: ${members:-No listed members}"
            done
        else
            echo "No privileged groups found or getent unavailable."
        fi
    } > "$output_dir/users_privileges.txt" 2>&1

    # Listening ports and associated processes/services
    if command -v ss > /dev/null 2>&1; then
        ss -tulnp > "$output_dir/ports_services.txt" 2>&1
    elif command -v netstat > /dev/null 2>&1; then
        netstat -tulnp > "$output_dir/ports_services.txt" 2>&1
    else
        echo "Neither ss nor netstat is installed." > "$output_dir/ports_services.txt"
    fi

    # Cron jobs
    {
        if [ -f /etc/crontab ]; then
            echo "===== /etc/crontab ====="
            cat /etc/crontab
            echo ""
        fi

        if [ -d /etc/cron.d ]; then
            for cronfile in /etc/cron.d/*; do
                [ -f "$cronfile" ] || continue
                echo "===== $cronfile ====="
                cat "$cronfile"
                echo ""
            done
        fi

        if [ -d /var/spool/cron ]; then
            for cronfile in /var/spool/cron/*; do
                [ -f "$cronfile" ] || continue
                echo "===== $cronfile ====="
                cat "$cronfile"
                echo ""
            done
        fi
    } > "$output_dir/crontabs.txt" 2>&1

    # Firewall rules
    {
        if command -v iptables > /dev/null 2>&1; then
            echo "===== iptables ====="
            iptables -L -n -v
            echo ""
        fi

        if command -v ufw > /dev/null 2>&1; then
            echo "===== ufw ====="
            ufw status verbose
            echo ""
        fi

        if command -v firewall-cmd > /dev/null 2>&1; then
            echo "===== firewalld ====="
            firewall-cmd --list-all
            echo ""
        fi
    } > "$output_dir/firewall_rules.txt" 2>&1

    # Installed software
    {
        if command -v dpkg-query > /dev/null 2>&1; then
            dpkg-query -W -f='${binary:Package}\t${Version}\n'
        elif command -v dnf > /dev/null 2>&1; then
            dnf list installed
        elif command -v rpm > /dev/null 2>&1; then
            rpm -qa
        elif command -v zypper > /dev/null 2>&1; then
            zypper search --installed-only
        elif command -v pacman > /dev/null 2>&1; then
            pacman -Q
        elif command -v apk > /dev/null 2>&1; then
            apk info -v
        else
            echo "Supported package manager not found."
        fi
    } > "$output_dir/installed_software.txt" 2>&1

    # Docker containers
    if command -v docker > /dev/null 2>&1; then
        docker ps -a > "$output_dir/docker_containers.txt" 2>&1
    else
        echo "Docker is not installed." > "$output_dir/docker_containers.txt"
    fi



    # Kubernetes / container orchestration
    {
        echo "===== Kubernetes / Orchestration Enumeration ====="
        echo ""

        if command -v kubectl > /dev/null 2>&1; then
            echo "kubectl: $(command -v kubectl)"
            kubectl version --client 2>&1
            echo ""
            echo "----- Current context -----"
            kubectl config current-context 2>&1 || true
            echo ""
            echo "----- Configured contexts -----"
            kubectl config get-contexts 2>&1 || true
            echo ""
            echo "----- Cluster info -----"
            kubectl cluster-info 2>&1 || true
            echo ""
            echo "----- Nodes -----"
            kubectl get nodes -o wide 2>&1 || true
            echo ""
            echo "----- Namespaces -----"
            kubectl get namespaces 2>&1 || true
            echo ""
            echo "----- Workloads / Services (all namespaces) -----"
            kubectl get pods,deployments,daemonsets,statefulsets,services -A -o wide 2>&1 || true
        else
            echo "kubectl not installed or not in PATH."
        fi

        echo ""
        echo "----- Kubernetes-related binaries -----"
        for cmd in kubelet kubeadm kubectl minikube k3s k3d kind helm crictl ctr nerdctl; do
            if command -v "$cmd" > /dev/null 2>&1; then
                echo "$cmd: $(command -v "$cmd")"
            fi
        done

        echo ""
        echo "----- Kubernetes-related processes -----"
        ps aux 2>/dev/null | grep -Ei '[k]ube(apiserver|let|proxy|controller|scheduler)|[e]tcd|[k]3s|[c]ontainerd|[c]ri-o' || true

        if command -v systemctl > /dev/null 2>&1; then
            echo ""
            echo "----- Kubernetes-related systemd services -----"
            systemctl list-units --type=service --all 2>/dev/null | grep -Ei 'kube|k3s|containerd|cri-o|etcd' || true
        fi
    } > "$output_dir/kubernetes.txt" 2>&1

    # Databases
    {
        echo "===== Database Enumeration ====="
        echo ""
        echo "----- Database client/server binaries found -----"
        for cmd in mysql mysqladmin mysqld mariadb mariadbd psql postgres pg_isready mongo mongosh mongod redis-cli redis-server sqlite3 sqlcmd couchdb influx; do
            if command -v "$cmd" > /dev/null 2>&1; then
                echo "$cmd: $(command -v "$cmd")"
            fi
        done

        echo ""
        echo "----- Database processes -----"
        ps aux 2>/dev/null | grep -Ei '[m]ysqld|[m]ariadbd|[p]ostgres|[m]ongod|[r]edis-server|[c]ouchdb|[i]nfluxd|[m]ssql' || true

        if command -v systemctl > /dev/null 2>&1; then
            echo ""
            echo "----- Database-related systemd services -----"
            systemctl list-units --type=service --all 2>/dev/null | grep -Ei 'mysql|mariadb|postgres|mongo|redis|couch|influx|mssql' || true
        fi

        echo ""
        echo "----- Common database listening ports -----"
        if command -v ss > /dev/null 2>&1; then
            ss -lntp 2>/dev/null | grep -E ':(3306|5432|27017|6379|1433|1521|9042|9200|5984|8086)([[:space:]]|$)' || true
        elif command -v netstat > /dev/null 2>&1; then
            netstat -lntp 2>/dev/null | grep -E ':(3306|5432|27017|6379|1433|1521|9042|9200|5984|8086)([[:space:]]|$)' || true
        fi
    } > "$output_dir/databases.txt" 2>&1

    # Running services / daemons
    {
        echo "===== Running Services ====="
        if command -v systemctl > /dev/null 2>&1; then
            systemctl list-units --type=service --state=running --no-pager 2>&1
        elif command -v service > /dev/null 2>&1; then
            service --status-all 2>&1
        else
            echo "systemctl/service command not available."
        fi
    } > "$output_dir/running_services.txt" 2>&1

    # Web/application servers and common infrastructure software
    {
        echo "===== Web / Application / Infrastructure Software ====="
        echo ""
        echo "----- Common binaries found -----"
        for cmd in nginx apache2 httpd caddy lighttpd haproxy traefik tomcat java node npm python3 php ruby perl git ansible terraform packer vault consul nomad jenkins podman docker containerd crictl snap flatpak; do
            if command -v "$cmd" > /dev/null 2>&1; then
                echo "$cmd: $(command -v "$cmd")"
            fi
        done

        echo ""
        echo "----- Related running processes -----"
        ps aux 2>/dev/null | grep -Ei '[n]ginx|[a]pache2|[h]ttpd|[c]addy|[h]aproxy|[t]raefik|[t]omcat|[j]ava|[n]ode|[p]hp-fpm|[j]enkins|[v]ault|[c]onsul|[n]omad|[p]odman|[d]ocker|[c]ontainerd' || true
    } > "$output_dir/software_services.txt" 2>&1

    # Container runtimes beyond Docker
    {
        echo "===== Container Runtime Enumeration ====="
        for cmd in docker podman containerd ctr nerdctl crictl; do
            if command -v "$cmd" > /dev/null 2>&1; then
                echo "$cmd: $(command -v "$cmd")"
            fi
        done

        if command -v podman > /dev/null 2>&1; then
            echo ""
            echo "----- Podman containers -----"
            podman ps -a 2>&1 || true
        fi

        if command -v crictl > /dev/null 2>&1; then
            echo ""
            echo "----- CRI containers -----"
            crictl ps -a 2>&1 || true
        fi

        if command -v ctr > /dev/null 2>&1; then
            echo ""
            echo "----- containerd namespaces -----"
            ctr namespaces list 2>&1 || true
        fi
    } > "$output_dir/container_runtimes.txt" 2>&1

    # Summary
    {
        echo "Enumeration completed: $(date)"
        echo "Hostname: $(hostname)"
        echo "Output directory: $output_dir"
        echo "Password changes: NOT PERFORMED"
    } > "$output_dir/summary.txt"

    # Create one master report containing every text report in this directory.
    # Combined.txt itself is excluded so it does not recursively include itself.
    combined_file="$output_dir/Combined.txt"
    : > "$combined_file"
    for report in "$output_dir"/*.txt; do
        [ -f "$report" ] || continue
        [ "$report" = "$combined_file" ] && continue

        printf '============================================================\n' >> "$combined_file"
        printf 'FILE: %s\n' "$(basename "$report")" >> "$combined_file"
        printf '============================================================\n\n' >> "$combined_file"
        cat "$report" >> "$combined_file"
        printf '\n\n' >> "$combined_file"
    done

    echo "Enumeration complete."
    echo "Results saved in: $output_dir"
}

# Run automatically by default.
# Use --menu if you want the original interactive menu instead.
if [ "$1" = "--menu" ]; then
    while true; do
        show_menu
        printf "%sPlease choose an option (1-8): %s\n" "$RED" "$NC"
        read option
        execute_option "$option"
        echo ""
    done
else
    run_all_safe_options
fi
