#!/bin/sh
# POSIX-compliant interactive script to block outbound C2

IPTABLES="/sbin/iptables"

add_rules() {
    echo "Adding rules to block common outbound C2 traffic..."
    $IPTABLES -A OUTPUT -s 192.168.220.0/24 -p tcp --dport 445 -j DROP
    $IPTABLES -A OUTPUT -s 192.168.220.0/24 -p tcp --dport 139 -j DROP
    $IPTABLES -A OUTPUT -s 192.168.220.0/24 -p tcp --dport 22 -j DROP
    # Allow DNS traffic to Cloudflare, Quad9, and Google DNS
    $IPTABLES -A OUTPUT -s 192.168.220.0/24 -p tcp -d 1.1.1.1 --dport 53 -j ACCEPT
    $IPTABLES -A OUTPUT -s 192.168.220.0/24 -p tcp -d 1.0.0.1 --dport 53 -j ACCEPT
    $IPTABLES -A OUTPUT -s 192.168.220.0/24 -p tcp -d 9.9.9.9 --dport 53 -j ACCEPT
    $IPTABLES -A OUTPUT -s 192.168.220.0/24 -p tcp -d 8.8.8.8 --dport 53 -j ACCEPT
    $IPTABLES -A OUTPUT -s 192.168.220.0/24 -p tcp -d 8.8.4.4 --dport 53 -j ACCEPT
    # Drop all other DNS traffic from source subnet on TCP port 53
    $IPTABLES -A OUTPUT -s 192.168.220.0/24 -p tcp --dport 53 -j DROP
    
    echo "Rules added."
}

remove_rules() {
    echo "Removing all rules added by script..."

    $IPTABLES -D OUTPUT -s 192.168.220.0/24 -p tcp --dport 445 -j DROP 2>/dev/null
    $IPTABLES -D OUTPUT -s 192.168.220.0/24 -p tcp --dport 139 -j DROP 2>/dev/null
    $IPTABLES -D OUTPUT -s 192.168.220.0/24 -p tcp --dport 22 -j DROP 2>/dev/null
    $IPTABLES -D OUTPUT -s 192.168.220.0/24 -p tcp -d 1.1.1.1 --dport 53 -j ACCEPT 2>/dev/null
    $IPTABLES -D OUTPUT -s 192.168.220.0/24 -p tcp -d 1.0.0.1 --dport 53 -j ACCEPT 2>/dev/null
    $IPTABLES -D OUTPUT -s 192.168.220.0/24 -p tcp -d 9.9.9.9 --dport 53 -j ACCEPT 2>/dev/null
    $IPTABLES -D OUTPUT -s 192.168.220.0/24 -p tcp -d 8.8.8.8 --dport 53 -j ACCEPT 2>/dev/null
    $IPTABLES -D OUTPUT -s 192.168.220.0/24 -p tcp -d 8.8.4.4 --dport 53 -j ACCEPT 2>/dev/null
    $IPTABLES -D OUTPUT -s 192.168.220.0/24 -p tcp --dport 53 -j DROP 2>/dev/null

    echo "Rules removed."
}

add_suspicious_rules() {
    echo "Blocking outbound SMB and SSH..."
    $IPTABLES -A OUTPUT -s 192.168.220.0/24 -p tcp --dport 445 -j DROP
    $IPTABLES -A OUTPUT -s 192.168.220.0/24 -p tcp --dport 139 -j DROP
    $IPTABLES -A OUTPUT -s 192.168.220.0/24 -p tcp --dport 22 -j DROP
}

remove_suspicious_rules() {
    echo "Removing SMB and SSH rules..."
    $IPTABLES -D OUTPUT -s 192.168.220.0/24 -p tcp --dport 445 -j DROP 2>/dev/null
    $IPTABLES -D OUTPUT -s 192.168.220.0/24 -p tcp --dport 139 -j DROP 2>/dev/null
    $IPTABLES -D OUTPUT -s 192.168.220.0/24 -p tcp --dport 22 -j DROP 2>/dev/null
}

main_menu() {
    while true; do
        echo
        echo "=== IPTables C2 Blocking Manager ==="
        echo "1) Add all blocking rules"
        echo "2) Remove all blocking rules"
        echo "3) Add rules except DNS"
        echo "4) Remove rules except DNS"
        echo "5) Exit"
        printf "Select an option [1-5]: "
        read choice

        case "$choice" in
            1)
                add_rules
                ;;
            2)
                remove_rules
                ;;
            3)
                add_suspicious_rules
                ;;
            4)
                remove_suspicious_rules
                ;;
            5)
                echo "Exiting."
                exit 0
                ;;
            *)
                echo "Invalid option. Please choose 1–4."
                ;;
        esac
    done
}

# Must be run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root."
    exit 1
fi

main_menu
