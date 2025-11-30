#!/bin/sh

#####
# Automated password changer
#####
# This script generates random passwords and assigns them to each
# user, and exports the list of users and passwords to a CSV file
# with the hostname of the computer.
# This script can also accept existing CSV files to read from,
# changing the passwords to the values in the file.

# Generated password length
LENPASS=15

# Generated CSV file name
OUTFILE="$(hostname)_passwordlist.csv"

# Help screen
printHelp() {
    echo "chpass.sh - Automated password changer for Linux"
    echo
    echo "Usage: chpass [-h|-s|-d|-f FILENAME]"
    echo "  -h  Displays this help message"
    echo "  -s  Use shadow file instead of passwd. Only changes users with an existing password hash."
    echo "  -d  Dry run (don't actually change passwords)"
    echo "  -f FILENAME  Read and change passwords from a given CSV"
    exit 0
}

DRYRUN="false"
USEFILE="false"
USERS=$(grep 'sh$' /etc/passwd | grep -v 'root' | awk -F: '{print $1}')  # Get all users (not "root") with shells from /etc/passwd (default behavior)

OPTIND=1 # Reset option index for getopts when running this script multiple times
while getopts "hsdf:" option; do
    case $option in
        h) # display Help
            printHelp
            ;;
        d) # Dry run
            DRYRUN="true"
            ;;
        s) # Use shadow
            USERS=$(grep '^[^:]*:[^\*!]' /etc/shadow | grep -v 'root' | awk -F: '{print $1}')  # Get all users (not "root") with passwords from /etc/shadow
            ;;
        f) # Use file
            USEFILE="true"
            FILE=$OPTARG
            ;;
        \?) # Invalid option
            echo "Error: Invalid option"
            printHelp
            exit 2
            ;;
    esac
done

# Ensure script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "❌ Must be run as root or sudo!"
    exit 1
fi

# Generate passwords
if [ "$USEFILE" = "false" ]; then
    # Clear contents of password list file if already exists
    if [ -f "$OUTFILE" ]; then
        echo "⚠️ Found existing output file, clearing its contents..."
        sleep 3  # Gives the user time to cancel if unintended
    fi
    echo "username,password" > "$OUTFILE"
    for USER in $USERS
    do
        PASSWORD=$(tr -dc 'A-Za-z0-9!?%=' < /dev/urandom | head -c "$LENPASS")  # Generate random password with special chars
        if [ "$DRYRUN" = "false" ]; then
            echo "$USER:$PASSWORD" | chpasswd  # Change the password!
        fi
        echo "Changed password for $USER."
        echo "$USER,$PASSWORD" >> "$OUTFILE"
    done
# Read and change passwords from file
elif [ "$USEFILE" = "true" ]; then
    # Skip header line in CSV and change passwords
    tail -n +2 "$FILE" | while IFS="," read -r USER PASSWORD
    do
        if [ "$DRYRUN" = "false" ]; then
            echo "$USER:$PASSWORD" | chpasswd  # Change password based on CSV input
        fi
        echo "Changed password from file for $USER."
    done
fi

echo "✅ Done!"
exit 0
