sudo tee /usr/local/sbin/ccdc-backup.sh > /dev/null <<'EOF'
#!/usr/bin/env bash

if [[ $EUID -ne 0 ]]; then
    echo "[-] Run as root." >&2
    exit 1
fi

umask 077

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
HOSTNAME_TAG=$(hostname -s)
BACKUP_ROOT="/var/tmp/.ccdc_backups"
BACKUP_DIR="${BACKUP_ROOT}/${HOSTNAME_TAG}_backup_${TIMESTAMP}"
ARCHIVE_PATH="${BACKUP_ROOT}/${HOSTNAME_TAG}_backup_${TIMESTAMP}.tar.gz"

# Create secure backup directory
if [[ -L "${BACKUP_ROOT}" ]]; then
    echo "[-] Backup directory cannot be a symbolic link." >&2
    exit 1
fi

mkdir -p "${BACKUP_ROOT}"
chown root:rocky "${BACKUP_ROOT}"
chmod 750 "${BACKUP_ROOT}"

mkdir -p "${BACKUP_DIR}/configs" \
         "${BACKUP_DIR}/web" \
         "${BACKUP_DIR}/databases" \
         "${BACKUP_DIR}/system_state"

# 1. State & Users
cp /etc/passwd /etc/shadow /etc/group /etc/sudoers "${BACKUP_DIR}/system_state/" 2>/dev/null

[ -d /etc/sudoers.d ] && cp -r /etc/sudoers.d "${BACKUP_DIR}/system_state/" 2>/dev/null

ss -tulpn > "${BACKUP_DIR}/system_state/listening_ports.txt" 2>/dev/null
ps aux > "${BACKUP_DIR}/system_state/ps_snapshot.txt" 2>/dev/null

mkdir -p "${BACKUP_DIR}/system_state/cron"
cp -r /var/spool/cron "${BACKUP_DIR}/system_state/cron/" 2>/dev/null
cp -r /etc/cron* "${BACKUP_DIR}/system_state/cron/" 2>/dev/null

# 2. Configs & Web Roots
tar --exclude='/etc/selinux' -cpf "${BACKUP_DIR}/configs/etc_backup.tar" /etc 2>/dev/null

[ -d /var/www ] && tar -cpf "${BACKUP_DIR}/web/var_www.tar" /var/www 2>/dev/null
[ -d /srv ] && tar -cpf "${BACKUP_DIR}/web/srv.tar" /srv 2>/dev/null
[ -d /opt ] && tar -cpf "${BACKUP_DIR}/web/opt.tar" /opt 2>/dev/null

# 3. Database Dumps
if command -v mysqldump &>/dev/null; then
    mysqldump --all-databases --single-transaction --quick > "${BACKUP_DIR}/databases/mysql_all_dbs.sql" 2>/dev/null
fi

if command -v pg_dumpall &>/dev/null; then
    sudo -u postgres pg_dumpall > "${BACKUP_DIR}/databases/postgres_all_dbs.sql" 2>/dev/null
fi

# 4. Package Backup
if ! tar -czpf "${ARCHIVE_PATH}" -C "${BACKUP_ROOT}" "${HOSTNAME_TAG}_backup_${TIMESTAMP}"; then
    echo "[-] Failed to create backup archive." >&2
    exit 1
fi

rm -rf "${BACKUP_DIR}"

# 5. Set Secure Permissions for SCP
# Root retains ownership, rocky group gets read-only access
chown root:rocky "${ARCHIVE_PATH}"
chmod 640 "${ARCHIVE_PATH}"

# 6. Generate SHA256 Checksum
sha256sum "${ARCHIVE_PATH}" > "${ARCHIVE_PATH}.sha256"
chown root:rocky "${ARCHIVE_PATH}.sha256"
chmod 640 "${ARCHIVE_PATH}.sha256"

# 7. Make Backups Immutable
chattr +i "${ARCHIVE_PATH}"
chattr +i "${ARCHIVE_PATH}.sha256"

echo "[+] Backup completed: ${ARCHIVE_PATH}"
echo "[+] Permissions: root:rocky (640)"
echo "[+] Immutable protection enabled"
echo "[+] Ready for SCP download"
EOF

sudo chmod 700 /usr/local/sbin/ccdc-backup.sh
sudo /usr/local/sbin/ccdc-backup.sh
