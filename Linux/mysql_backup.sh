#!/bin/bash
# Datenbank Parameter
DB_HOST="localhost"
DB_USER="sqluser"
DB_PASSWORD="pass"
DB_NAME="komments"
# Samba Server Parameter
SAMBA_SERVER="//172.16.240.29/daten/sql/"
MOUNT_POINT="/mnt/sharedfolder"
SAMBA_USERNAME="vital"
SAMBA_PASSWORD="Password1"
# Local Parameter
BACKUP_DIR="/root/sql_backup"
CURRENT_DATE=$(date +"%Y-%m-%d_%H:%M:%S")
HOSTNAME=$(hostname -s)
BACKUP_FILE="$BACKUP_DIR/${CURRENT_DATE}_${DB_NAME}_${HOSTNAME}.sql"
mkdir -p $BACKUP_DIR

mysqldump -h $DB_HOST -u $DB_USER -p$DB_PASSWORD $DB_NAME > $BACKUP_FILE

if [ $? -eq 0 ]; then
    echo "Datenbank-Backup $DB_NAME erfolgreich erstellt: $BACKUP_FILE"
    gzip $BACKUP_FILE
    # Überprüfen, ob die Samba-Verbindung aktiv ist
    if mountpoint -q $MOUNT_POINT; then
        echo "Samba-Server bereits verbunden."
    else
        # Verbindung zum Samba-Server herstellen
        mkdir -p $MOUNT_POINT
        sudo mount -t cifs $SAMBA_SERVER $MOUNT_POINT -o username=$SAMBA_USERNAME,password=$SAMBA_PASSWORD
        if [ $? -eq 0 ]; then
            echo "Verbindung zum Samba-Server erfolgreich hergestellt."
        else
            echo "Fehler bei der Verbindung zum Samba-Server."
            exit 1
        fi
    fi

    # Kopieren des Backups auf den Samba-Server
    cp $BACKUP_FILE.gz $MOUNT_POINT
    if [ $? -eq 0 ]; then
        echo "Backup erfolgreich auf den Samba-Server kopiert: $BACKUP_FILE"
    else
        echo "Fehler beim Kopieren des Backups auf den Samba-Server."
    fi
else
    echo "Fehler beim Erstellen des Datenbank-Backups $DB_NAME"
fi

# Löschen von .gz-Dateien, die älter als 7 Tage sind
# find $BACKUP_DIR -type f -name "*.gz" -mtime +7 -exec rm {} \;

echo "Backup completed: $BACKUP_FILE"
