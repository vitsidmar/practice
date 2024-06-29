#!/bin/bash

# Database credentials
DB_USER="your_username"
DB_PASSWORD="your_password"
DB_NAME="your_database_name"

# Backup directory
BACKUP_DIR="/path/to/backup/directory"

# Timestamp (to create unique backup filenames)
TIMESTAMP=$(date +"%Y%m%d%H%M%S")

# Create backup directory if it doesn't exist
mkdir -p $BACKUP_DIR

# Backup the MySQL database
mysqldump -u$DB_USER -p$DB_PASSWORD $DB_NAME > $BACKUP_DIR/$DB_NAME-$TIMESTAMP.sql

# Compress the backup
gzip $BACKUP_DIR/$DB_NAME-$TIMESTAMP.sql

# Optionally, you can remove backups older than a certain period
# find $BACKUP_DIR -type f -name "*.gz" -mtime +7 -exec rm {} \;

echo "Backup completed: $BACKUP_DIR/$DB_NAME-$TIMESTAMP.sql.gz"
