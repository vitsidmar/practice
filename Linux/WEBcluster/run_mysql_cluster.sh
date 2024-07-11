#!/bin/bash

REMOTE_HOST='172.16.240.12'
root_login='rootuser'
root_pass='password'
cluster_login='replicator'
cluster_pass='replicator_password'

# Create root mysql user 
CREATE USER '$root_login'@'%' IDENTIFIED BY '$root_pass';
GRANT ALL PRIVILEGES ON *.* TO '$root_login'@'%' WITH GRANT OPTION;
# Create replication user
CREATE USER '$cluster_login'@'%' IDENTIFIED WITH mysql_native_password BY '$cluster_pass';
GRANT REPLICATION SLAVE ON *.* TO '$cluster_login'@'%';
FLUSH PRIVILEGES;
FLUSH TABLES WITH READ LOCK;

REMOTE_FILE=`mysql --host=$REMOTE_HOST --user=$LOGIN --password=$PASS -e "show master status \G" | grep "File" | awk '{print $2}'`
REMOTE_POS=`mysql --host=$REMOTE_HOST --user=$LOGIN --password=$PASS -e "show master status \G" | grep "Position" | awk '{print $2}'`

echo REMOTE_FILE=$REMOTE_FILE
echo REMOTE_POS=$REMOTE_POS
mysql --user=$LOGIN --password=$PASS -e "stop slave"
mysql --user=$LOGIN --password=$PASS -e "CHANGE MASTER TO MASTER_HOST='$REMOTE_HOST', MASTER_USER='$cluster_login', MASTER_PASSWORD='$cluster_pass', MASTER_LOG_FILE='$REMOTE_FILE', MASTER_LOG_POS=$REMOTE_POS;"
mysql --user=$LOGIN --password=$PASS -e "start slave"
