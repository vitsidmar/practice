#!/bin/bash
# Create root mysql user 
#CREATE USER 'rootuser'@'%' IDENTIFIED BY 'password';
#GRANT ALL PRIVILEGES ON *.* TO 'rootuser'@'%' WITH GRANT OPTION;

REMOTE_HOST='172.16.240.12'
root_login='rootuser'
root_pass='password'
cluster_login='replicator'
cluster_pass='replicator_password'
config_file="/etc/mysql/mysql.conf.d/mysqld.cnf"
database="komments"

sudo sed -i 's/^bind-address.*/bind-address = 0.0.0.0/' "$config_file"
sudo sed -i 's/^\(max_binlog_size.*\)$/#\1/' "$config_file"

cat <<EOL | sudo tee -a "$config_file"
server-id = 1 #serv02 server-id = 2
log_bin = /var/log/mysql/mysql-bin.log
binlog_expire_logs_seconds = 2592000
max_binlog_size = 100M
auto_increment_increment= 2
auto_increment_offset = 1 #serv02 auto_increment_offset = 2
binlog_do_db = $database
binlog-ignore-db = mysql
binlog-ignore-db = Syslog
binlog-ignore-db = performance_schema
binlog-ignore-db = information_schema
EOL

sudo systemctl restart mysql

# Create replication user
mysql --user=$root_login --password=$root_pass -e "CREATE USER '$cluster_login'@'%' IDENTIFIED WITH mysql_native_password BY '$cluster_pass';"
mysql --user=$root_login --password=$root_pass -e "GRANT REPLICATION SLAVE ON *.* TO '$cluster_login'@'%';"
mysql --user=$root_login --password=$root_pass -e "FLUSH PRIVILEGES;"
mysql --user=$root_login --password=$root_pass -e "FLUSH TABLES WITH READ LOCK;"

REMOTE_FILE=`mysql --host=$REMOTE_HOST --user=$LOGIN --password=$PASS -e "show master status \G" | grep "File" | awk '{print $2}'`
REMOTE_POS=`mysql --host=$REMOTE_HOST --user=$LOGIN --password=$PASS -e "show master status \G" | grep "Position" | awk '{print $2}'`

echo REMOTE_FILE=$REMOTE_FILE
echo REMOTE_POS=$REMOTE_POS
mysql --user=$LOGIN --password=$PASS -e "stop slave"
mysql --user=$LOGIN --password=$PASS -e "CHANGE MASTER TO MASTER_HOST='$REMOTE_HOST', MASTER_USER='$cluster_login', MASTER_PASSWORD='$cluster_pass', MASTER_LOG_FILE='$REMOTE_FILE', MASTER_LOG_POS=$REMOTE_POS;"
mysql --user=$LOGIN --password=$PASS -e "start slave"
