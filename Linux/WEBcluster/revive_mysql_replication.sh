#!/bin/bash
# crontab -l | { cat; echo "*/1 * * * * /etc/keepalived/revive_mysql_replication.sh"; } | crontab
# GRANT ALL PRIVILEGES ON *.* TO 'root'@'<ip_server2>' IDENTIFIED BY 'root';
#FLUSH PRIVILEGES;
# GRANT ALL PRIVILEGES ON *.* TO 'root'@'<ip_server1>' IDENTIFIED BY 'root';
# FLUSH PRIVILEGES;
LOCAL_FILE=`mysql --user=root --password=root -e "show slave status \G" | grep "Master_Log_File" | awk ' {print $2}'`
REMOTE_FILE=`mysql --host=<IP адрес встречного сервера> --user=root --password=root -e "show master status \G" | grep "File" | awk '{print $2}'`
 
if [ $LOCAL_FILE != $REMOTE_FILE ]
 then
 mysql --user=root --password=root -e "stop slave"
 mysql --user=root --password=root -e "start slave"
fi
