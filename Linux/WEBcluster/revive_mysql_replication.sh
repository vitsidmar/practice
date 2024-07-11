#!/bin/bash
LOCAL_FILE=`mysql --user=root --password=root -e "show slave status \G" | grep "Master_Log_File" | awk ' {print $2}'`
REMOTE_FILE=`mysql --host=<IP адрес встречного сервера> --user=root --password=root -e "show master status \G" | grep "File" | awk '{print $2}'`
 
if [ $LOCAL_FILE != $REMOTE_FILE ]
 then
 mysql --user=root --password=root -e "stop slave"
 mysql --user=root --password=root -e "start slave"
fi
