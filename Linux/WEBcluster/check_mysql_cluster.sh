#!/bin/bash

# Verbindungsparameter für MySQL-Server
SERVERS=("172.16.240.11" "172.16.240.12")
MYSQL_USER="rootuser"
MYSQL_PASSWORD="password"

# Funktion zur Überprüfung des MySQL-Serverstatus und Abruf von MASTER_LOG_FILE und MASTER_LOG_POS
check_server_status() {
    local server=$1
    local remote=$2
    # Überprüfung der Verbindung durch Ausführen eines einfachen SQL-Befehls
    result=$(mysql -h "$server" -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" -e "SHOW MASTER STATUS\G" 2>&1)
    if [ $? -eq 0 ]; then
        echo "MySQL-Server auf $server läuft."
        master_log_file=$(echo "$result" | grep 'File:' | awk '{print $2}')
        master_log_pos=$(echo "$result" | grep 'Position:' | awk '{print $2}')
        echo "MASTER_LOG_FILE: $master_log_file"
        echo "MASTER_LOG_POS: $master_log_pos"
    else
        echo "MySQL-Server auf $server läuft NICHT."
        echo "Fehlermeldung: $result"
        # Versuchen, den MySQL-Dienst neu zu starten
        if [ "$remote" = true ]; then
            echo "Versuchen, den MySQL-Dienst auf dem Remote-Server $server neu zu starten..."
            ssh root@$server 'systemctl restart mysql'
        else
            echo "Versuchen, den MySQL-Dienst auf dem lokalen Server neu zu starten..."
            systemctl restart mysql
        fi

        # Überprüfung des Status nach dem Neustart
        result=$(mysql -h "$server" -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" -e "SHOW MASTER STATUS\G" 2>&1)
        if [ $? -eq 0 ]; then
            echo "MySQL-Server auf $server wurde erfolgreich neu gestartet."
            master_log_file=$(echo "$result" | grep 'File:' | awk '{print $2}')
            master_log_pos=$(echo "$result" | grep 'Position:' | awk '{print $2}')
            echo "MASTER_LOG_FILE: $master_log_file"
            echo "MASTER_LOG_POS: $master_log_pos"
        else
            echo "Fehler beim Neustart des MySQL-Servers auf $server. Überprüfen Sie den Server manuell."
            return 1
        fi
    fi
}

# Überprüfung des Status jedes Servers im Cluster
for server in "${SERVERS[@]}"; do
    if [ "$server" = "172.16.240.11" ]; then
        check_server_status "$server" false
    else
        check_server_status "$server" true
    fi
    if [ $? -ne 0 ]; then
        echo "MySQL-Cluster hat Probleme. Überprüfen Sie den Server $server."
        exit 1
    fi
done

echo "Alle MySQL-Server im Cluster laufen einwandfrei."
