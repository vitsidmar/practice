#!/bin/bash

### INSTALL Elasticsearch
install_Elasticsearch() {
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
apt install apt-transport-https net-tools -y
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | tee -a /etc/apt/sources.list.d/elastic-8.x.list
apt update && apt install elasticsearch -y
systemctl daemon-reload
systemctl enable elasticsearch.service
systemctl start elasticsearch.service
curl -X GET "localhost:9200"

### CONFIGURE Elasticsearch
elastic_conf="/etc/elasticsearch/elasticsearch.yml"
sudo sed -i "s|#network.host: 192.168.0.1|network.host: 127.0.0.1|" $elastic_conf
sudo sed -i "s|http.host: 0.0.0.0|http.host: 127.0.0.1|" $elastic_conf
sudo sed -i '/#discovery.seed_hosts: \["host1", "host2"\]/a discovery.seed_hosts: ["127.0.0.1", "[::1]"]' $elastic_conf
systemctl restart elasticsearch.service
# netstat -tulnp | grep 9200
}

### INSTALL Kibana
install_Kibana() {
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | tee -a /etc/apt/sources.list.d/elastic-8.x.list
apt update && apt install kibana -y
systemctl daemon-reload
systemctl enable kibana.service
systemctl start kibana.service
systemctl status kibana.service
# netstat -tulnp | grep 5601

### CONFIGURE kibana
cp -R /etc/elasticsearch/certs /etc/kibana
chown -R root:kibana /etc/kibana/certs
newpass=$(yes | /usr/share/elasticsearch/bin/elasticsearch-reset-password -u kibana_system)
kibana_password=$(echo "$newpass" | grep "New value:" | awk '{print $3}')
echo "New password for kibana_system is: $kibana_password"
ip_address=$(hostname -I | awk '{print $1}')
kibana_conf="/etc/kibana/kibana.yml"
sudo sed -i "s|#server.port: 5601|#server.port: 5601|" $kibana_conf
sudo sed -i "s|#server.host: \"localhost\"|server.host: \"$ip_address\"|" $kibana_conf
sudo sed -i "s|#server.publicBaseUrl: \"\"|server.publicBaseUrl: \"http://$ip_address:5601/\"|" $kibana_conf
sudo sed -i "s|#elasticsearch.username: \"kibana_system\"|elasticsearch.username: \"kibana_system\"|" $kibana_conf
sudo sed -i "s|#elasticsearch.password: \"pass\"|elasticsearch.password: \"$kibana_password\"|" $kibana_conf
sudo sed -i 's|#elasticsearch.ssl.certificateAuthorities: \[ "/path/to/your/CA.pem" \]|elasticsearch.ssl.certificateAuthorities: \[ "/etc/kibana/certs/http_ca.crt" \]|' $kibana_conf
sudo sed -i 's|#elasticsearch.hosts: \["http://localhost:9200"\]|elasticsearch.hosts: \["https://localhost:9200"\]|' $kibana_conf
systemctl restart kibana.service
}

### INSTALL Logstash
install_Logstash() {
apt install logstash -y
systemctl enable logstash.service
cp -R /etc/elasticsearch/certs /etc/logstash
chown -R root:logstash /etc/logstash/certs
logstash_dir="/etc/logstash/conf.d"
cat >$logstash_dir/input.conf <<EOF
input {
  beats {
    port => 5044
  }
}
EOF

cat >$logstash_dir/output.conf <<EOF
output {
    if "winsrv" in [tags] {
        elasticsearch {
            hosts     => "https://localhost:9200"
            index    => "winsrv-%{+YYYY.MM.dd}"
        }
    }
    else {
        elasticsearch {
            hosts     => "https://localhost:9200"
            index    => "unknown_messages"
        }
    }
}
EOF

cat >$logstash_dir/filter.conf <<EOF
filter {
}
EOF
}
# https://grokdebug.herokuapp.com/

install_Elasticsearch
install_Kibana
install_Logstash


#https://serveradmin.ru/ustanovka-i-nastroyka-elasticsearch-logstash-kibana-elk-stack/
