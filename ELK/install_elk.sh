#!/bin/bash
sed -i "/#\$nrconf{restart} = 'i';/s/.*/\$nrconf{restart} = 'a';/" /etc/needrestart/needrestart.conf
apt-get update && apt-get upgrade -y

### INSTALL Elasticsearch
install_Elasticsearch() {
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
apt install apt-transport-https -y
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | tee -a /etc/apt/sources.list.d/elastic-8.x.list
apt update && apt install elasticsearch -y
systemctl daemon-reload
systemctl enable elasticsearch.service
systemctl start elasticsearch.service

### CONFIGURE Elasticsearch
elastic_conf="/etc/elasticsearch/elasticsearch.yml"
sed -i "s|#node.name: node-1|node.name: elk-node|" $elastic_conf
sudo sed -i "s|#network.host: 192.168.0.1|network.host: 127.0.0.1|" $elastic_conf
sudo sed -i "s|http.host: 0.0.0.0|http.host: 127.0.0.1|" $elastic_conf
cat > /etc/elasticsearch/jvm.options.d/jvm.option <<EOF
-Xmx4g
EOF
systemctl restart elasticsearch.service
elastic_new_pass=$(yes | /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic)
elastic_password=$(echo "$elastic_new_pass" | grep "New value:" | awk '{print $3}')
curl -k --user elastic:'$elastic_password' https://127.0.0.1:9200
}

### INSTALL Kibana
install_Kibana() {
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | tee -a /etc/apt/sources.list.d/elastic-8.x.list
apt-get update && apt-get install kibana -y
systemctl daemon-reload
systemctl enable kibana.service
systemctl start kibana.service

### CONFIGURE kibana
cp -R /etc/elasticsearch/certs /etc/kibana
chown -R root:kibana /etc/kibana/certs
kibana_new_pass=$(yes | /usr/share/elasticsearch/bin/elasticsearch-reset-password -u kibana_system)
kibana_password=$(echo "$kibana_new_pass" | grep "New value:" | awk '{print $3}')
ip_address=$(hostname -I | awk '{print $1}')
url="http://$ip_address:5601"
kibana_conf="/etc/kibana/kibana.yml"
sudo sed -i "s|#server.port: 5601|#server.port: 5601|" $kibana_conf
sudo sed -i "s|#server.host: \"localhost\"|server.host: \"$ip_address\"|" $kibana_conf
sudo sed -i "s|#server.publicBaseUrl: \"\"|server.publicBaseUrl: \"$url\"|" $kibana_conf
sudo sed -i "s|#elasticsearch.username: \"kibana_system\"|elasticsearch.username: \"kibana_system\"|" $kibana_conf
sudo sed -i "s|#elasticsearch.password: \"pass\"|elasticsearch.password: \"$kibana_password\"|" $kibana_conf
sudo sed -i 's|#elasticsearch.ssl.certificateAuthorities: \[ "/path/to/your/CA.pem" \]|elasticsearch.ssl.certificateAuthorities: \[ "/etc/kibana/certs/http_ca.crt" \]|' $kibana_conf
sudo sed -i 's|#elasticsearch.hosts: \["http://localhost:9200"\]|elasticsearch.hosts: \["https://localhost:9200"\]|' $kibana_conf
echo "Login: kibana_system"
echo "Password: $kibana_password"
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
        elasticsearch {
            hosts => "https://localhost:9200"
            index => "winlogbeat-%{+YYYY.MM}"
	    user => "elastic"
	    password => "$elastic_password"
	    cacert => "/etc/logstash/certs/http_ca.crt"
        }
}
EOF
}

### INSTALL NGINX
install_NGINX() {
apt-get install -y nginx
cat > /etc/nginx/sites-available/elasticsearch <<EOF 
upstream elasticsearch {
    server 127.0.0.1:9200;
    keepalive 64;
}

server {
    listen 9201;
    server_name search.proxy;
    client_max_body_size 50m;

    location / {
        proxy_pass https://elasticsearch;
        proxy_redirect off;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $http_host;
        proxy_pass_header Access-Control-Allow-Origin;
        proxy_pass_header Access-Control-Allow-Methods;
        proxy_hide_header Access-Control-Allow-Headers;
        add_header Access-Control-Allow-Headers 'X-Requested-With, Content-Type';
        add_header Access-Control-Allow-Credentials true;

        # SSL configuration
        proxy_ssl_verify off;
    }
}
EOF
ln -s /etc/nginx/sites-available/elasticsearch /etc/nginx/sites-enabled/
nginx -t
systemctl restart nginx
}

install_Elasticsearch
install_Kibana
install_Logstash
install_NGINX

ss -tunlp | grep 9200
ss -tunlp | grep 5601
ss -tunlp | grep 5044
echo "$url"
echo "Login: elastic"
echo "Password: $elastic_password"
