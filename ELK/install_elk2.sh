wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-7.x.list
apt-get update && apt-get install apt-transport-https elasticsearch kibana openjdk-8-jre logstash -y
elastic_conf="/etc/elasticsearch/elasticsearch.yml"
sed -i "s|#node.name: node-1|node.name: elk-node|" $elastic_conf
sed -i "s|#network.host: 192.168.0.1|network.host: 127.0.0.1|" $elastic_conf
ss -tunlp | grep 9200
curl http://localhost:9200
