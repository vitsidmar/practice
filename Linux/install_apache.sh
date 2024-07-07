#!/bin/bash
# curl -L https://github.com/vitsidmar/practice/raw/main/Linux/install_apache.sh -o install_apache.sh && chmod +x install_apache.sh && ./install_apache.sh
sed -i "/#\$nrconf{restart} = 'i';/s/.*/\$nrconf{restart} = 'a';/" /etc/needrestart/needrestart.conf
apt update -y && apt upgrade -y
apt install apache2 openssl
domain="lamp.migrate.local"
ssldir="/etc/apache2/ssl"
sslfile="server"
sitedir="/var/www/html/adfs"
sites_available="adfs"

cat >> $ssldir/$sslfile.cnf << EOL
[ req ]
default_bits       = 2048
default_keyfile    = $sslfile.key
distinguished_name = req_distinguished_name
req_extensions     = req_ext
x509_extensions    = v3_ca # The extentions to add to the self signed cert
prompt             = no

[ req_distinguished_name ]
countryName                = UA
stateOrProvinceName        = Kyiv
localityName               = Kyiv
organizationName           = SS
organizationalUnitName     =
commonName                 = $domain
emailAddress               =

[ req_ext ]
subjectAltName = @alt_names

[ v3_ca ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1   = $domain
EOL
sudo mkdir -p $ssldir
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout $ssldir/$sslfile.key -out $ssldir/$sslfile.crt -config $ssldir/$sslfile.cnf

cat >> /etc/apache2/sites-available/$apachefile.conf << EOL
<VirtualHost *:80>
    ServerName $domain
    Redirect permanent / https://$domain/
</VirtualHost>

<VirtualHost *:443>
    ServerName $domain

    DocumentRoot $sitedir
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined

    SSLEngine on
    SSLCertificateFile $ssldir/$crtname.crt
    SSLCertificateKeyFile $ssldir/$crtname.key

    <Directory $sitedir>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
EOL
sudo a2enmod ssl
sudo a2ensite $sites_available.conf
sudo systemctl restart apache2
