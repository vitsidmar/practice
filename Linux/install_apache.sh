#!/bin/bash


apt update -y && apt upgrade -y
apt install apache2 openssl
domain="lamp.migrate.local"
ssldir="/etc/apache2/ssl"
sitedir="/var/www/html/adfs"
sslfile="server"
apachefile="adfs"
sudo mkdir -p $ssldir
sudo openssl genpkey -algorithm RSA -out $ssldir/$sslfile.key -pkeyopt rsa_keygen_bits:2048
sudo openssl req -new -key $ssldir/$sslfile.key -out $ssldir/$sslfile.csr
sudo openssl x509 -req -days 365 -in $ssldir/$sslfile.csr -signkey $ssldir/$sslfile.key -out $ssldir/$sslfile.crt
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
sudo a2ensite $apachefile.conf
sudo systemctl restart apache2
