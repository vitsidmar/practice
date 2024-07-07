apt update -y && apt upgrade -y
apt install apache2 openssl
sudo mkdir /etc/apache2/ssl
sudo openssl genpkey -algorithm RSA -out /etc/apache2/ssl/server.key -pkeyopt rsa_keygen_bits:2048
sudo openssl req -new -key /etc/apache2/ssl/server.key -out /etc/apache2/ssl/server.csr
sudo openssl x509 -req -days 365 -in /etc/apache2/ssl/server.csr -signkey /etc/apache2/ssl/server.key -out /etc/apache2/ssl/server.crt

<VirtualHost *:80>
    ServerName lamp.migrate.local
    Redirect permanent / https://lamp.migrate.local/
</VirtualHost>

<VirtualHost *:443>
    ServerName lamp.migrate.local

    DocumentRoot /var/www/html/adfs
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined

    SSLEngine on
    SSLCertificateFile /etc/apache2/ssl/server.crt
    SSLCertificateKeyFile /etc/apache2/ssl/server.key

    <Directory /var/www/html/adfs>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>

sudo a2enmod ssl
sudo a2ensite adfs.conf
sudo systemctl restart apache2
