#!/bin/bash


#set -xe
VERSION="1.0"

# VARIABLES
WWW="/var/www/html"
blanc="\033[1;37m"
gris="\033[0;37m"
magenta="\033[0;35m"
rouge="\033[1;31m"
vert="\033[1;32m"
jaune="\033[1;33m"
bleu="\033[1;34m"
rescolor="\033[0m"

# DEBUT DU SCRIPT
echo -e "$vert"
echo -e "#########################################################"
echo -e "#                                                       #"
echo -e "#          Script d'installation de Nextcloud           #"
echo -e "#                                                       #"
echo -e "#              Testé sur Debian GNU/Linux 9 x64         #"
echo -e "#                      by @pytlin                       #"
echo -e "#                                                       #"
echo -e "#########################################################"
echo -e "                        $VERSION"
echo -e "$rescolor\n\n"
sleep 3


if [ "$UID" -ne "0" ]
then
	echo -e "\n${jaune}\tRun this script as root.$rescolor \n\n"
	exit 1
fi

echo -e "\n${jaune}Mise à jour Système...${rescolor}" && sleep 1
apt-get update -y && apt-get upgrade -y
echo -e "\n${jaune}Installation de quelques paquets...${rescolor}" && sleep 1
apt-get install sudo vim apt-transport-https dirmngr ufw -y

#Variables
PortSSH=22
db_root_password="Support27274141ncdbroot@"
domain="sharecloud.mysecureowncloud.net"
loginAdminNC="nextcloudAdmin"
passwdAdminNC="Support27274141ncweb@"
databaseNameNC="nextcloud"
databaseUserNC="nextcloud"
databasePasswdNC="nextcloud"
dataDirNC="/var/nc_data"
databaseNC="mysql"
mailAdminNC="sharecloud@fastmail.com"
userSystemNC="sharecloud"
pwdSystemNC="sharecloud"
versionPHP="7.3"
versionMYSQL="10.3"
timezone="Europe/Paris"
versionNGINX="1.17.0"



is_mysql_command_available() {
  which mysql > /dev/null 2>&1
}

echo -e "\n${jaune}Autorisation port SSH, 80 et 443 - pare-feu : ufw...${rescolor}" && sleep 1
# Disable firewall
ufw --force disable
sudo ufw default allow outgoing
sudo ufw default deny incoming
sudo ufw allow $PortSSH
sudo ufw allow 80
sudo ufw allow 443
# Enable firewall
ufw --force enable

echo -e "\n${jaune}Création de l'utilisateur nextcloud...${rescolor}" && sleep 1
useradd --uid 1010 --home /home/$userSystemNC/ --create-home --shell /bin/bash $userSystemNC
echo "$userSystemNC:$pwdSystemNC" | sudo chpasswd
usermod -aG sudo $userSystemNC
cd /home/$userSystemNC

echo -e "\n${jaune}Installation de quelques paquets et mise à jour système...${rescolor}" && sleep 1
cd /usr/local/src
sudo apt-get install apt-transport-https git wget gnupg2 dirmngr lsb-release ssl-cert ca-certificates tree -y
sudo make-ssl-cert generate-default-snakeoil
echo "deb http://mirror2.hs-esslingen.de/mariadb/repo/$versionMYSQL/debian stretch main" | sudo tee -a /etc/apt/sources.list
echo "deb https://packages.sury.org/php/ stretch main" | sudo tee -a /etc/apt/sources.list
sudo wget -O /etc/apt/trusted.gpg.d/php.gpg https://packages.sury.org/php/apt.gpg
sudo apt-key adv --recv-keys --keyserver hkp://keyserver.ubuntu.com:80 0xF1656F24C74CD1D8
sudo apt-get update -y && sudo apt-get upgrade -y
sudo apt-get install software-properties-common zip unzip screen curl git ffmpeg libfile-fcntllock-perl -y

echo -e "\n${jaune}Téléchargement et ajout clé publique nginx...${rescolor}" && sleep 1
cd /usr/local/src
sudo wget http://nginx.org/keys/nginx_signing.key && sudo apt-key add nginx_signing.key

echo -e "\n${jaune}Mise à jour repository => ajout repository nginx...${rescolor}" && sleep 1
echo "deb http://nginx.org/packages/mainline/debian/ stretch nginx" | sudo tee -a /etc/apt/sources.list
echo "deb-src http://nginx.org/packages/mainline/debian/ stretch nginx" | sudo tee -a /etc/apt/sources.list


echo -e "\n${jaune}Récupération des sources de nginx et OpenSSL...${rescolor}" && sleep 1
sudo mkdir /usr/local/src/nginx && cd /usr/local/src/nginx/
sudo apt-get clean -y && sudo apt-get update -y
sudo apt-get install dpkg-dev -y && sudo apt source nginx
sleep 10
cd /usr/local/src && sudo apt-get install git -y
sleep 5
sudo git clone https://github.com/openssl/openssl.git
sleep 30
cd openssl && git branch -a
sleep 10
sudo git checkout OpenSSL_1_1_1-stable
sleep 5

echo -e "\n${jaune}Modification de la configuration du build de nginx...${rescolor}" && sleep 1
sudo sed -i 's|with-ld-opt="$(LDFLAGS)"|with-ld-opt="$(LDFLAGS)" --with-openssl=/usr/local/src/openssl|g' /usr/local/src/nginx/nginx-$versionNGINX/debian/rules
sudo sed -i s/"dh_shlibdeps -a"/"dh_shlibdeps -a --dpkg-shlibdeps-params=--ignore-missing-info"/g /usr/local/src/nginx/nginx-$versionNGINX/debian/rules
sudo sed -i s/'CFLAGS="$CFLAGS -Werror"'/'#CFLAGS="$CFLAGS -Werror"'/g /usr/local/src/nginx/nginx-$versionNGINX/auto/cc/gcc

echo -e "\n${jaune}Build de nginx...${rescolor}" && sleep 1
cd /usr/local/src/nginx/nginx-$versionNGINX/
sudo apt build-dep nginx -y && sudo dpkg-buildpackage -b

echo -e "\n${jaune}Installation de nginx, freeze de la version de nginx et redémarrage du service nginx...${rescolor}" && sleep 1
sudo apt remove nginx nginx-common nginx-full -y --allow-change-held-packages
cd /usr/local/src/nginx/
#Install the new built NGINX
sudo dpkg -i nginx_1.17.0*.deb
#If the service will be masked please unmask it:
sudo systemctl unmask nginx
sudo systemctl restart nginx
sudo apt-mark hold nginx
sudo nginx -V

echo -e "\n${jaune}Création de dossiers et paramétrage des permissions...${rescolor}" && sleep 1
#create folders and apply permissions :
sudo mkdir -p /var/nc_data /var/www/letsencrypt /usr/local/tmp/sessions /usr/local/tmp/apc
sudo chown -R www-data:www-data /var/nc_data /var/www
sudo chown -R www-data:root /usr/local/tmp/sessions /usr/local/tmp/apc

#if you do not want variables to be replaced, you need to surround END with single quotes.
#conf nginx
echo -e "\n${jaune}backup fichier de configuration nginx => nginx.conf.bak...${rescolor}" && sleep 1
sudo mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak

echo -e "\n${jaune}modification du fichier de configuration nginx => nginx.conf...${rescolor}" && sleep 1
sudo tee -a /etc/nginx/nginx.conf << 'END'
user www-data;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;
events {
worker_connections 1024;
multi_accept on;
use epoll;
}
http {
server_names_hash_bucket_size 64;
upstream php-handler {
server unix:/run/php/php7.3-fpm.sock;
}
set_real_ip_from 127.0.0.1;
set_real_ip_from 62.113.196.44/24;
real_ip_header X-Forwarded-For;
real_ip_recursive on;
include /etc/nginx/mime.types;
include /etc/nginx/proxy.conf;
#include /etc/nginx/ssl.conf;
include /etc/nginx/header.conf;
include /etc/nginx/optimization.conf;
default_type application/octet-stream;
log_format main '$remote_addr - $remote_user [$time_local] "$request" '
'$status $body_bytes_sent "$http_referer" '
'"$http_user_agent" "$http_x_forwarded_for" '
'"$host" sn="$server_name" '
'rt=$request_time '
'ua="$upstream_addr" us="$upstream_status" '
'ut="$upstream_response_time" ul="$upstream_response_length" '
'cs=$upstream_cache_status' ;
access_log /var/log/nginx/access.log main;
sendfile on;
send_timeout 3600;
tcp_nopush on;
tcp_nodelay on;
open_file_cache max=500 inactive=10m;
open_file_cache_errors on;
keepalive_timeout 65;
reset_timedout_connection on;
server_tokens off;
resolver 62.113.196.44 valid=30s;
#resolver 127.0.0.1 valid=30s; is recommended but reuqires a valid resolver configuration
resolver_timeout 5s;
include /etc/nginx/conf.d/*.conf;
}
END

echo -e "\n${jaune}Création du fichier proxy.conf...${rescolor}" && sleep 1
#if you do not want variables to be replaced, you need to surround END with single quotes.
#Create the proxy.conf
sudo touch /etc/nginx/proxy.conf
sudo tee -a /etc/nginx/proxy.conf << 'END'
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-Host $host;
proxy_set_header X-Forwarded-Protocol $scheme;
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Forwarded-Port $server_port;
proxy_set_header X-Forwarded-Server $host;
proxy_connect_timeout 3600;
proxy_send_timeout 3600;
proxy_read_timeout 3600;
proxy_redirect off;
END

echo -e "\n${jaune}Création du fichier header.conf...${rescolor}" && sleep 1
#Create the header.conf
sudo touch /etc/nginx/header.conf
sudo tee -a /etc/nginx/header.conf << 'END'
add_header Strict-Transport-Security "max-age=15768000; includeSubDomains; preload;";
add_header X-Robots-Tag none;
add_header X-Download-Options noopen;
add_header X-Permitted-Cross-Domain-Policies none;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "no-referrer" always;
#add_header Feature-Policy "accelerometer 'none'; autoplay 'self'; geolocation 'none'; midi 'none'; sync-xhr 'self' ; microphone 'self'; camera 'self'; magnetometer 'none'; gyroscope 'none'; speaker 'self'; fullscreen 'self'; payment 'none'; usb 'none'";
END

echo -e "\n${jaune}Création du fichier optimization.conf...${rescolor}" && sleep 1
#if you do not want variables to be replaced, you need to surround END with single quotes.
#Create the optimization.conf
sudo touch /etc/nginx/optimization.conf
sudo tee -a /etc/nginx/optimization.conf << 'END'
fastcgi_read_timeout 3600;
fastcgi_buffers 64 64K;
fastcgi_buffer_size 256k;
fastcgi_busy_buffers_size 3840K;
fastcgi_cache_key $http_cookie$request_method$host$request_uri;
fastcgi_cache_use_stale error timeout invalid_header http_500;
fastcgi_ignore_headers Cache-Control Expires Set-Cookie;
gzip on;
gzip_vary on;
gzip_comp_level 4;
gzip_min_length 256;
gzip_proxied expired no-cache no-store private no_last_modified no_etag auth;
gzip_types application/atom+xml application/javascript application/json application/ld+json application/manifest+json application/rss+xml application/vnd.geo+json application/vnd.ms-fontobject application/x-font-ttf application/x-web-app-manifest+json application/xhtml+xml application/xml font/opentype image/bmp image/svg+xml image/x-icon text/cache-manifest text/css text/plain text/vcard text/vnd.rim.location.xloc text/vtt text/x-component text/x-cross-domain-policy;
gzip_disable "MSIE [1-6]\.";
END

echo -e "\n${jaune}Création du fichier php_optimization.conf...${rescolor}" && sleep 1
#if you do not want variables to be replaced, you need to surround END with single quotes.
#Create the php_optimization.conf
sudo touch /etc/nginx/php_optimization.conf
sudo tee -a /etc/nginx/php_optimization.conf << 'END'
fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
fastcgi_param PATH_INFO $fastcgi_path_info;
fastcgi_param modHeadersAvailable true;
fastcgi_param front_controller_active true;
fastcgi_intercept_errors on;
fastcgi_request_buffering off;
fastcgi_cache_valid 404 1m;
fastcgi_cache_valid any 1h;
fastcgi_cache_methods GET HEAD;
END

echo -e "\n${jaune}Création du fichier ssl.conf...${rescolor}" && sleep 1
#if you do not want variables to be replaced, you need to surround END with single quotes
#create the ssl.conf
sudo touch /etc/nginx/ssl.conf
sudo tee -a /etc/nginx/ssl.conf << 'END'
ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;
ssl_trusted_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
ssl_certificate /etc/letsencrypt/rsa-certs/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/rsa-certs/privkey.pem;
ssl_certificate /etc/letsencrypt/ecc-certs/fullchain.pem;                                                                                                                               
ssl_certificate_key /etc/letsencrypt/ecc-certs/privkey.pem;                                                                                                                             
ssl_trusted_certificate /etc/letsencrypt/ecc-certs/chain.pem;
#ssl_dhparam /etc/ssl/certs/dhparam.pem;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;
ssl_session_tickets off;
ssl_protocols TLSv1.3 TLSv1.2;
ssl_ciphers 'TLS-CHACHA20-POLY1305-SHA256:TLS-AES-256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384';
ssl_ecdh_curve X448:secp521r1:secp384r1:prime256v1;
ssl_prefer_server_ciphers on;
ssl_stapling on;
ssl_stapling_verify on;
END

echo -e "\n${jaune}Création du fichier letsencrypt.conf...${rescolor}" && sleep 1
#if you do not want variables to be replaced, you need to surround END with single quotes.
#create letsencrypt.conf
sudo touch /etc/nginx/conf.d/letsencrypt.conf
sudo tee -a /etc/nginx/conf.d/letsencrypt.conf << 'END'
server {
server_name 127.0.0.1;
listen 127.0.0.1:81 default_server;
charset utf-8;
access_log /var/log/nginx/le.access.log main;
error_log /var/log/nginx/le.error.log warn;
location ^~ /.well-known/acme-challenge {
default_type text/plain;
root /var/www/letsencrypt;
}
}
END

echo -e "\n${jaune}Installation de php $versionPHP...${rescolor}" && sleep 1
#install php
sudo apt-get install php$versionPHP-fpm php$versionPHP-gd php$versionPHP-mysql php$versionPHP-curl php$versionPHP-xml php$versionPHP-zip php$versionPHP-intl php$versionPHP-mbstring php$versionPHP-json php$versionPHP-bz2 php$versionPHP-ldap php-apcu imagemagick php-imagick -y

echo -e "\n${jaune}Modification timezeone...${rescolor}" && sleep 1
timedatectl set-timezone $timezone

echo -e "\n${jaune}Modification fichier de configuration php et php$versionPHP-fpm...${rescolor}" && sleep 1
#Configure PHP
sudo cp /etc/php/$versionPHP/fpm/pool.d/www.conf /etc/php/$versionPHP/fpm/pool.d/www.conf.bak
sudo cp /etc/php/$versionPHP/cli/php.ini /etc/php/$versionPHP/cli/php.ini.bak
sudo cp /etc/php/$versionPHP/fpm/php.ini /etc/php/$versionPHP/fpm/php.ini.bak
sudo cp /etc/php/$versionPHP/fpm/php-fpm.conf /etc/php/$versionPHP/fpm/php-fpm.conf.bak
sudo sed -i "s/;env\[HOSTNAME\] = /env[HOSTNAME] = /" /etc/php/$versionPHP/fpm/pool.d/www.conf
sudo sed -i "s/;env\[TMP\] = /env[TMP] = /" /etc/php/$versionPHP/fpm/pool.d/www.conf
sudo sed -i "s/;env\[TMPDIR\] = /env[TMPDIR] = /" /etc/php/$versionPHP/fpm/pool.d/www.conf
sudo sed -i "s/;env\[TEMP\] = /env[TEMP] = /" /etc/php/$versionPHP/fpm/pool.d/www.conf
sudo sed -i "s/;env\[PATH\] = /env[PATH] = /" /etc/php/$versionPHP/fpm/pool.d/www.conf
sudo sed -i "s/pm.max_children = .*/pm.max_children = 240/" /etc/php/$versionPHP/fpm/pool.d/www.conf
sudo sed -i "s/pm.start_servers = .*/pm.start_servers = 20/" /etc/php/$versionPHP/fpm/pool.d/www.conf
sudo sed -i "s/pm.min_spare_servers = .*/pm.min_spare_servers = 10/" /etc/php/$versionPHP/fpm/pool.d/www.conf
sudo sed -i "s/pm.max_spare_servers = .*/pm.max_spare_servers = 20/" /etc/php/$versionPHP/fpm/pool.d/www.conf
sudo sed -i "s/;pm.max_requests = 500/pm.max_requests = 500/" /etc/php/$versionPHP/fpm/pool.d/www.conf
sudo sed -i "s/output_buffering =.*/output_buffering = 'Off'/" /etc/php/$versionPHP/cli/php.ini
sudo sed -i "s/max_execution_time =.*/max_execution_time = 1800/" /etc/php/$versionPHP/cli/php.ini
sudo sed -i "s/max_input_time =.*/max_input_time = 3600/" /etc/php/$versionPHP/cli/php.ini
sudo sed -i "s/post_max_size =.*/post_max_size = 10240M/" /etc/php/$versionPHP/cli/php.ini
sudo sed -i "s/upload_max_filesize =.*/upload_max_filesize = 10240M/" /etc/php/$versionPHP/cli/php.ini
sudo sed -i "s/max_file_uploads =.*/max_file_uploads = 100/" /etc/php/$versionPHP/cli/php.ini
sudo sed -i "s/;date.timezone.*/date.timezone = Europe\/\Berlin/" /etc/php/$versionPHP/cli/php.ini
sudo sed -i "s/;session.cookie_secure.*/session.cookie_secure = True/" /etc/php/$versionPHP/cli/php.ini
sudo sed -i "s/;session.save_path =.*/session.save_path = \"N;700;\/usr\/local\/tmp\/sessions\"/" /etc/php/$versionPHP/cli/php.ini
sudo sed -i '$aapc.enable_cli = 1' /etc/php/$versionPHP/cli/php.ini
sudo sed -i "s/memory_limit = 128M/memory_limit = 512M/" /etc/php/$versionPHP/fpm/php.ini
sudo sed -i "s/output_buffering =.*/output_buffering = 'Off'/" /etc/php/$versionPHP/fpm/php.ini
sudo sed -i "s/max_execution_time =.*/max_execution_time = 1800/" /etc/php/$versionPHP/fpm/php.ini
sudo sed -i "s/max_input_time =.*/max_input_time = 3600/" /etc/php/$versionPHP/fpm/php.ini
sudo sed -i "s/post_max_size =.*/post_max_size = 10240M/" /etc/php/$versionPHP/fpm/php.ini
sudo sed -i "s/upload_max_filesize =.*/upload_max_filesize = 10240M/" /etc/php/$versionPHP/fpm/php.ini
sudo sed -i "s/max_file_uploads =.*/max_file_uploads = 100/" /etc/php/$versionPHP/fpm/php.ini
sudo sed -i "s/;date.timezone.*/date.timezone = Europe\/\Berlin/" /etc/php/$versionPHP/fpm/php.ini
sudo sed -i "s/;session.cookie_secure.*/session.cookie_secure = True/" /etc/php/$versionPHP/fpm/php.ini
sudo sed -i "s/;opcache.enable=.*/opcache.enable=1/" /etc/php/$versionPHP/fpm/php.ini
sudo sed -i "s/;opcache.enable_cli=.*/opcache.enable_cli=1/" /etc/php/$versionPHP/fpm/php.ini
sudo sed -i "s/;opcache.memory_consumption=.*/opcache.memory_consumption=128/" /etc/php/$versionPHP/fpm/php.ini
sudo sed -i "s/;opcache.interned_strings_buffer=.*/opcache.interned_strings_buffer=8/" /etc/php/$versionPHP/fpm/php.ini
sudo sed -i "s/;opcache.max_accelerated_files=.*/opcache.max_accelerated_files=10000/" /etc/php/$versionPHP/fpm/php.ini
sudo sed -i "s/;opcache.revalidate_freq=.*/opcache.revalidate_freq=1/" /etc/php/$versionPHP/fpm/php.ini
sudo sed -i "s/;opcache.save_comments=.*/opcache.save_comments=1/" /etc/php/$versionPHP/fpm/php.ini
sudo sed -i "s/;session.save_path =.*/session.save_path = \"N;700;\/usr\/local\/tmp\/sessions\"/" /etc/php/$versionPHP/fpm/php.ini
sudo sed -i "s/;emergency_restart_threshold =.*/emergency_restart_threshold = 10/" /etc/php/$versionPHP/fpm/php-fpm.conf
sudo sed -i "s/;emergency_restart_interval =.*/emergency_restart_interval = 1m/" /etc/php/$versionPHP/fpm/php-fpm.conf
sudo sed -i "s/;process_control_timeout =.*/process_control_timeout = 10s/" /etc/php/$versionPHP/fpm/php-fpm.conf
sudo sed -i '$aapc.enabled=1' /etc/php/$versionPHP/fpm/php.ini
sudo sed -i '$aapc.file_update_protection=2' /etc/php/$versionPHP/fpm/php.ini
sudo sed -i '$aapc.optimization=0' /etc/php/$versionPHP/fpm/php.ini
sudo sed -i '$aapc.shm_size=256M' /etc/php/$versionPHP/fpm/php.ini
sudo sed -i '$aapc.include_once_override=0' /etc/php/$versionPHP/fpm/php.ini
sudo sed -i '$aapc.shm_segments=1' /etc/php/$versionPHP/fpm/php.ini
sudo sed -i '$aapc.ttl=7200' /etc/php/$versionPHP/fpm/php.ini
sudo sed -i '$aapc.user_ttl=7200' /etc/php/$versionPHP/fpm/php.ini
sudo sed -i '$aapc.gc_ttl=3600' /etc/php/$versionPHP/fpm/php.ini
sudo sed -i '$aapc.num_files_hint=1024' /etc/php/$versionPHP/fpm/php.ini
sudo sed -i '$aapc.enable_cli=0' /etc/php/$versionPHP/fpm/php.ini
sudo sed -i '$aapc.max_file_size=5M' /etc/php/$versionPHP/fpm/php.ini
sudo sed -i '$aapc.cache_by_default=1' /etc/php/$versionPHP/fpm/php.ini
sudo sed -i '$aapc.use_request_time=1' /etc/php/$versionPHP/fpm/php.ini
sudo sed -i '$aapc.slam_defense=0' /etc/php/$versionPHP/fpm/php.ini
sudo sed -i '$aapc.mmap_file_mask=/usr/local/tmp/apc/apc.XXXXXX' /etc/php/$versionPHP/fpm/php.ini
sudo sed -i '$aapc.stat_ctime=0' /etc/php/$versionPHP/fpm/php.ini
sudo sed -i '$aapc.canonicalize=1' /etc/php/$versionPHP/fpm/php.ini
sudo sed -i '$aapc.write_lock=1' /etc/php/$versionPHP/fpm/php.ini
sudo sed -i '$aapc.report_autofilter=0' /etc/php/$versionPHP/fpm/php.ini
sudo sed -i '$aapc.rfc1867=0' /etc/php/$versionPHP/fpm/php.ini
sudo sed -i '$aapc.rfc1867_prefix =upload_' /etc/php/$versionPHP/fpm/php.ini
sudo sed -i '$aapc.rfc1867_name=APC_UPLOAD_PROGRESS' /etc/php/$versionPHP/fpm/php.ini
sudo sed -i '$aapc.rfc1867_freq=0' /etc/php/$versionPHP/fpm/php.ini
sudo sed -i '$aapc.rfc1867_ttl=3600' /etc/php/$versionPHP/fpm/php.ini
sudo sed -i '$aapc.lazy_classes=0' /etc/php/$versionPHP/fpm/php.ini
sudo sed -i '$aapc.lazy_functions=0' /etc/php/$versionPHP/fpm/php.ini
sudo sed -i "s/09,39.*/# &/" /etc/cron.d/php
sudo sed -i "s/rights\=\"none\" pattern\=\"PDF\"/rights\=\"read\|write\" pattern\=\"PDF\"/" /etc/ImageMagick-6/policy.xml


echo -e "\n${jaune}Installation MariaDB...${rescolor}" && sleep 1
#install mariadb
export DEBIAN_FRONTEND=noninteractive
debconf-set-selections <<< "mariadb-server mysql-server/root_password password ${db_root_password}"
debconf-set-selections <<< "mariadb-server mysql-server/root_password_again password ${db_root_password}"
sudo apt-get install mariadb-server -y

if ! is_mysql_command_available; then
  echo "The MySQL/MariaDB client mysql(1) is not installed."
  exit 1
fi

echo -e "\n${jaune}Affichage de la version de mysql...${rescolor}" && sleep 1
mysql --version 

echo -e "\n${jaune}Sécurisation de MariaDB...${rescolor}" && sleep 1
#automatization of mysql_secure_installation :
mysql --user=root --password=${db_root_password} <<_EOF_
  UPDATE mysql.user SET Password=PASSWORD('${db_root_password}') WHERE User='root';
  DELETE FROM mysql.user WHERE User='';
  DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
  DROP DATABASE IF EXISTS test;
  DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
  FLUSH PRIVILEGES;
_EOF_

echo -e "\n${jaune}Configuration de MariaDB...${rescolor}" && sleep 1
#configure mariadb
sudo systemctl stop mysql
sudo mv /etc/mysql/mariadb.cnf /etc/mysql/mariadb.cnf.bak
sudo tee -a /etc/mysql/mariadb.cnf << 'END'
[client]
default-character-set = utf8mb4
port = 3306
socket = /var/run/mysqld/mysqld.sock

[mysqld_safe]
log_error=/var/log/mysql/mysql_error.log
nice = 0
socket = /var/run/mysqld/mysqld.sock

[mysqld]
basedir = /usr
bind-address = 127.0.0.1
binlog_format = ROW
bulk_insert_buffer_size = 16M
character-set-server = utf8mb4
collation-server = utf8mb4_general_ci
concurrent_insert = 2
connect_timeout = 5
datadir = /var/lib/mysql
default_storage_engine = InnoDB
expire_logs_days = 10
general_log_file = /var/log/mysql/mysql.log
general_log = 0
innodb_buffer_pool_size = 1024M
innodb_buffer_pool_instances = 1
innodb_flush_log_at_trx_commit = 2
innodb_log_buffer_size = 32M
innodb_max_dirty_pages_pct = 90
innodb_file_per_table = 1
innodb_open_files = 400
innodb_io_capacity = 4000
innodb_flush_method = O_DIRECT
key_buffer_size = 128M
lc_messages_dir = /usr/share/mysql
lc_messages = en_US
log_bin = /var/log/mysql/mariadb-bin
log_bin_index = /var/log/mysql/mariadb-bin.index
log_error=/var/log/mysql/mysql_error.log
log_slow_verbosity = query_plan
log_warnings = 2
long_query_time = 1
max_allowed_packet = 16M
max_binlog_size = 100M
max_connections = 200
max_heap_table_size = 64M
myisam_recover_options = BACKUP
myisam_sort_buffer_size = 512M
port = 3306
pid-file = /var/run/mysqld/mysqld.pid
query_cache_limit = 2M
query_cache_size = 64M
query_cache_type = 1
query_cache_min_res_unit = 2k
read_buffer_size = 2M
read_rnd_buffer_size = 1M
skip-external-locking
skip-name-resolve
slow_query_log_file = /var/log/mysql/mariadb-slow.log
slow-query-log = 1
socket = /var/run/mysqld/mysqld.sock
sort_buffer_size = 4M
table_open_cache = 400
thread_cache_size = 128
tmp_table_size = 64M
tmpdir = /tmp
transaction_isolation = READ-COMMITTED
user = mysql
wait_timeout = 600

[mysqldump]
max_allowed_packet = 16M
quick
quote-names

[isamchk]
!include /etc/mysql/mariadb.cnf
!includedir /etc/mysql/conf.d/
key_buffer = 16M
END

echo -e "\n${jaune}restart mariaDB...${rescolor}" && sleep 1
#restart mariadb and connect to mariadb
sudo systemctl restart mysql

echo -e "\n${jaune}create database, user database and password...${rescolor}" && sleep 1
#create database nextcloud, the user and the password :
mysql --user=root --password=${db_root_password} <<_EOF_
  CREATE DATABASE nextcloud CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci; 
  CREATE USER nextcloud@localhost identified by 'nextcloud'; 
  GRANT ALL PRIVILEGES on nextcloud.* to nextcloud@localhost; 
  FLUSH privileges; 
_EOF_

echo -e "\n${jaune}Vérification du niveau d'isolation des transactions et de la collation...${rescolor}" && sleep 1
#Verify the transaction Isolation level was set to READ_Commit and the collation was set to UTF8MB4 properly:
mysql -h localhost -uroot -p${db_root_password} -e "SELECT @@TX_ISOLATION; SELECT SCHEMA_NAME 'database', default_character_set_name 'charset', DEFAULT_COLLATION_NAME 'collation' FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='nextcloud'"

#result is REPEATABLE-READ #tocorrect
#If the resultset will be “READ-COMMITTED” and “utf8mb4_general_ci” as shown go ahead with the installation of redis.
#tofix

echo -e "\n${jaune}Installation de redis...${rescolor}" && sleep 1
#install redis
sudo apt install redis-server php-redis -y

echo -e "\n${jaune}Configuration de redis...${rescolor}" && sleep 1
sudo cp /etc/redis/redis.conf /etc/redis/redis.conf.bak
sudo sed -i "s/port 6379/port 0/" /etc/redis/redis.conf
sudo sed -i s/\#\ unixsocket/\unixsocket/g /etc/redis/redis.conf
sudo sed -i "s/unixsocketperm 700/unixsocketperm 770/" /etc/redis/redis.conf
sudo sed -i "s/# maxclients 10000/maxclients 512/" /etc/redis/redis.conf
sudo usermod -aG redis www-data
sudo cp /etc/sysctl.conf /etc/sysctl.conf.bak && sudo sed -i '$avm.overcommit_memory = 1' /etc/sysctl.conf

echo -e "\n${jaune}VirtualHost nextcloud...${rescolor}" && sleep 1
#nextcloud
[ -f /etc/nginx/conf.d/default.conf ] && sudo mv /etc/nginx/conf.d/default.conf /etc/nginx/conf.d/default.conf.bak
sudo touch /etc/nginx/conf.d/default.conf
sudo touch /etc/nginx/conf.d/nextcloud.conf
#if you do not want variables to be replaced, you need to surround END with single quotes.
sudo tee -a /etc/nginx/conf.d/nextcloud.conf << 'END'
server {
server_name mysecureowncloud.net;
listen 80 default_server;
location ^~ /.well-known/acme-challenge {
proxy_pass http://127.0.0.1:81;
proxy_set_header Host $host;
}
location / {
return 301 https://$host$request_uri;
}
}
server {
server_name mysecureowncloud.net;
listen 443 http2 default_server; 
root /var/www/nextcloud/;
access_log /var/log/nginx/nextcloud.access.log main;
error_log /var/log/nginx/nextcloud.error.log warn;
location = /robots.txt {
allow all;
log_not_found off;
access_log off;
}
location = /.well-known/carddav {
return 301 $scheme://$host/remote.php/dav;
}
location = /.well-known/caldav {
return 301 $scheme://$host/remote.php/dav;
}
#SOCIAL app enabled? Please uncomment the following three rows
#rewrite ^/.well-known/webfinger /public.php?service=webfinger last;
#rewrite ^/.well-known/host-meta /public.php?service=host-meta last;
#rewrite ^/.well-known/host-meta.json /public.php?service=host-meta-json last;
client_max_body_size 10240M;
location / {
rewrite ^ /index.php$request_uri;
}
location ~ ^/(?:build|tests|config|lib|3rdparty|templates|data)/ {
deny all;
}
location ~ ^/(?:\.|autotest|occ|issue|indie|db_|console) {
deny all;
}
location ~ \.(?:flv|mp4|mov|m4a)$ {
mp4;
mp4_buffer_size 100M;
mp4_max_buffer_size 1024M;
fastcgi_split_path_info ^(.+\.php)(/.*)$;
include fastcgi_params;
include php_optimization.conf;
fastcgi_pass php-handler;
fastcgi_param HTTPS on;
}
location ~ ^/(?:index|remote|public|cron|core/ajax/update|status|ocs/v[12]|updater/.+|ocs-provider/.+)\.php(?:$|/) {
fastcgi_split_path_info ^(.+\.php)(/.*)$;
include fastcgi_params;
include php_optimization.conf;
fastcgi_pass php-handler;
fastcgi_param HTTPS on;
}
location ~ ^/(?:updater|ocs-provider)(?:$|/) {
try_files $uri/ =404;
index index.php;
}
location ~ \.(?:css|js|woff2?|svg|gif|png|html|ttf|ico|jpg|jpeg)$ {
try_files $uri /index.php$request_uri;
access_log off;
expires 360d;
}
}
END

#Enhance security, may take time accoding to your hardware #last more than 12 minutes, so optional 
#if we don't execute this, we must put in comment the line dhparam.pem in /etc/nginx/ssl.conf
#sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 4096

echo -e "\n${jaune}Téléchargement de Nextcloud...${rescolor}" && sleep 1
#download and extract nextcloud
cd ~
sudo wget https://download.nextcloud.com/server/releases/latest.tar.bz2
sudo tar -xjf latest.tar.bz2 -C /var/www && sudo chown -R www-data:www-data /var/www/ && sudo rm latest*.tar.bz2

echo -e "\n${jaune}Création du script des permissions => permissions.sh...${rescolor}" && sleep 1
#Apply the permissions using a permissions.sh script:
sudo touch /root/permissions.sh
sudo tee -a /root/permissions.sh << 'END'
#!/bin/bash
find /var/www/ -type f -print0 | xargs -0 chmod 0640
find /var/www/ -type d -print0 | xargs -0 chmod 0750
chown -R www-data:www-data /var/www/
chown -R www-data:www-data /var/nc_data/
chmod 0644 /var/www/nextcloud/.htaccess
chmod 0644 /var/www/nextcloud/.user.ini
chmod 600 /etc/letsencrypt/rsa-certs/fullchain.pem
chmod 600 /etc/letsencrypt/rsa-certs/privkey.pem
chmod 600 /etc/letsencrypt/rsa-certs/chain.pem
chmod 600 /etc/letsencrypt/rsa-certs/cert.pem
chmod 600 /etc/letsencrypt/ecc-certs/fullchain.pem
chmod 600 /etc/letsencrypt/ecc-certs/privkey.pem
chmod 600 /etc/letsencrypt/ecc-certs/chain.pem
chmod 600 /etc/letsencrypt/ecc-certs/cert.pem
chmod 600 /etc/ssl/certs/dhparam.pem
exit 0
END

echo -e "\n${jaune}Execution du script permissions.sh...${rescolor}" && sleep 1
sudo chmod +x /root/permissions.sh && sudo /root/permissions.sh


echo -e "\n${jaune}modification ssl.conf...${rescolor}" && sleep 1
#Modify the ssl.conf
sudo sed -i '/ssl-cert-snakeoil/d' /etc/nginx/ssl.conf
sudo sed -i s/\#\ssl/\ssl/g /etc/nginx/ssl.conf


echo -e "\n${jaune}Installation de Nextcloud...${rescolor}" && sleep 1
#install nextcloud silently
sudo -s /bin/bash -c "php /var/www/nextcloud/occ maintenance:install --database ${databaseNC} --database-name ${databaseNameNC} --database-user ${databaseUserNC} --database-pass ${databasePasswdNC} --admin-user ${loginAdminNC} --admin-pass ${passwdAdminNC} --data-dir ${dataDirNC}"


echo -e "\n${jaune}modification configuration php => config.php...${rescolor}" && sleep 1
sudo -s /bin/bash -c "php /var/www/nextcloud/occ config:system:set trusted_domains 1 --value=${domain}"
sudo -s /bin/bash -c "php /var/www/nextcloud/occ config:system:set overwrite.cli.url --value=https://${domain}"
sudo cp /var/www/nextcloud/config/config.php /var/www/nextcloud/config/config.php.bak


sudo sed -i 's/^[ ]*//' /var/www/nextcloud/config/config.php
sudo sed -i '/);/d' /var/www/nextcloud/config/config.php

sudo tee -a /var/www/nextcloud/config/config.php << 'END'
'activity_expire_days' => 14,
'auth.bruteforce.protection.enabled' => true,
'blacklisted_files' => 
array (
0 => '.htaccess',
1 => 'Thumbs.db',
2 => 'thumbs.db',
),
'cron_log' => true,
'enable_previews' => true,
'enabledPreviewProviders' => 
array (
0 => 'OC\\Preview\\PNG',
1 => 'OC\\Preview\\JPEG',
2 => 'OC\\Preview\\GIF',
3 => 'OC\\Preview\\BMP',
4 => 'OC\\Preview\\XBitmap',
5 => 'OC\\Preview\\Movie',
6 => 'OC\\Preview\\PDF',
7 => 'OC\\Preview\\MP3',
8 => 'OC\\Preview\\TXT',
9 => 'OC\\Preview\\MarkDown',
),
'filesystem_check_changes' => 0,
'filelocking.enabled' => 'true',
'htaccess.RewriteBase' => '/',
'integrity.check.disabled' => false,
'knowledgebaseenabled' => false,
'logfile' => '/var/nc_data/nextcloud.log',
'loglevel' => 2,
'logtimezone' => 'Europe/Berlin',
'log_rotate_size' => 104857600,
'maintenance' => false,
'memcache.local' => '\\OC\\Memcache\\APCu',
'memcache.locking' => '\\OC\\Memcache\\Redis',
'overwriteprotocol' => 'https',
'preview_max_x' => 1024,
'preview_max_y' => 768,
'preview_max_scale_factor' => 1,
'redis' => 
array (
'host' => '/var/run/redis/redis.sock',
'port' => 0,
'timeout' => 0.0,
),
'quota_include_external_storage' => false,
'share_folder' => '/Shares',
'skeletondirectory' => '',
'theme' => '',
'trashbin_retention_obligation' => 'auto, 7',
'updater.release.channel' => 'stable',
);
END

echo -e "\n${jaune}Modification du fichier .user.ini (configuration de nextcloud) ...${rescolor}" && sleep 1
#Edit the Nextcloud .user.ini
sudo sed -i "s/upload_max_filesize=.*/upload_max_filesize=10240M/" /var/www/nextcloud/.user.ini
sudo sed -i "s/post_max_size=.*/post_max_size=10240M/" /var/www/nextcloud/.user.ini
sudo sed -i "s/output_buffering=.*/output_buffering='Off'/" /var/www/nextcloud/.user.ini


echo -e "\n${jaune}Exécution du script des permissions => permissions.sh ...${rescolor}" && sleep 1
sudo /root/permissions.sh

echo "--------------------------------------------------------acme------------------------------------------------"

echo -e "\n${jaune}Génération des certificats pour le domaine : $domain ...${rescolor}" && sleep 1
#Install acme and request your ssl-certificate(s):
cd /home/$userSystemNC
sudo su $userSystemNC -c 'git clone https://github.com/Neilpang/acme.sh.git'
cd acme.sh
sudo chmod +x acme.sh
sudo su $userSystemNC -c './acme.sh --install'
sudo su $userSystemNC -c './acme.sh --upgrade --use-wget'
sudo mkdir -p /etc/letsencrypt/rsa-certs /etc/letsencrypt/ecc-certs
cd /home/userSystemNC/.acme.sh
sudo /home/$userSystemNC/.acme.sh/acme.sh --issue -d $domain --keylength 4096 -w /var/www/letsencrypt --key-file /etc/letsencrypt/rsa-certs/privkey.pem --ca-file /etc/letsencrypt/rsa-certs/chain.pem --cert-file /etc/letsencrypt/rsa-certs/cert.pem --fullchain-file /etc/letsencrypt/rsa-certs/fullchain.pem --home /home/$userSystemNC/.acme.sh/ --staging
sudo /home/$userSystemNC/.acme.sh/acme.sh --issue -d $domain --keylength ec-384 -w /var/www/letsencrypt --key-file /etc/letsencrypt/ecc-certs/privkey.pem --ca-file /etc/letsencrypt/ecc-certs/chain.pem --cert-file /etc/letsencrypt/ecc-certs/cert.pem --fullchain-file /etc/letsencrypt/ecc-certs/fullchain.pem --home /home/$userSystemNC/.acme.sh/ --staging

echo -e "\n${jaune}Modification nginx.conf et nextcloud.conf => prise en compte des certificats ...${rescolor}" && sleep 1
sudo sed -i s/\#\include/\include/g /etc/nginx/nginx.conf
sudo sed -i s/"listen 443"/"listen 443 ssl"/g /etc/nginx/conf.d/nextcloud.conf

echo -e "\n${jaune}Exécution du script des permissions => permissions.sh ...${rescolor}" && sleep 1
sudo /root/permissions.sh


echo -e "\n${jaune}Test de la configuration nginx...${rescolor}" && sleep 1
#tocheck
sudo nginx -t

echo -e "\n${jaune}Redémarrage des services : mysql, php$versionPHP-fpm, redis-server et nginx...${rescolor}" && sleep 1
#restart all services
sudo systemctl restart mysql && sudo systemctl restart php$versionPHP-fpm  && sudo systemctl restart redis-server  && sudo systemctl restart nginx  #&& sudo systemctl restart fail2ban

echo -e "\n${jaune}Activation des applications et finitions du paramétrage de Nextcloud...${rescolor}" && sleep 1
#Adjust Nextcloud configuration with occ
sudo -u www-data -s /bin/bash -c 'php /var/www/nextcloud/occ app:disable survey_client'
sudo -u www-data -s /bin/bash -c 'php /var/www/nextcloud/occ app:disable firstrunwizard'
sudo -u www-data -s /bin/bash -c 'php /var/www/nextcloud/occ app:disable admin_audit'
sudo -u www-data -s /bin/bash -c 'php /var/www/nextcloud/occ app:disable files_pdfviewer'
sudo -u www-data -s /bin/bash -c 'php /var/www/nextcloud/occ app:enable calendar'
sudo -u www-data -s /bin/bash -c 'php /var/www/nextcloud/occ app:enable news'
sudo -u www-data -s /bin/bash -c 'php /var/www/nextcloud/occ app:enable contacts'
sudo -u www-data -s /bin/bash -c 'php /var/www/nextcloud/occ app:enable mail'
sudo -u www-data -s /bin/bash -c 'php /var/www/nextcloud/occ app:enable tasks'
sudo -u www-data -s /bin/bash -c 'php /var/www/nextcloud/occ app:enable keeweb'
sudo -u www-data -s /bin/bash -c 'php /var/www/nextcloud/occ app:enable bookmarks'
sudo -u www-data -s /bin/bash -c 'php /var/www/nextcloud/occ app:enable circles'
sudo -u www-data -s /bin/bash -c 'php /var/www/nextcloud/occ app:enable notes'
sudo -u www-data -s /bin/bash -c 'php /var/www/nextcloud/occ app:enable activity'
sudo -u www-data -s /bin/bash -c 'php /var/www/nextcloud/occ app:disable encryption'
sudo -u www-data -s /bin/bash -c 'php /var/www/nextcloud/occ app:enable talk'
sudo -u www-data -s /bin/bash -c 'php /var/www/nextcloud/occ app:enable registration'

sudo -u www-data -s /bin/bash -c 'php /var/www/nextcloud/occ log:manage --level 0'
sudo -u www-data -s /bin/bash -c 'php /var/www/nextcloud/occ app:enable encryption'
sudo -u www-data -s /bin/bash -c 'php /var/www/nextcloud/occ encryption:enable'
sudo -u www-data -s /bin/bash -c 'php /var/www/nextcloud/occ encryption:encrypt-all'
sudo -u www-data -s /bin/bash -c "php /var/www/nextcloud/occ user:setting ${loginAdminNC} settings email ${mailAdminNC}"

echo -e "\n\n${magenta} --- FIN DU SCRIPT (v${VERSION})---\n${rescolor}"

exit 0

