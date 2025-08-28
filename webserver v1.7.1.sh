#!/bin/bash
#
# ФИНАЛЬНЫЙ СКРИПТ УСТАНОВКИ POWER-СТЕКА НА DEBIAN 12 (v1.7.1 - ИСПРАВЛЕНА ОШИБКА NGINX)
# Эта версия добавляет ручное создание недостающих файлов конфигурации SSL
# (options-ssl-nginx.conf и ssl-dhparams.pem), чтобы гарантировать запуск Nginx.
#
# --- ДАННЫЕ УЖЕ ВНЕСЕНЫ ---
WP_DOMAIN="your.site"
PMA_DOMAIN="db.your.site"
LETSENCRYPT_EMAIL="mail@mail.com"
# --------------------------------------------------------------------

set -e

# --- ПЕРЕМЕННЫЕ И ФУНКЦИИ ---
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'
MARIADB_FALLBACK_VERSION="11.4"
WP_FALLBACK_VERSION="6.6.1"
PMA_FALLBACK_VERSION="5.2.1"
CURL_OPTIONS="--retry 3 --retry-delay 5 -4 -sL --fail --connect-timeout 15"

if [ "$(id -u)" -ne 0 ]; then echo -e "${RED}Ошибка: Скрипт нужно запускать от root.${NC}" >&2; exit 1; fi

fetch_latest_versions() {
    echo -e "\n${YELLOW}Шаг 1: Добавление репозиториев и определение версий...${NC}"
    apt-get update; apt-get install -y curl gnupg2 jq
    mkdir -p /etc/apt/keyrings /usr/share/keyrings
    curl $CURL_OPTIONS https://packages.sury.org/php/apt.gpg | gpg --dearmor | tee /usr/share/keyrings/deb.sury.org-php.gpg > /dev/null
    echo "deb [signed-by=/usr/share/keyrings/deb.sury.org-php.gpg] https://packages.sury.org/php/ $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/php.list
    curl $CURL_OPTIONS https://nginx.org/keys/nginx_signing.key | gpg --dearmor | tee /usr/share/keyrings/nginx-archive-keyring.gpg > /dev/null
    echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/debian `lsb_release -cs` nginx" | tee /etc/apt/sources.list.d/nginx.list
    curl $CURL_OPTIONS 'https://mariadb.org/mariadb_release_signing_key.pgp' > /etc/apt/keyrings/mariadb-keyring.pgp
    apt-get update
    PHP_LATEST=$(apt-cache search --names-only '^php[0-9]+\.[0-9]+$' | cut -d' ' -f1 | sed 's/php//' | sort -V | tail -n1)
    if [ -z "$PHP_LATEST" ]; then echo -e "${RED}Критическая ошибка: Не удалось определить версию PHP.${NC}"; exit 1; fi
    echo -e "${GREEN}PHP: ${PHP_LATEST}${NC}"
    MARIADB_LATEST_DATA=$(curl $CURL_OPTIONS 'https://downloads.mariadb.org/rest-api/mariadb/latest_stable/' || true)
    MARIADB_LATEST_BRANCH=$(echo "$MARIADB_LATEST_DATA" | jq -r '.major_version' 2>/dev/null || true)
    if [ -z "$MARIADB_LATEST_BRANCH" ] || [ "$MARIADB_LATEST_BRANCH" == "null" ]; then MARIADB_LATEST_BRANCH=$MARIADB_FALLBACK_VERSION; echo -e "${YELLOW}MariaDB: не удалось определить, используется запасная версия ${MARIADB_LATEST_BRANCH}.${NC}"; else echo -e "${GREEN}MariaDB: ${MARIADB_LATEST_BRANCH}${NC}"; fi
    echo "deb [signed-by=/etc/apt/keyrings/mariadb-keyring.pgp] https://deb.mariadb.org/${MARIADB_LATEST_BRANCH}/debian $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/mariadb.list
    WP_LATEST_DATA=$(curl $CURL_OPTIONS https://api.wordpress.org/core/version-check/1.7/ || true)
    WP_LATEST=$(echo "$WP_LATEST_DATA" | jq -r '.offers[0].version' 2>/dev/null || true)
    if [ -z "$WP_LATEST" ] || [ "$WP_LATEST" == "null" ]; then WP_LATEST=$WP_FALLBACK_VERSION; echo -e "${YELLOW}WordPress: не удалось определить, используется запасная версия ${WP_LATEST}.${NC}"; else echo -e "${GREEN}WordPress: ${WP_LATEST}${NC}"; fi
    PMA_LATEST_DATA=$(curl $CURL_OPTIONS https://www.phpmyadmin.net/home_page/version.json || true)
    PMA_LATEST=$(echo "$PMA_LATEST_DATA" | jq -r '.version' 2>/dev/null || true)
    if [ -z "$PMA_LATEST" ] || [ "$PMA_LATEST" == "null" ]; then PMA_LATEST=$PMA_FALLBACK_VERSION; echo -e "${YELLOW}phpMyAdmin: не удалось определить, используется запасная версия ${PMA_LATEST}.${NC}"; else echo -e "${GREEN}phpMyAdmin: ${PMA_LATEST}${NC}"; fi
}

clear
echo -e "${BLUE}=====================================================================${NC}"
echo -e "${GREEN}  Автоматическая установка Power-стека для WordPress на Debian 12${NC}"
echo -e "${GREEN}                 Версия 1.7.1 - Стабильный Финальный Релиз${NC}"
echo -e "${BLUE}=====================================================================${NC}"
echo -e "\n${YELLOW}Скрипт будет запущен со следующими параметрами:${NC}"
echo -e " - Домен WordPress: ${GREEN}${WP_DOMAIN}${NC}"; echo -e " - Домен phpMyAdmin:  ${GREEN}${PMA_DOMAIN}${NC}"; echo -e " - Email для SSL:     ${GREEN}${LETSENCRYPT_EMAIL}${NC}"
echo -e "\n${YELLOW}Выберите действие:${NC}"; echo "1. Новая установка стека"; echo "2. Обновить системные пакеты"
read -p "Введите номер (1 или 2): " ACTION

case $ACTION in
    1)
        echo -e "\n${YELLOW}Шаг 0: Подготовка системы и базовых утилит...${NC}"
        apt-get update; apt-get install -y apt-transport-https lsb-release ca-certificates curl wget gnupg2 software-properties-common unzip jq apache2-utils
        fetch_latest_versions
        echo -e "\n${YELLOW}Настройка данных для входа...${NC}"
        read -s -p "Введите новый пароль root для MariaDB: " DB_ROOT_PASS; echo
        read -s -p "Подтвердите пароль: " DB_ROOT_PASS_CONFIRM; echo
        if [ "$DB_ROOT_PASS" != "$DB_ROOT_PASS_CONFIRM" ] || [ -z "$DB_ROOT_PASS" ]; then echo -e "${RED}Пароли не совпадают или пусты. Прерывание.${NC}"; exit 1; fi
        read -p "Введите имя пользователя для входа в phpMyAdmin: " PMA_AUTH_USER
        read -s -p "Введите пароль для этого пользователя: " PMA_AUTH_PASS; echo
        if [ -z "$PMA_AUTH_USER" ] || [ -z "$PMA_AUTH_PASS" ]; then echo -e "${RED}Данные для phpMyAdmin не могут быть пустыми. Прерывание.${NC}"; exit 1; fi
        DB_USER_PASS=$(openssl rand -base64 16)
        echo -e "\n${YELLOW}Шаг 2: Установка компонентов...${NC}"
        apt-get update; apt-get install -y nginx varnish redis-server mariadb-server ed php${PHP_LATEST}-fpm php${PHP_LATEST}-mysql php${PHP_LATEST}-curl php${PHP_LATEST}-gd php${PHP_LATEST}-intl php${PHP_LATEST}-mbstring php${PHP_LATEST}-xml php${PHP_LATEST}-zip certbot python3-certbot-nginx
        echo -e "\n${YELLOW}Шаг 3: Настройка PHP...${NC}"
        PHP_INI_PATH="/etc/php/${PHP_LATEST}/fpm/php.ini"
        sed -i 's/display_errors = Off/display_errors = On/' "$PHP_INI_PATH"; sed -i 's/log_errors = Off/log_errors = On/' "$PHP_INI_PATH"; sed -i "s|;error_log = .*|error_log = /var/log/php${PHP_LATEST}-fpm.log|" "$PHP_INI_PATH"
        echo -e "\n${YELLOW}Шаг 4: Настройка сервисов...${NC}"
        systemctl enable --now redis-server varnish
        mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${DB_ROOT_PASS}';"
        mysql -u root -p"${DB_ROOT_PASS}" -e "CREATE DATABASE wordpress DEFAULT CHARACTER SET utf8 COLLATE utf8_unicode_ci;"
        mysql -u root -p"${DB_ROOT_PASS}" -e "CREATE USER 'wp_user'@'localhost' IDENTIFIED BY '${DB_USER_PASS}';"
        mysql -u root -p"${DB_ROOT_PASS}" -e "GRANT ALL ON wordpress.* TO 'wp_user'@'localhost';"
        mysql -u root -p"${DB_ROOT_PASS}" -e "FLUSH PRIVILEGES;"
        cat > /etc/varnish/default.vcl << EOF
vcl 4.1; import std; backend default { .host = "127.0.0.1"; .port = "8080"; }
sub vcl_recv { if (req.url ~ "wp-(login|admin|cron)" || req.http.Cookie ~ "wordpress_logged_in" || req.http.Authorization || req.method != "GET" && req.method != "HEAD") { return (pass); } if (req.url ~ "\.(css|js|png|gif|jp(e)?g|svg|woff|woff2)") { unset req.http.Cookie; } return (hash); }
sub vcl_backend_response { if (beresp.http.Set-Cookie) { set beresp.uncacheable = true; return (deliver); } set beresp.ttl = 1h; return (deliver); }
sub vcl_deliver { if (obj.hits > 0) { set resp.http.X-Cache = "HIT"; } else { set resp.http.X-Cache = "MISS"; } return (deliver); }
EOF
        systemctl restart varnish
        echo -e "\n${YELLOW}Шаг 5: Установка WordPress и phpMyAdmin...${NC}"
        mkdir -p /var/www/${WP_DOMAIN} /var/www/${PMA_DOMAIN}; cd /var/www/${WP_DOMAIN}
        wget --progress=bar:force https://wordpress.org/wordpress-${WP_LATEST}.tar.gz; tar -xzf wordpress-${WP_LATEST}.tar.gz --strip-components=1 && rm wordpress-${WP_LATEST}.tar.gz
        cd /var/www/${PMA_DOMAIN}
        wget --progress=bar:force https://files.phpmyadmin.net/phpMyAdmin/${PMA_LATEST}/phpMyAdmin-${PMA_LATEST}-all-languages.tar.gz; tar -xzf phpMyAdmin-${PMA_LATEST}-all-languages.tar.gz --strip-components=1 && rm phpMyAdmin-${PMA_LATEST}-all-languages.tar.gz
        chown -R www-data:www-data /var/www/${WP_DOMAIN} /var/www/${PMA_DOMAIN}
        
        echo -e "\n${YELLOW}Шаг 6: Получение SSL сертификатов (Автономный режим)...${NC}"
        systemctl stop nginx || true # Останавливаем Nginx, игнорируя ошибку, если он уже остановлен
        certbot certonly --standalone -d ${WP_DOMAIN} -d ${PMA_DOMAIN} --non-interactive --agree-tos -m ${LETSENCRYPT_EMAIL}
        
        # --- ИСПРАВЛЕНИЕ: Создаем недостающие файлы конфигурации SSL ---
        echo -e "${BLUE}Создание файлов конфигурации SSL...${NC}"
        mkdir -p /etc/letsencrypt/
        cat > /etc/letsencrypt/options-ssl-nginx.conf << EOF
ssl_session_cache shared:le_nginx_SSL:10m;
ssl_session_timeout 1440m;
ssl_session_tickets off;
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers off;
ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384";
EOF
        if [ ! -f "/etc/letsencrypt/ssl-dhparams.pem" ]; then
            openssl dhparam -out /etc/letsencrypt/ssl-dhparams.pem 2048
        fi

        echo -e "\n${YELLOW}Шаг 7: Настройка WordPress и финальной конфигурации Nginx...${NC}"
        WP_CONFIG_PATH="/var/www/${WP_DOMAIN}/wp-config.php"
        cp /var/www/${WP_DOMAIN}/wp-config-sample.php "$WP_CONFIG_PATH";
        sed -i "s/database_name_here/wordpress/g" "$WP_CONFIG_PATH"; sed -i "s/username_here/wp_user/g" "$WP_CONFIG_PATH"; sed -i "s#password_here#${DB_USER_PASS}#g" "$WP_CONFIG_PATH"
        SALT=$(curl $CURL_OPTIONS https://api.wordpress.org/secret-key/1.1/salt/); printf '%s\n' "g/put your unique phrase here/d" a "$SALT" . w | ed -s "$WP_CONFIG_PATH"
        CONFIG_CODE="\
/**\
 * Настройки для работы за обратным прокси-сервером (Varnish/Nginx).\
 */\
define( 'WP_HOME', 'https://${WP_DOMAIN}' );\
define( 'WP_SITEURL', 'https://${WP_DOMAIN}' );\
\
if ( isset(\\\$_SERVER['HTTP_X_FORWARDED_PROTO']) && \\\$_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https' ) {\
    \\\$_SERVER['HTTPS'] = 'on';\
}\
"
        sed -i "#/\* That's all, stop editing! Happy publishing. \*/#i ${CONFIG_CODE}" "$WP_CONFIG_PATH"
        htpasswd -cb /etc/nginx/.htpasswd-pma "${PMA_AUTH_USER}" "${PMA_AUTH_PASS}"
        
        cat > /etc/nginx/conf.d/main-stack.conf << EOF
server { listen 127.0.0.1:8080; server_name ${WP_DOMAIN}; root /var/www/${WP_DOMAIN}; index index.php; location / { try_files \$uri \$uri/ /index.php?\$args; } location ~ \.php\$ { include fastcgi_params; fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; fastcgi_pass unix:/run/php/php${PHP_LATEST}-fpm.sock; }}
server { listen 80; server_name ${WP_DOMAIN} ${PMA_DOMAIN}; return 301 https://\$host\$request_uri; }
server { listen 443 ssl http2; server_name ${WP_DOMAIN}; ssl_certificate /etc/letsencrypt/live/${WP_DOMAIN}/fullchain.pem; ssl_certificate_key /etc/letsencrypt/live/${WP_DOMAIN}/privkey.pem; include /etc/letsencrypt/options-ssl-nginx.conf; ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; root /var/www/${WP_DOMAIN}; location ~* \.(css|js|jpg|jpeg|gif|png|svg|ico|eot|ttf|woff|woff2)\$ { expires 1M; access_log off; try_files \$uri =404; } location / { proxy_pass http://127.0.0.1:6081; proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr; proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; proxy_set_header X-Forwarded-Proto \$scheme; }}
server { listen 443 ssl http2; server_name ${PMA_DOMAIN}; ssl_certificate /etc/letsencrypt/live/${WP_DOMAIN}/fullchain.pem; ssl_certificate_key /etc/letsencrypt/live/${WP_DOMAIN}/privkey.pem; include /etc/letsencrypt/options-ssl-nginx.conf; ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; root /var/www/${PMA_DOMAIN}; index index.php; location / { auth_basic "Admin Login"; auth_basic_user_file /etc/nginx/.htpasswd-pma; try_files \$uri \$uri/ /index.php?\$args; } location ~ \.php\$ { include fastcgi_params; fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; fastcgi_pass unix:/run/php/php${PHP_LATEST}-fpm.sock; }}
EOF
        
        echo -e "\n${YELLOW}Шаг 8: Финальный запуск сервисов...${NC}"
        usermod -aG www-data nginx
        systemctl restart php${PHP_LATEST}-fpm.service
        systemctl start nginx
        systemctl enable nginx

        echo -e "\n\n${BLUE}=====================================================================${NC}"
        echo -e "${GREEN}                        УСТАНОВКА УСПЕШНО ЗАВЕРШЕНА!${NC}"; echo -e "${BLUE}=====================================================================${NC}"
        echo -e "WordPress:   ${YELLOW}https://${WP_DOMAIN}${NC}"; echo -e "phpMyAdmin:      ${YELLOW}https://${PMA_DOMAIN}${NC}"
        echo -e "\n${RED}СОХРАНИТЕ ЭТИ ДАННЫЕ:${NC}"; echo "--------------------------------------------------"
        echo -e "${YELLOW}Пароль root для MariaDB вы установили самостоятельно.${NC}"; echo -e "Пользователь БД для WP:         ${GREEN}wp_user${NC}"; echo -e "Пароль пользователя БД для WP:  ${GREEN}${DB_USER_PASS}${NC}"
        echo -e "Пользователь Basic Auth (PMA):  ${GREEN}${PMA_AUTH_USER}${NC}"; echo -e "Пароль Basic Auth (PMA):        ${YELLOW}вы установили самостоятельно${NC}"
        echo "--------------------------------------------------"; echo -e "\n${YELLOW}РЕКОМЕНДАЦИИ:${NC}"
        echo -e " - Для использования Redis установите плагин 'Redis Object Cache' в WordPress."; echo -e " - Кэширование Varnish для WordPress уже работает."
        ;;
    2)
        echo -e "\n${YELLOW}Обновление системных пакетов...${NC}"
        apt-get update; apt-get dist-upgrade -y; apt-get autoremove -y
        echo -e "\n${GREEN}Системные пакеты обновлены.${NC}"
        ;;
    *)
        echo -e "${RED}Неверный выбор. Прерывание.${NC}"; exit 1
        ;;
esac