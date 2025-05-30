#!/usr/bin/env python3
# Official Xtream UI Automated Installation Script (Python Version)
# =============================================
# Versión Python del script original

import os
import sys
import subprocess
import argparse
import platform
import re
import random
import string
import socket
import time
import datetime
import shutil
import base64
from itertools import cycle

# Códigos de color ANSI para salida en terminal
class Color:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    CHECK_MARK = '\033[0;32m✓\033[0m'

# Variables globales
XC_VERSION = "22 CK 41"
PANEL_PATH = "/home/xtreamcodes/iptv_xtream_codes"

def spinner(message):
    """Muestra un spinner mientras un proceso está en ejecución"""
    print(f"{message}", end='', flush=True)
    chars = ['|', '/', '-', '\\']
    for _ in range(10):
        for char in chars:
            print(f"\r{message} {char}", end='', flush=True)
            time.sleep(0.1)
    print("\r", end='', flush=True)

def run_command(command, silent=False):
    """Ejecuta un comando de shell y devuelve la salida"""
    try:
        if silent:
            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        else:
            result = subprocess.run(command, shell=True, text=True, check=True)
        return result.stdout if result.stdout else ""
    except subprocess.CalledProcessError as e:
        print(f"{Color.FAIL}Comando fallido: {e}{Color.ENDC}")
        return e.stderr if e.stderr else ""

def is_package_installed(package, os_type):
    """Comprueba si un paquete está instalado"""
    if os_type in ["CentOs", "Fedora", "Centos Stream"]:
        return run_command(f"rpm -q {package} > /dev/null 2>&1", silent=True) == 0
    elif os_type in ["Ubuntu", "debian"]:
        return run_command(f"dpkg -l | grep -q {package}", silent=True) == 0
    return False

def detect_os():
    """Detecta el sistema operativo y su versión"""
    os_name = ""
    os_version = ""
    
    if os.path.exists("/etc/centos-release"):
        if is_package_installed("centos-stream-repos", "CentOs"):
            os_name = "Centos Stream"
        else:
            os_name = "CentOs"
        with open("/etc/centos-release", "r") as f:
            version_line = f.read().strip()
            match = re.search(r'release (\d+)', version_line)
            if match:
                os_version = match.group(1)
    elif os.path.exists("/etc/fedora-release"):
        os_name = "Fedora"
        with open("/etc/fedora-release", "r") as f:
            version_line = f.read().strip()
            match = re.search(r'release (\d+)', version_line)
            if match:
                os_version = match.group(1)
    elif os.path.exists("/etc/lsb-release"):
        with open("/etc/lsb-release", "r") as f:
            for line in f:
                if "DISTRIB_ID" in line:
                    os_name = line.split("=")[1].strip()
                if "DISTRIB_RELEASE" in line:
                    os_version = line.split("=")[1].strip()
    elif os.path.exists("/etc/os-release"):
        with open("/etc/os-release", "r") as f:
            for line in f:
                if line.startswith("ID="):
                    os_name = line.split("=")[1].strip().strip('"')
                if line.startswith("VERSION_ID="):
                    os_version = line.split("=")[1].strip().strip('"')
    else:
        os_name = platform.system()
        os_version = platform.release()
    
    arch = platform.machine()
    return os_name, os_version, arch
def install_packages(packages, os_type, os_version):
    """Instala paquetes según el tipo de sistema operativo"""
    if os_type in ["CentOs", "Fedora", "Centos Stream"]:
        installer = "yum -y -q install"
    elif os_type in ["Ubuntu", "debian"]:
        installer = "apt-get -yqq install"
    
    package_list = " ".join(packages)
    run_command(f"{installer} {package_list}")

def get_ip_address():
    """Obtiene la dirección IP del servidor"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # No es necesario que sea alcanzable
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def get_network_interface():
    """Obtiene la interfaz de red principal"""
    interfaces = os.listdir('/sys/class/net/')
    for interface in interfaces:
        if interface != 'lo':  # Excluir loopback
            return interface
    return 'eth0'  # Interfaz por defecto

def generate_random_string(length):
    """Genera una cadena aleatoria de longitud fija"""
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for _ in range(length))

def encrypt_config(host, username, password, database, server_id, port):
    """Encripta el archivo de configuración usando el mismo método que en el script original"""
    config_data = f'{{"host":"{host}","db_user":"{username}","db_pass":"{password}","db_name":"{database}","server_id":"{server_id}", "db_port":"{port}"}}'
    key = "5709650b0d7806074842c6de575025b1"
    
    # Implementa el método de encriptación del script original
    encrypted = ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(config_data, cycle(key)))
    encoded = base64.b64encode(encrypted.encode()).decode('utf-8')
    
    with open(f'{PANEL_PATH}/config', 'w') as f:
        f.write(encoded)

def modify_nginx_conf(admin_port, nginx_vars):
    """Modifica el archivo nginx.conf"""
    nginx_path = f"{PANEL_PATH}/nginx/conf/nginx.conf"
    
    try:
        with open(nginx_path, "r") as f:
            nginx_data = f.read()
        
        # Divide en la última llave de cierre e inserta el bloque del servidor admin
        parts = nginx_data.rsplit("}", 1)
        admin_block = f"""    server {{
        listen {admin_port};
        index index.php index.html index.htm;
        root {PANEL_PATH}/admin/;

        location ~ \\.php$ {{
            limit_req zone=one burst=8;
            try_files {nginx_vars['uri']} =404;
            fastcgi_index index.php;
            fastcgi_pass php;
            include fastcgi_params;
            fastcgi_buffering on;
            fastcgi_buffers 96 32k;
            fastcgi_buffer_size 32k;
            fastcgi_max_temp_file_size 0;
            fastcgi_keep_conn on;
            fastcgi_param SCRIPT_FILENAME {nginx_vars['document_root']};
            fastcgi_param SCRIPT_NAME {nginx_vars['script_name']};
        }}
    }}
}}"""
        
        new_nginx_data = parts[0] + admin_block
        
        with open(nginx_path, "w") as f:
            f.write(new_nginx_data)
            
        # Actualiza el archivo hosts
        hosts_content = ""
        with open("/etc/hosts", "r") as f:
            hosts_content = f.read()
        
        if "api.xtream-codes.com" not in hosts_content:
            run_command('echo "127.0.0.1    api.xtream-codes.com" >> /etc/hosts')
        if "downloads.xtream-codes.com" not in hosts_content:
            run_command('echo "127.0.0.1    downloads.xtream-codes.com" >> /etc/hosts')
        if "xtream-codes.com" not in hosts_content and " xtream-codes.com" not in hosts_content:
            run_command('echo "127.0.0.1    xtream-codes.com" >> /etc/hosts')
        
    except Exception as e:
        print(f"{Color.FAIL}Error modificando nginx.conf: {e}{Color.ENDC}")

def setup_mysql(mysql_password, db_password, ip_addr, ssh_port, os_version, network_interface):
    """Configura MySQL para Xtream UI"""
    # Crear base de datos
    run_command(f'mysql -u root -p{mysql_password} -e "DROP DATABASE IF EXISTS xtream_iptvpro; CREATE DATABASE IF NOT EXISTS xtream_iptvpro;"')
    
    # Importar esquema de base de datos
    run_command(f"mysql -u root -p{mysql_password} xtream_iptvpro < {PANEL_PATH}/database.sql")
    
    # Configurar servidor de streaming
    run_command(f'mysql -u root -p{mysql_password} -e "USE xtream_iptvpro; REPLACE INTO streaming_servers (id, server_name, domain_name, server_ip, vpn_ip, ssh_password, ssh_port, diff_time_main, http_broadcast_port, total_clients, system_os, network_interface, latency, status, enable_geoip, geoip_countries, last_check_ago, can_delete, server_hardware, total_services, persistent_connections, rtmp_port, geoip_type, isp_names, isp_type, enable_isp, boost_fpm, http_ports_add, network_guaranteed_speed, https_broadcast_port, https_ports_add, whitelist_ips, watchdog_data, timeshift_only) VALUES (1, \'Main Server\', \'\', \'{ip_addr}\', \'\', NULL, \'{ssh_port}\', 0, 2082, 1000, \'{os_version}\', \'{network_interface}\', 0, 1, 0, \'\', 0, 0, \'{{}}\', 3, 0, 2086, \'low_priority\', \'\', \'low_priority\', 0, 0, \'\', 1000, 2083, \'\', \'[\\\"127.0.0.1\\\",\\\"\\\"]\', \'{{}}\', 0);"')
    
    # Conceder privilegios al usuario
    run_command(f'mysql -u root -p{mysql_password} -e "GRANT ALL PRIVILEGES ON *.* TO \'user_iptvpro\'@\'%\' IDENTIFIED BY \'{db_password}\' WITH GRANT OPTION; FLUSH PRIVILEGES;"')

def disable_file(filename):
    """Deshabilita un archivo cambiando su nombre"""
    try:
        os.rename(filename, f"{filename}_disabled_by_xtream_ui")
    except Exception:
        pass
def create_full_nginx_conf(client_port):
    """Crea un archivo de configuración completo para Nginx"""
    nginx_conf = f"""user  xtreamcodes;
worker_processes  auto;

worker_rlimit_nofile 300000;
events {{
    worker_connections  16000;
    use epoll;
    accept_mutex on;
    multi_accept on;
}}
thread_pool pool_xtream threads=32 max_queue=0;
http {{

    include       mime.types;
    default_type  application/octet-stream;

    sendfile           on;
    tcp_nopush         on;
    tcp_nodelay        on;
    reset_timedout_connection on;
    gzip off;
    fastcgi_read_timeout 200;
    access_log off;
    keepalive_timeout 10;
    include balance.conf;
    send_timeout 20m;	
    sendfile_max_chunk 512k;
    lingering_close off;
    aio threads=pool_xtream;
    client_body_timeout 13s;
    client_header_timeout 13s;
    client_max_body_size 3m;

    limit_req_zone $binary_remote_addr zone=one:30m rate=20r/s;
    server {{
        listen {client_port};listen 25463 ssl;ssl_certificate server.crt;ssl_certificate_key server.key; ssl_protocols SSLv3 TLSv1.1 TLSv1.2;
        index index.php index.html index.htm;
        root {PANEL_PATH}/wwwdir/;
        server_tokens off;
        chunked_transfer_encoding off;

        if ( $request_method !~ ^(GET|POST)$ ) {{
            return 200;
        }}

        rewrite_log on;
        rewrite ^/live/(.*)/(.*)/(.*)\.(.*) /streaming/clients_live.php?username=$1&password=$2&stream=$3&extension=$4 break;
        rewrite ^/movie/(.*)/(.*)/(.*) /streaming/clients_movie.php?username=$1&password=$2&stream=$3&type=movie break;
        rewrite ^/series/(.*)/(.*)/(.*) /streaming/clients_movie.php?username=$1&password=$2&stream=$3&type=series break;
        rewrite ^/(.*)/(.*)/(.*).ch$ /streaming/clients_live.php?username=$1&password=$2&stream=$3&extension=ts break;
        rewrite ^/(.*).ch$ /streaming/clients_live.php?extension=ts&stream=$1&qs=$query_string break;
        rewrite ^/ch(.*).m3u8$ /streaming/clients_live.php?extension=m3u8&stream=$1&qs=$query_string break;
        rewrite ^/hls/(.*)/(.*)/(.*)/(.*)/(.*) /streaming/clients_live.php?extension=m3u8&username=$1&password=$2&stream=$3&type=hls&segment=$5&token=$4 break;
        rewrite ^/hlsr/(.*)/(.*)/(.*)/(.*)/(.*)/(.*) /streaming/clients_live.php?token=$1&username=$2&password=$3&segment=$6&stream=$4&key_seg=$5 break;
        rewrite ^/timeshift/(.*)/(.*)/(.*)/(.*)/(.*)\.(.*) /streaming/timeshift.php?username=$1&password=$2&stream=$5&extension=$6&duration=$3&start=$4 break;
        rewrite ^/timeshifts/(.*)/(.*)/(.*)/(.*)/(.*)\.(.*) /streaming/timeshift.php?username=$1&password=$2&stream=$4&extension=$6&duration=$3&start=$5 break;
        
        rewrite ^/(.*)/(.*)/(\d+) /streaming/clients_live.php?username=$1&password=$2&stream=$3&extension=ts break;
        #add pvr support
        rewrite ^/server/load.php$ /portal.php break;
        
        location /stalker_portal/c {{
            alias {PANEL_PATH}/wwwdir/c;
        }}
        
        #FFmpeg Report Progress
        location = /progress.php {{
            allow 127.0.0.1;
            deny all;
            fastcgi_pass php;
            include fastcgi_params;
            fastcgi_ignore_client_abort on;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_param SCRIPT_NAME $fastcgi_script_name;
        }}


        location ~ \\.php$ {{
            limit_req zone=one burst=8;
            try_files $uri =404;
            fastcgi_index index.php;
            fastcgi_pass php;
            include fastcgi_params;
            fastcgi_buffering on;
            fastcgi_buffers 96 32k;
            fastcgi_buffer_size 32k;
            fastcgi_max_temp_file_size 0;
            fastcgi_keep_conn on;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_param SCRIPT_NAME $fastcgi_script_name;
        }}
    }}
    #ISP CONFIGURATION

    server {{
         listen 8805;
         root {PANEL_PATH}/isp/;
         location / {{
                      allow 127.0.0.1;
                      deny all;
         }}
         location ~ \\.php$ {{
                             limit_req zone=one burst=8;
                             try_files $uri =404;
                             fastcgi_index index.php;
                             fastcgi_pass php;
                             include fastcgi_params;
                             fastcgi_buffering on;
                             fastcgi_buffers 96 32k;
                             fastcgi_buffer_size 32k;
                             fastcgi_max_temp_file_size 0;
                             fastcgi_keep_conn on;
                             fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
                             fastcgi_param SCRIPT_NAME $fastcgi_script_name;
         }}
    }}
}}
"""
    nginx_path = f"{PANEL_PATH}/nginx/conf/nginx.conf"
    with open(nginx_path, "w") as f:
        f.write(nginx_conf)

def create_mysql_config():
    """Crea una configuración para MySQL"""
    mysql_config = """# Xtream Codes

[client]
port              = 3306

[mysqld_safe]
nice              = 0

[mysqld]
user              = mysql
port              = 7999
basedir           = /usr
datadir           = /var/lib/mysql
tmpdir            = /tmp
lc-messages-dir   = /usr/share/mysql
skip-external-locking
skip-name-resolve=1

bind-address              = *
key_buffer_size = 128M

myisam_sort_buffer_size = 4M
max_allowed_packet        = 64M
myisam-recover-options = BACKUP
max_length_for_sort_data = 8192
query_cache_limit         = 4M
query_cache_size          = 256M


expire_logs_days          = 10
max_binlog_size           = 100M

max_connections  = 20000
back_log = 4096
open_files_limit = 20240
innodb_open_files = 20240
max_connect_errors = 3072
table_open_cache = 4096
table_definition_cache = 4096


tmp_table_size = 1G
max_heap_table_size = 1G

innodb_buffer_pool_size = 10G
innodb_buffer_pool_instances = 10
innodb_read_io_threads = 64
innodb_write_io_threads = 64
innodb_thread_concurrency = 0
innodb_flush_log_at_trx_commit = 0
innodb_flush_method = O_DIRECT
performance_schema = 0
innodb-file-per-table = 1
innodb_io_capacity=20000
innodb_table_locks = 0
innodb_lock_wait_timeout = 0
innodb_deadlock_detect = 0


sql-mode="NO_ENGINE_SUBSTITUTION"

[mysqldump]
quick
quote-names
max_allowed_packet        = 16M

[mysql]

[isamchk]
key_buffer_size              = 16M
"""
    return mysql_config

def update_xtream_codes(mysql_password, db_password, admin_port, client_port, timezone):
    """Actualiza la configuración de Xtream Codes"""
    # Actualizar puertos y contraseñas en la base de datos
    run_command(f'mysql -u root -p{mysql_password} xtream_iptvpro -e "UPDATE streaming_servers SET http_broadcast_port = \'{client_port}\' WHERE streaming_servers.id = 1;"')
    
    # Actualizar clave en vivo
    zzz = generate_random_string(20)
    run_command(f'mysql -u root -p{mysql_password} xtream_iptvpro -e "UPDATE settings SET live_streaming_pass = \'{zzz}\' WHERE settings.id = 1;"')
    
    # Actualizar ID único
    eee = generate_random_string(10)
    run_command(f'mysql -u root -p{mysql_password} xtream_iptvpro -e "UPDATE settings SET unique_id = \'{eee}\' WHERE settings.id = 1;"')
    
    # Actualizar cifrado de balanceo de carga
    rrr = generate_random_string(20)
    run_command(f'mysql -u root -p{mysql_password} xtream_iptvpro -e "UPDATE settings SET crypt_load_balancing = \'{rrr}\' WHERE settings.id = 1;"')
    
    # Actualizar zona horaria en php.ini
    run_command(f'sed -i "s|;date.timezone =|date.timezone = {timezone}|g" {PANEL_PATH}/php/lib/php.ini')

def setup_system_files():
    """Configura archivos y permisos del sistema"""
    # Configurar sudoers
    if not os.path.exists("/etc/sudoers.bak"):
        shutil.copy("/etc/sudoers", "/etc/sudoers.bak")
    
    with open("/etc/sudoers", "r") as f:
        sudoers_content = f.read()
    
    if "xtreamcodes ALL = (root) NOPASSWD: /sbin/iptables" not in sudoers_content:
        with open("/etc/sudoers", "a") as f:
            f.write("\nxtreamcodes ALL = (root) NOPASSWD: /sbin/iptables, /usr/bin/chattr, /usr/bin/python3, /usr/bin/python\n")
    
    # Crear enlace simbólico para ffmpeg
    if not os.path.exists("/usr/bin/ffmpeg"):
        os.symlink(f"{PANEL_PATH}/bin/ffmpeg", "/usr/bin/ffmpeg")
    
    # Configurar fstab para streams y tmp
    with open("/etc/fstab", "r") as f:
        fstab_content = f.read()
    
    with open("/etc/fstab", "a") as f:
        if "tmpfs /home/xtreamcodes/iptv_xtream_codes/streams" not in fstab_content:
            f.write("tmpfs /home/xtreamcodes/iptv_xtream_codes/streams tmpfs defaults,noatime,nosuid,nodev,noexec,mode=1777,size=90% 0 0\n")
        if "tmpfs /home/xtreamcodes/iptv_xtream_codes/tmp" not in fstab_content:
            f.write("tmpfs /home/xtreamcodes/iptv_xtream_codes/tmp tmpfs defaults,noatime,nosuid,nodev,noexec,mode=1777,size=2G 0 0\n")
    
    # Configurar crontab para inicio automático
    with open("/etc/crontab", "a") as f:
        f.write("@reboot root sudo /home/xtreamcodes/iptv_xtream_codes/start_services.sh\n")
    
    # Establecer permisos
    run_command(f"chmod -R 0777 {PANEL_PATH}")
    run_command(f"chown xtreamcodes:xtreamcodes -R {PANEL_PATH}")
    run_command(f"chmod +x {PANEL_PATH}/start_services.sh")
    run_command(f"chmod +x {PANEL_PATH}/permissions.sh")
    run_command(f"chmod -R 0777 {PANEL_PATH}/crons")

def download_and_setup_additional_files():
    """Descarga y configura archivos adicionales"""
    # Descargar archivos balancer
    run_command(f"wget https://raw.githubusercontent.com/Servextex/xtream-ui-ubuntu/main/balancer.php -O {PANEL_PATH}/crons/balancer.php")
    run_command(f"wget https://raw.githubusercontent.com/Servextex/xtream-ui-ubuntu/main/balancer.sh -O {PANEL_PATH}/pytools/balancer.sh")
    run_command(f"chmod +x {PANEL_PATH}/pytools/balancer.sh")
    
    # Descargar script de inicio de servicios
    run_command(f"wget https://github.com/Servextex/xtream-ui-ubuntu/raw/main/start_services.sh -O {PANEL_PATH}/start_services.sh")
    run_command(f"chmod +x {PANEL_PATH}/start_services.sh")
    
    # Actualizar GeoLite2.mmdb
    run_command(f"chattr -i {PANEL_PATH}/GeoLite2.mmdb")
    run_command(f"wget -O {PANEL_PATH}/GeoLite2.mmdb https://bitbucket.org/emre1393/xtreamui_mirror/downloads/GeoLite2.mmdb")
    run_command(f"chattr +i {PANEL_PATH}/GeoLite2.mmdb")
    
    # Obtener versión de geolite
    geolite_version = run_command("wget -qO- https://bitbucket.org/emre1393/xtreamui_mirror/downloads/Geolite2_status.json | jq -r \".version\"")
    run_command(f'mysql -u root -p$PASSMYSQL xtream_iptvpro -e "UPDATE admin_settings SET value = \'{geolite_version}\' WHERE admin_settings.type = \'geolite2_version\';"')
def rebuild_nginx(os_type):
    """Reconstruye Nginx con los módulos necesarios"""
    # Instalar dependencias
    if os_type in ["Ubuntu", "debian"]:
        run_command("apt-get install -y libaio-dev libmaxminddb-dev")
    else:
        run_command("yum install -y libaio-devel libmaxminddb-devel")
    
    # Descargar y compilar OpenSSL
    run_command("cd /tmp/ && wget https://github.com/openssl/openssl/archive/OpenSSL_1_1_1h.tar.gz")
    run_command("cd /tmp/ && tar -xzvf OpenSSL_1_1_1h.tar.gz")
    
    # Descargar y compilar Nginx
    run_command("cd /root && wget http://nginx.org/download/nginx-1.19.5.tar.gz")
    run_command("cd /root && tar -xzvf nginx-1.19.5.tar.gz")
    run_command("cd /root && git clone https://github.com/leev/ngx_http_geoip2_module.git")
    
    # Configurar y compilar Nginx
    run_command(f"""cd /root/nginx-1.19.5 && ./configure --prefix={PANEL_PATH}/nginx/ --http-client-body-temp-path={PANEL_PATH}/tmp/client_temp --http-proxy-temp-path={PANEL_PATH}/tmp/proxy_temp --http-fastcgi-temp-path={PANEL_PATH}/tmp/fastcgi_temp --lock-path={PANEL_PATH}/tmp/nginx.lock --http-uwsgi-temp-path={PANEL_PATH}/tmp/uwsgi_temp --http-scgi-temp-path={PANEL_PATH}/tmp/scgi_temp --conf-path={PANEL_PATH}/nginx/conf/nginx.conf --error-log-path={PANEL_PATH}/logs/error.log --http-log-path={PANEL_PATH}/logs/access.log --pid-path={PANEL_PATH}/nginx/nginx.pid --with-http_ssl_module --with-http_realip_module --with-http_addition_module --with-http_sub_module --with-http_dav_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_v2_module --with-pcre --with-http_random_index_module --with-http_secure_link_module --with-http_stub_status_module --with-http_auth_request_module --with-threads --with-mail --with-mail_ssl_module --with-file-aio --with-cpu-opt=generic --add-module=/root/ngx_http_geoip2_module --with-openssl=/tmp/openssl-OpenSSL_1_1_1h""")
    
    run_command("cd /root/nginx-1.19.5 && make")
    run_command(f"rm -f {PANEL_PATH}/nginx/sbin/nginx")
    run_command(f"cp /root/nginx-1.19.5/objs/nginx {PANEL_PATH}/nginx/sbin/")
    run_command(f"chmod +x {PANEL_PATH}/nginx/sbin/nginx")
    
    # Reconstruir Nginx RTMP
    run_command("cd /tmp/ && rm -rf openssl-OpenSSL_1_1_1h && tar -xzvf OpenSSL_1_1_1h.tar.gz")
    run_command("cd /root && rm -rf nginx-1.19.5 ngx_http_geoip2_module")
    run_command("cd /root && tar -xzvf nginx-1.19.5.tar.gz")
    run_command("cd /root && git clone https://github.com/leev/ngx_http_geoip2_module.git")
    run_command("cd /root && wget https://github.com/arut/nginx-rtmp-module/archive/v1.2.1.zip")
    run_command("cd /root && unzip v1.2.1.zip")
    
    run_command(f"""cd /root/nginx-1.19.5 && ./configure --prefix={PANEL_PATH}/nginx_rtmp/ --lock-path={PANEL_PATH}/nginx_rtmp/nginx_rtmp.lock --conf-path={PANEL_PATH}/nginx_rtmp/conf/nginx.conf --error-log-path={PANEL_PATH}/logs/rtmp_error.log --http-log-path={PANEL_PATH}/logs/rtmp_access.log --pid-path={PANEL_PATH}/nginx_rtmp/nginx.pid --add-module=/root/nginx-rtmp-module-1.2.1 --with-pcre --without-http_rewrite_module --with-file-aio --with-cpu-opt=generic --with-openssl=/tmp/openssl-OpenSSL_1_1_1h --add-module=/root/ngx_http_geoip2_module --with-http_ssl_module --with-cc-opt="-Wimplicit-fallthrough=0" """)
    
    run_command("cd /root/nginx-1.19.5 && make")
    run_command("cd /root/nginx-1.19.5/objs && mv nginx nginx_rtmp")
    run_command(f"rm -f {PANEL_PATH}/nginx_rtmp/sbin/nginx_rtmp")
    run_command(f"cp /root/nginx-1.19.5/objs/nginx_rtmp {PANEL_PATH}/nginx_rtmp/sbin/")
    run_command(f"chmod +x {PANEL_PATH}/nginx_rtmp/sbin/nginx_rtmp")
    
    # Limpiar archivos temporales
    run_command("cd /root && rm -rf /tmp/OpenSSL_1_1_1h /tmp/openssl-OpenSSL_1_1_1h nginx-1.19.5 v1.2.1.zip nginx-rtmp-module-1.2.1 ngx_http_geoip2_module nginx-1.19.5.tar.gz")

def print_completion_info(admin_user, admin_pass, admin_port, mysql_pass, db_pass, ip_addr, domain=None, ssl_enabled=False):
    """Imprime la información de instalación completada"""
    protocol = "https" if ssl_enabled else "http"
    server = domain if domain else ip_addr
    
    info = f"""
─────────────────  Guardado en: /root/Xtreaminfo.txt  ─────────────────
│ ACCESO AL PANEL: {protocol}://{server}:{admin_port}
│ USUARIO: {admin_user}
│ CONTRASEÑA: {admin_pass}
│ CONTRASEÑA MYSQL root: {mysql_pass}
│ CONTRASEÑA MYSQL user_iptvpro: {db_pass}
│ DOMINIO CONFIGURADO: {domain if domain else 'No configurado'}
│ SSL HABILITADO: {'Sí' if ssl_enabled else 'No'}
────────────────────────────────────────────────────────────────────
"""
    print(info)
    
    # Guardar la información en un archivo
    with open("/root/Xtreaminfo.txt", "w") as f:
        f.write(f"""
───────────────────────────  INFO  ─────────────────────────────────
│
│ ACCESO AL PANEL: {protocol}://{server}:{admin_port}
│ 
│ USUARIO: {admin_user}
│
│ CONTRASEÑA: {admin_pass}
│ 
│ CONTRASEÑA MYSQL root: {mysql_pass}
│
│ CONTRASEÑA MYSQL user_iptvpro: {db_pass}
│ 
│ DOMINIO CONFIGURADO: {domain if domain else 'No configurado'}
│
│ SSL HABILITADO: {'Sí' if ssl_enabled else 'No'}
│ 
────────────────────────────────────────────────────────────────────
""")

def main():
    """Función principal que ejecuta el instalador"""
    # Configurar el analizador de argumentos
    parser = argparse.ArgumentParser(description="Instalador automatizado de Xtream UI")
    parser.add_argument("-t", "--timezone", help="Zona horaria")
    parser.add_argument("-a", "--admin", help="Usuario administrador")
    parser.add_argument("-p", "--password", help="Contraseña de administrador")
    parser.add_argument("-o", "--admin-port", help="Puerto de acceso de administrador")
    parser.add_argument("-c", "--client-port", help="Puerto de acceso de cliente")
    parser.add_argument("-r", "--apache-port", help="Puerto de acceso de Apache")
    parser.add_argument("-e", "--email", help="Dirección de correo electrónico")
    parser.add_argument("-m", "--mysql-password", help="Contraseña de MySQL")
    parser.add_argument("-s", "--silent", action="store_true", help="Instalación silenciosa")
    parser.add_argument("-d", "--domain", help="Dominio para configurar (opcional)")
    parser.add_argument("--ssl", action="store_true", help="Instalar certificado SSL para el dominio")
    
    args = parser.parse_args()
    
    # Limpiar pantalla
    os.system('clear')
    
    # Mostrar mensaje de bienvenida
    print("")
    print("#############################################################")
    print(f"#  Bienvenido al Instalador Oficial de Xtream UI {XC_VERSION}  #")
    print("#############################################################")
    print("\nComprobando que los requisitos mínimos son correctos")
    
    # Detectar sistema operativo
    os_type, os_version, arch = detect_os()
    print(f"Sistema operativo: {os_type} {os_version} {arch}")
    
    # Comprobar si el sistema operativo es compatible
    supported = False
    if os_type == "Ubuntu" and os_version in ["18.04", "20.04", "22.04"] and arch == "x86_64":
        supported = True
    elif os_type == "CentOs" and os_version in ["7", "8"] and arch == "x86_64":
        supported = True
    elif os_type == "Fedora" and int(os_version) >= 34 and int(os_version) <= 36 and arch == "x86_64":
        supported = True
    elif os_type == "debian" and os_version in ["10", "11"] and arch == "x86_64":
        supported = True
    
    if not supported:
        print(f"{Color.FAIL}Error: Sistema operativo no compatible {os_type} {os_version} {arch}{Color.ENDC}")
        print("Este instalador solo es compatible con:")
        print("- Ubuntu 18.04/20.04/22.04 (64-bit)")
        print("- CentOS 7/8 (64-bit)")
        print("- Fedora 34/35/36 (64-bit)")
        print("- Debian 10/11 (64-bit)")
        sys.exit(1)
    
    # Configurar instalador de paquetes según el sistema operativo
    if os_type in ["CentOs", "Fedora", "Centos Stream"]:
        package_installer = "yum -y -q install"
        package_remover = "yum -y -q remove"
        package_updater = "yum -y -q update"
        mysql_cnf = "/etc/my.cnf"
    elif os_type in ["Ubuntu", "debian"]:
        package_installer = "apt-get -yqq install"
        package_remover = "apt-get -yqq purge"
        mysql_cnf = "/etc/mysql/mariadb.cnf"
    
    # Instalar paquetes requeridos
    print("\n-- Instalando paquetes requeridos")
    if os_type in ["Ubuntu", "debian"]:
        run_command("apt-get update -y")
        run_command(f"{package_installer} wget curl net-tools")
    else:
        run_command(f"{package_installer} wget curl net-tools")
    
    # Obtener dirección IP
    ip_addr = get_ip_address()
    network_interface = get_network_interface()
    ssh_port = run_command("grep Port /etc/ssh/sshd_config | grep -v '^#' | awk '{print $2}'").strip() or "22"
    
    # Generar cadenas aleatorias para contraseñas
    zzz = generate_random_string(20)
    eee = generate_random_string(10)
    rrr = generate_random_string(20)
    xpass = generate_random_string(20)
    
    # Obtener valores de los argumentos o solicitar entrada
    timezone = args.timezone
    if not timezone:
        # Instalar tzdata si es necesario
        run_command(f"{package_installer} tzdata")
        # Listar zonas horarias disponibles
        print("\nZonas horarias disponibles:")
        zones = run_command("timedatectl list-timezones").strip().split("\n")
        for i, zone in enumerate(zones[:10]):
            print(f"{i+1}. {zone}")
        print("...")
        
        timezone = input("Ingrese su zona horaria (ej. America/New_York): ")
    
    # Configurar zona horaria
    run_command(f"timedatectl set-timezone {timezone}")
    
    # Usuario administrador
    admin_user = args.admin
    if not admin_user:
        admin_user = input("Ingrese su usuario de administrador deseado: ")
    
    # Contraseña de administrador
    admin_pass = args.password
    if not admin_pass:
        admin_pass = input("Ingrese su contraseña de administrador deseada: ")
    
    # Puerto de administrador
    admin_port = args.admin_port
    if not admin_port:
        admin_port = input("Ingrese su puerto de acceso de administrador deseado: ")
    
    # Puerto de cliente
    client_port = args.client_port
    if not client_port:
        client_port = input("Ingrese su puerto de acceso de cliente deseado: ")
    
    # Puerto de Apache
    apache_port = args.apache_port
    if not apache_port:
        apache_port = input("Ingrese su puerto de acceso de Apache deseado: ")
    
    # Correo electrónico
    email = args.email
    if not email:
        email = input("Ingrese su dirección de correo electrónico: ")
    
    # Contraseña de MySQL
    mysql_pass = args.mysql_password
    if not mysql_pass:
        mysql_pass = input("Ingrese su contraseña de MySQL deseada: ")
        
    # Dominio (opcional)
    domain = args.domain
    if not domain and not args.silent:
        domain_opt = input("¿Desea configurar un dominio? (y/n): ")
        if domain_opt.lower() == "y":
            domain = input("Ingrese su dominio (ej. ejemplo.com): ")

    # SSL (opcional, solo si hay dominio)
    ssl_enabled = args.ssl
    if domain and not ssl_enabled and not args.silent:
        ssl_opt = input("¿Desea configurar SSL para su dominio? (y/n): ")
        ssl_enabled = ssl_opt.lower() == "y"
    
    # Preguntar por confirmación
    silent = args.silent
    if not silent:
        protocol = "https" if domain and ssl_enabled else "http"
        server = domain if domain else ip_addr
        confirm = input(f"\n¿Está seguro de que desea instalar Xtream UI {XC_VERSION} en {protocol}://{server}:{admin_port}? (y/n): ")
        if confirm.lower() != "y":
            print("Instalación cancelada")
            sys.exit(0)
    
    # Crear archivo de registro
    logfile = datetime.datetime.now().strftime("%Y-%m-%d_%H.%M.%S_xtream_ui_install.log")
    print(f"Instalando Xtream UI {XC_VERSION} en http://{ip_addr}:{admin_port}")
    print(f"en el servidor: {os_type} {os_version} {arch}")
    
    # Instalar dependencias
    print("[+] Instalando dependencias...")
    run_command("wget -qO- https://raw.githubusercontent.com/Servextex/xtream-ui-ubuntu/main/ubuntu/depbuild.sh | bash")
    
    # Instalar daemonize
    run_command(f"{package_installer} daemonize")
    
    # Configurar MySQL
    run_command(f'mysql -u root -e "ALTER USER \'root\'@\'localhost\' IDENTIFIED BY \'{mysql_pass}\'; flush privileges;"')
    print(f"{Color.CHECK_MARK} Instalación de paquetes completada")
    
    # Crear usuario xtreamcodes
    print("[+] Instalando XtreamCodes...")
    if os_type in ["Ubuntu", "debian"]:
        run_command("adduser --system --shell /bin/false --group --disabled-login xtreamcodes")
    else:
        run_command("adduser --system --shell /bin/false xtreamcodes")
        run_command("mkdir -p /home/xtreamcodes")
    
    # Descargar y extraer Xtream UI
    os_name_file = os_type.replace(" ", ".")
    run_command(f"wget -q -O /tmp/xtreamcodes.tar.gz https://github.com/Servextex/xtream-ui-ubuntu/releases/download/start/main_xui_{os_name_file}_{os_version}.tar.gz")
    run_command(f"tar -xf /tmp/xtreamcodes.tar.gz -C /home/xtreamcodes/")
    run_command("rm -r /tmp/xtreamcodes.tar.gz")
    
    # Guardar configuración de MySQL original
    run_command(f"mv {mysql_cnf} {mysql_cnf}.xc")
    
    # Crear nueva configuración de MySQL
    mysql_config = create_mysql_config()
    
    # Codificar y guardar configuración en base64
    mysql_config_b64 = base64.b64encode(mysql_config.encode()).decode()
    run_command(f"echo {mysql_config_b64} | base64 --decode > {mysql_cnf}")
    
    # Reiniciar MariaDB
    run_command("systemctl restart mariadb")
    print(f"{Color.CHECK_MARK} Instalación de XtreamCodes completada")
    
    # Configurar MySQL y Nginx
    print("[+] Configurando MySQL y Nginx...")
    
    # Crear y configurar la base de datos
    setup_mysql(mysql_pass, xpass, ip_addr, ssh_port, f"{os_type} {os_version}", network_interface)
    
    # Encriptar archivo de configuración
    encrypt_config("127.0.0.1", "user_iptvpro", xpass, "xtream_iptvpro", 1, 7999)
    
    # Variables para Nginx
    nginx_vars = {
        "uri": "$uri",
        "document_root": "$document_root$fastcgi_script_name",
        "script_name": "$fastcgi_script_name",
        "host_port": "$host:$server_port$request_uri"
    }
    
    # Modificar configuración de Nginx
    modify_nginx_conf(admin_port, nginx_vars)
    
    # Descargar y aplicar SQL de instalación
    run_command("wget -qO install.sql https://github.com/Servextex/xtream-ui-ubuntu/raw/main/install.sql")
    run_command(f"sed -i \"s|adminn|{admin_user}|g\" install.sql")
    run_command(f"sed -i \"s|kkkk|{generate_random_string(10)}|g\" install.sql")
    run_command(f"sed -i \"s|EMAIL|{email}|g\" install.sql")
    run_command(f"mysql -u root -p{mysql_pass} xtream_iptvpro < install.sql")
    run_command("rm -f install.sql")
    print(f"{Color.CHECK_MARK} Configuración de MySQL y Nginx completada")
    
    # Configurar crons y autorizaciones
    print("[+] Configurando Crons y Autorizaciones...")
    run_command(f"rm -r {PANEL_PATH}/database.sql")
    
    # Configurar sistema
    setup_system_files()
    
    # Crear configuración de Nginx con o sin dominio/SSL
    if domain:
        setup_nginx_with_domain(admin_port, client_port, domain, ssl_enabled)
        if ssl_enabled:
            install_ssl(domain, email, os_type)
    else:
        create_full_nginx_conf(client_port)
    
    # Actualizar configuración de Xtream Codes
    update_xtream_codes(mysql_pass, xpass, admin_port, client_port, timezone)
    
    # Instalar acceso web de administrador
    print("[+] Instalando acceso web de administrador...")
    
    # Descargar e instalar actualización
    run_command("wget -q -O /tmp/update.zip http://xcodes.mine.nu/XCodes/update.zip")
    run_command("unzip -o /tmp/update.zip -d /tmp/update/")
    run_command(f"chattr -i {PANEL_PATH}/GeoLite2.mmdb")
    run_command(f"rm -rf /tmp/update/XtreamUI-main/php")
    run_command(f"rm -rf /tmp/update/XtreamUI-main/GeoLite2.mmdb")
    run_command(f"cp -rf /tmp/update/XtreamUI-main/* {PANEL_PATH}/")
    run_command("rm -rf /tmp/update/XtreamUI-main")
    run_command("rm /tmp/update.zip")
    run_command("rm -rf /tmp/update")
    
    # Actualizar versión del panel
    run_command(f'mysql -u root -p{mysql_pass} xtream_iptvpro -e "UPDATE admin_settings SET value = \'Servextexv1\' WHERE admin_settings.type = \'panel_version\';"')
    
    # Descargar y configurar archivos adicionales
    download_and_setup_additional_files()
    
    # Reconstruir Nginx
    print("Reconstruyendo Nginx, esta operación puede llevar tiempo...")
    rebuild_nginx(os_type)
    
    # Iniciar servicios
    run_command(f"{PANEL_PATH}/start_services.sh")
    
    # Mostrar información de finalización
    print(f"{Color.CHECK_MARK} Configuración de inicio automático completada")
    print(" ")
    print(" ┌────────────────────────────────────────────┐ ")
    print(" │[R]        XtreamCodes está listo...       │ ")
    print(" └────────────────────────────────────────────┘ ")
    
    # Imprimir información de instalación
    print_completion_info(admin_user, admin_pass, admin_port, mysql_pass, xpass, ip_addr, domain, ssl_enabled)

if __name__ == "__main__":
    main()
def install_ssl(domain, email, os_type):
    """Instala certificado SSL usando Certbot para el dominio especificado"""
    print(f"[+] Instalando certificado SSL para {domain}...")
    
    # Instalar Certbot según el sistema operativo
    if os_type in ["Ubuntu", "debian"]:
        run_command("apt-get update")
        run_command("apt-get install -y certbot python3-certbot-nginx")
    else:  # CentOS, Fedora
        run_command("yum install -y epel-release")
        run_command("yum install -y certbot python3-certbot-nginx")
    
    # Obtener certificado SSL con Certbot
    run_command(f"certbot --nginx --non-interactive --agree-tos --email {email} -d {domain}")
    
    # Verificar que se haya instalado correctamente
    if os.path.exists(f"/etc/letsencrypt/live/{domain}/fullchain.pem"):
        print(f"{Color.CHECK_MARK} Certificado SSL instalado correctamente para {domain}")
        return True
    else:
        print(f"{Color.FAIL}Error al instalar certificado SSL para {domain}{Color.ENDC}")
        return False

def setup_nginx_with_domain(admin_port, client_port, domain, ssl_enabled):
    """Configura Nginx con un dominio específico y SSL si está habilitado"""
    nginx_conf_path = f"{PANEL_PATH}/nginx/conf/nginx.conf"
    
    # Configuración base de Nginx
    nginx_conf = f"""user  xtreamcodes;
worker_processes  auto;

worker_rlimit_nofile 300000;
events {{
    worker_connections  16000;
    use epoll;
    accept_mutex on;
    multi_accept on;
}}
thread_pool pool_xtream threads=32 max_queue=0;
http {{

    include       mime.types;
    default_type  application/octet-stream;

    sendfile           on;
    tcp_nopush         on;
    tcp_nodelay        on;
    reset_timedout_connection on;
    gzip off;
    fastcgi_read_timeout 200;
    access_log off;
    keepalive_timeout 10;
    include balance.conf;
    send_timeout 20m;	
    sendfile_max_chunk 512k;
    lingering_close off;
    aio threads=pool_xtream;
    client_body_timeout 13s;
    client_header_timeout 13s;
    client_max_body_size 3m;

    limit_req_zone $binary_remote_addr zone=one:30m rate=20r/s;
    server {{
        listen {client_port};
"""

    # Añadir configuración SSL si está habilitado
    if ssl_enabled:
        nginx_conf += f"""        listen 443 ssl;
        ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_prefer_server_ciphers on;
        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
        ssl_session_timeout 1d;
        ssl_session_cache shared:SSL:10m;
        ssl_session_tickets off;
        ssl_stapling on;
        ssl_stapling_verify on;
        
        # Redirigir HTTP a HTTPS
        if ($scheme != "https") {{
            return 301 https://$host$request_uri;
        }}
"""

    # Configuración de servidor para cliente
    nginx_conf += f"""        server_name {domain if domain else '_'};
        index index.php index.html index.htm;
        root {PANEL_PATH}/wwwdir/;
        server_tokens off;
        chunked_transfer_encoding off;

        if ( $request_method !~ ^(GET|POST)$ ) {{
            return 200;
        }}

        rewrite_log on;
        rewrite ^/live/(.*)/(.*)/(.*)\.(.*) /streaming/clients_live.php?username=$1&password=$2&stream=$3&extension=$4 break;
        rewrite ^/movie/(.*)/(.*)/(.*) /streaming/clients_movie.php?username=$1&password=$2&stream=$3&type=movie break;
        rewrite ^/series/(.*)/(.*)/(.*) /streaming/clients_movie.php?username=$1&password=$2&stream=$3&type=series break;
        rewrite ^/(.*)/(.*)/(.*).ch$ /streaming/clients_live.php?username=$1&password=$2&stream=$3&extension=ts break;
        rewrite ^/(.*).ch$ /streaming/clients_live.php?extension=ts&stream=$1&qs=$query_string break;
        rewrite ^/ch(.*).m3u8$ /streaming/clients_live.php?extension=m3u8&stream=$1&qs=$query_string break;
        rewrite ^/hls/(.*)/(.*)/(.*)/(.*)/(.*) /streaming/clients_live.php?extension=m3u8&username=$1&password=$2&stream=$3&type=hls&segment=$5&token=$4 break;
        rewrite ^/hlsr/(.*)/(.*)/(.*)/(.*)/(.*)/(.*) /streaming/clients_live.php?token=$1&username=$2&password=$3&segment=$6&stream=$4&key_seg=$5 break;
        rewrite ^/timeshift/(.*)/(.*)/(.*)/(.*)/(.*)\.(.*) /streaming/timeshift.php?username=$1&password=$2&stream=$5&extension=$6&duration=$3&start=$4 break;
        rewrite ^/timeshifts/(.*)/(.*)/(.*)/(.*)/(.*)\.(.*) /streaming/timeshift.php?username=$1&password=$2&stream=$4&extension=$6&duration=$3&start=$5 break;
        
        rewrite ^/(.*)/(.*)/(\d+) /streaming/clients_live.php?username=$1&password=$2&stream=$3&extension=ts break;
        #add pvr support
        rewrite ^/server/load.php$ /portal.php break;
        
        location /stalker_portal/c {{
            alias {PANEL_PATH}/wwwdir/c;
        }}
        
        #FFmpeg Report Progress
        location = /progress.php {{
            allow 127.0.0.1;
            deny all;
            fastcgi_pass php;
            include fastcgi_params;
            fastcgi_ignore_client_abort on;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_param SCRIPT_NAME $fastcgi_script_name;
        }}


        location ~ \.php$ {{
            limit_req zone=one burst=8;
            try_files $uri =404;
            fastcgi_index index.php;
            fastcgi_pass php;
            include fastcgi_params;
            fastcgi_buffering on;
            fastcgi_buffers 96 32k;
            fastcgi_buffer_size 32k;
            fastcgi_max_temp_file_size 0;
            fastcgi_keep_conn on;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_param SCRIPT_NAME $fastcgi_script_name;
        }}
    }}
    
    # Admin Panel Server
    server {{
        listen {admin_port};"""

    # Agregar SSL para el panel de administración si está habilitado
    if ssl_enabled:
        nginx_conf += f"""
        listen {admin_port} ssl;
        ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
"""

    nginx_conf += f"""
        server_name {domain if domain else '_'};
        index index.php index.html index.htm;
        root {PANEL_PATH}/admin/;

        location ~ \.php$ {{
            limit_req zone=one burst=8;
            try_files $uri =404;
            fastcgi_index index.php;
            fastcgi_pass php;
            include fastcgi_params;
            fastcgi_buffering on;
            fastcgi_buffers 96 32k;
            fastcgi_buffer_size 32k;
            fastcgi_max_temp_file_size 0;
            fastcgi_keep_conn on;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_param SCRIPT_NAME $fastcgi_script_name;
        }}
    }}
    
    #ISP CONFIGURATION
    server {{
         listen 8805;
         root {PANEL_PATH}/isp/;
         location / {{
                      allow 127.0.0.1;
                      deny all;
         }}
         location ~ \.php$ {{
                             limit_req zone=one burst=8;
                             try_files $uri =404;
                             fastcgi_index index.php;
                             fastcgi_pass php;
                             include fastcgi_params;
                             fastcgi_buffering on;
                             fastcgi_buffers 96 32k;
                             fastcgi_buffer_size 32k;
                             fastcgi_max_temp_file_size 0;
                             fastcgi_keep_conn on;
                             fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
                             fastcgi_param SCRIPT_NAME $fastcgi_script_name;
         }}
    }}
}}
"""

    # Escribir la configuración de Nginx
    with open(nginx_conf_path, "w") as f:
        f.write(nginx_conf)
    
    return True
