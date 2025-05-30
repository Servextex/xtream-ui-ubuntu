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
