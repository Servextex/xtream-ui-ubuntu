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
