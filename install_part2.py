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
