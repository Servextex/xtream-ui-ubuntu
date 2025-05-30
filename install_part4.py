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

def print_completion_info(admin_user, admin_pass, admin_port, mysql_pass, db_pass, ip_addr):
    """Imprime la información de instalación completada"""
    info = f"""
─────────────────  Guardado en: /root/Xtreaminfo.txt  ─────────────────
│ ACCESO AL PANEL: http://{ip_addr}:{admin_port}
│ USUARIO: {admin_user}
│ CONTRASEÑA: {admin_pass}
│ CONTRASEÑA MYSQL root: {mysql_pass}
│ CONTRASEÑA MYSQL user_iptvpro: {db_pass}
────────────────────────────────────────────────────────────────────
"""
    print(info)
    
    # Guardar la información en un archivo
    with open("/root/Xtreaminfo.txt", "w") as f:
        f.write(f"""
───────────────────────────  INFO  ─────────────────────────────────
│
│ ACCESO AL PANEL: http://{ip_addr}:{admin_port}
│ 
│ USUARIO: {admin_user}
│
│ CONTRASEÑA: {admin_pass}
│ 
│ CONTRASEÑA MYSQL root: {mysql_pass}
│
│ CONTRASEÑA MYSQL user_iptvpro: {db_pass}
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
    
    # Preguntar por confirmación
    silent = args.silent
    if not silent:
        confirm = input(f"\n¿Está seguro de que desea instalar Xtream UI {XC_VERSION} en http://{ip_addr}:{admin_port}? (y/n): ")
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
    
    # Crear configuración completa de Nginx
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
    print_completion_info(admin_user, admin_pass, admin_port, mysql_pass, xpass, ip_addr)

if __name__ == "__main__":
    main()
