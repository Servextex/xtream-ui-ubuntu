import os
import subprocess
import re

NGINX_LOG_DIR = "/var/log/nginx"
XTREAM_LOG_DIR = "/home/xtreamcodes/iptv_xtream_codes/logs"
PHP_FPM_BIN = "/home/xtreamcodes/iptv_xtream_codes/php/sbin/php-fpm"
PHP_FPM_CONF = "/home/xtreamcodes/iptv_xtream_codes/php/etc/VaiIb8.conf"
PHP_FPM_SOCK = "/home/xtreamcodes/iptv_xtream_codes/php/VaiIb8.sock"

def run(cmd, capture_output=True):
    try:
        if capture_output:
            return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode().strip()
        else:
            return subprocess.call(cmd, shell=True)
    except subprocess.CalledProcessError as e:
        return e.output.decode() if hasattr(e, "output") else str(e)

def check_process(process_name):
    print(f"\n🔍 Buscando procesos con nombre '{process_name}'...")
    output = run(f"ps aux | grep {process_name} | grep -v grep")
    if output:
        print(f"✅ Procesos encontrados:\n{output}")
        return True
    else:
        print(f"❌ No se encontró ningún proceso '{process_name}'.")
        return False

def check_file_exists(path, description="archivo"):
    print(f"\n🔍 Verificando existencia de {description} en: {path}")
    if os.path.exists(path):
        print(f"✅ {description.capitalize()} existe.")
        return True
    else:
        print(f"❌ {description.capitalize()} NO existe.")
        return False

def check_permissions(path):
    print(f"\n🔍 Revisando permisos de: {path}")
    try:
        st = os.stat(path)
        print(f"Permisos: {oct(st.st_mode)}")
        print(f"Dueño UID: {st.st_uid} GID: {st.st_gid}")
    except Exception as e:
        print(f"❌ Error al obtener permisos: {e}")

def tail_log(logfile, lines=20):
    print(f"\n📄 Últimas {lines} líneas del log: {logfile}")
    if not os.path.exists(logfile):
        print("❌ Log no encontrado.")
        return ""
    output = run(f"tail -n {lines} {logfile}")
    print(output if output else "(log vacío)")
    return output

def tail_all_logs_in_dir(dir_path, lines=20):
    print(f"\n📂 Revisión de logs en directorio: {dir_path}")
    if not os.path.isdir(dir_path):
        print("❌ Directorio no existe.")
        return ""

    logs = [f for f in os.listdir(dir_path) if f.endswith(".log")]
    if not logs:
        print("❌ No se encontraron archivos .log")
        return ""

    combined_logs = ""
    for log_file in logs:
        combined_logs += tail_log(os.path.join(dir_path, log_file), lines) + "\n"
    return combined_logs

def try_start_php_fpm():
    print("\n🚀 Intentando iniciar PHP-FPM manualmente para ver errores...")
    cmd = f"{PHP_FPM_BIN} --fpm-config {PHP_FPM_CONF} -R"
    output = run(cmd)
    if "error" in output.lower() or "failed" in output.lower():
        print("❌ PHP-FPM reporta errores:\n" + output)
        return output
    else:
        print("✅ PHP-FPM inició sin errores visibles (revisa si quedó en segundo plano).")
        return ""

def check_for_errors(log_content):
    error_keywords = [
        "error", "failed", "denied", "cannot", "warning", "fatal",
        "segfault", "exception", "not found", "unable"
    ]
    log_lower = log_content.lower()
    for keyword in error_keywords:
        if keyword in log_lower:
            return True
    return False

def restart_services():
    print("\n🔄 Reiniciando servicios nginx y php-fpm...")
    nginx_status = run("systemctl restart nginx && systemctl status nginx", capture_output=True)
    php_fpm_status = run("systemctl restart php7.4-fpm && systemctl status php7.4-fpm", capture_output=True)

    print("\n=== Estado nginx después del reinicio ===")
    print(nginx_status)
    print("\n=== Estado php-fpm después del reinicio ===")
    print(php_fpm_status)

def main():
    print("=== Diagnóstico completo para Xtream UI Error 500 ===")

    # 1. Verificar procesos
    php_running = check_process("php-fpm")
    nginx_running = check_process("nginx")

    # 2. Revisar existencia y permisos del socket
    socket_exists = check_file_exists(PHP_FPM_SOCK, "socket PHP-FPM")
    if socket_exists:
        check_permissions(PHP_FPM_SOCK)

    # 3. Revisar logs nginx y xtream UI
    nginx_logs = tail_all_logs_in_dir(NGINX_LOG_DIR)
    xtream_logs = tail_all_logs_in_dir(XTREAM_LOG_DIR)

    # 4. Intentar iniciar PHP-FPM manualmente para detectar errores
    php_fpm_errors = try_start_php_fpm()

    # 5. Verificar permisos generales
    check_permissions("/home/xtreamcodes/iptv_xtream_codes")
    check_permissions("/home/xtreamcodes/iptv_xtream_codes/php")

    # 6. Comprobar si hay errores en logs o en PHP-FPM startup
    found_errors = False
    if check_for_errors(nginx_logs):
        print("\n❗ Se encontraron errores en logs de nginx.")
        found_errors = True
    if check_for_errors(xtream_logs):
        print("\n❗ Se encontraron errores en logs de Xtream UI.")
        found_errors = True
    if php_fpm_errors:
        print("\n❗ Se encontraron errores al iniciar PHP-FPM manualmente.")
        found_errors = True

    # 7. Si hay errores, reiniciar servicios automáticamente
    if found_errors:
        print("\n⚠️ Errores detectados, procediendo a reiniciar servicios...")
        restart_services()

        # Volver a mostrar estado después del reinicio
        print("\n🔍 Estado de procesos tras reinicio:")
        check_process("php-fpm")
        check_process("nginx")
    else:
        print("\n✅ No se detectaron errores evidentes en logs o PHP-FPM.")

    print("\n=== Diagnóstico terminado ===")

if __name__ == "__main__":
    main()
