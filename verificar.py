import os
import subprocess
import sys

# Configuración
PHP_FPM_BIN = "/home/xtreamcodes/iptv_xtream_codes/php/sbin/php-fpm"
PHP_FPM_CONF = "/home/xtreamcodes/iptv_xtream_codes/php/etc/VaiIb8.conf"
LIBZIP4 = "/usr/lib/x86_64-linux-gnu/libzip.so.4"
LIBZIP5 = "/usr/lib/x86_64-linux-gnu/libzip.so.5"
SYMLINK_COMMAND = f"sudo ln -s {LIBZIP5} {LIBZIP4}"

def run(cmd, capture_output=True):
    try:
        if capture_output:
            return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode().strip()
        else:
            return subprocess.call(cmd, shell=True)
    except subprocess.CalledProcessError as e:
        return e.output.decode().strip() if hasattr(e, 'output') else str(e)

def check_and_fix_libzip():
    print("🔍 Verificando libzip.so.4...")
    if os.path.exists(LIBZIP4):
        print("✅ libzip.so.4 ya existe.")
        return True

    if not os.path.exists(LIBZIP5):
        print("❌ libzip.so.5 no se encontró. Intenta instalar con:")
        print("   sudo apt install libzip5")
        return False

    print("🔧 Creando symlink libzip.so.4 -> libzip.so.5...")
    result = run(SYMLINK_COMMAND)
    if os.path.exists(LIBZIP4):
        print("✅ Symlink creado con éxito.")
        return True
    else:
        print("❌ No se pudo crear el symlink. Resultado:")
        print(result)
        return False

def try_start_php_fpm():
    print("🚀 Probando iniciar PHP-FPM con Xtream UI...")
    cmd = f"{PHP_FPM_BIN} --fpm-config {PHP_FPM_CONF}"
    result = run(cmd)
    if "error" in result.lower():
        print("❌ Error al iniciar PHP-FPM:")
        print(result)
        return False
    print("✅ PHP-FPM iniciado correctamente.")
    return True

def restart_services():
    print("🔁 Reiniciando servicios relevantes...")
    services = ["nginx", "xtreamcodes"]
    for svc in services:
        print(f"  ↪️  Reiniciando {svc}...")
        run(f"sudo systemctl restart {svc}", capture_output=False)

    print("✅ Servicios reiniciados. Revisa el panel de Xtream UI.")

def main():
    if not check_and_fix_libzip():
        sys.exit(1)
    
    if not try_start_php_fpm():
        print("⚠️ Aún hay errores al iniciar PHP-FPM.")
        sys.exit(2)

    restart_services()

if __name__ == "__main__":
    main()
