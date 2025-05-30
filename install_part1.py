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
