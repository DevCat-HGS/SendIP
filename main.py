import os
import platform
import socket
import requests
import time
import threading
import queue
import random
import string
import sys
from datetime import datetime
from colorama import init, Fore, Back, Style
from concurrent.futures import ThreadPoolExecutor

init(autoreset=True)

# Configuración global
VERBOSE = False
MAX_THREADS = 10
EXTENDED_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
TIMEOUT = 1
MATRIX_CHARS = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(50))

def matrix_effect():
    for _ in range(3):
        for char in MATRIX_CHARS:
            print(f"{Fore.GREEN}{char}", end='', flush=True)
            time.sleep(0.01)
        print()
    time.sleep(0.5)
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    matrix_effect()
    banner = f"""
    {Fore.GREEN}╔══════════════════════════════════════╗
    ║ {Fore.CYAN}███████╗███████╗███╗   ██╗██████╗ {Fore.GREEN}║
    ║ {Fore.CYAN}██╔════╝██╔════╝████╗  ██║██╔══██╗{Fore.GREEN}║
    ║ {Fore.CYAN}███████╗█████╗  ██╔██╗ ██║██║  ██║{Fore.GREEN}║
    ║ {Fore.CYAN}╚════██║██╔══╝  ██║╚██╗██║██║  ██║{Fore.GREEN}║
    ║ {Fore.CYAN}███████║███████╗██║ ╚████║██████╔╝{Fore.GREEN}║
    ║ {Fore.CYAN}╚══════╝╚══════╝╚═╝  ╚═══╝╚═════╝ {Fore.GREEN}║
    ╚══════════════════════════════════════╝
    {Style.BRIGHT}{Fore.GREEN}[ {Fore.WHITE}Network Reconnaissance Tool {Fore.GREEN}]
    """
    print(banner)
    time.sleep(0.1)

def check_common_vulnerabilities(host, port):
    vulnerabilities = []
    try:
        # Verificar versiones obsoletas comunes
        if port == 80 or port == 443:
            try:
                protocol = "https" if port == 443 else "http"
                r = requests.get(f"{protocol}://{host}:{port}", timeout=TIMEOUT, verify=False)
                server = r.headers.get("Server", "")
                if server and any(v in server.lower() for v in ["apache/2.2", "nginx/1.10", "iis/6"]):
                    vulnerabilities.append(f"Versión potencialmente vulnerable: {server}")
            except:
                pass
    except Exception as e:
        if VERBOSE:
            print(Fore.RED + f"[!] Error en análisis de vulnerabilidades: {str(e)}")
    return vulnerabilities

def detect_os(host):
    try:
        # Realizar ping y capturar TTL
        if platform.system() == "Windows":
            response = os.popen(f"ping -n 1 {host}").read()
            ttl = int(response.split("TTL=")[1].split("\n")[0]) if "TTL=" in response else 0
        else:
            response = os.popen(f"ping -c 1 {host}").read()
            ttl = int(response.split("ttl=")[1].split(" ")[0]) if "ttl=" in response else 0
        
        # Análisis avanzado de TTL y características
        os_info, fingerprints = analyze_os_fingerprint(host, ttl)
        if VERBOSE and fingerprints:
            print(Fore.CYAN + "\n[*] Detalles de fingerprinting:")
            for fp in fingerprints:
                print(Fore.CYAN + f"    ├─ {fp}")
        
        return os_info, True if ttl > 0 else False
    except Exception as e:
        if VERBOSE:
            print(Fore.RED + f"[!] Error en detección: {str(e)}")
        return "Error en detección", False

def analyze_os_fingerprint(host, ttl):
    fingerprints = []
    os_type = "Sistema Desconocido"
    
    try:
        # Análisis de TTL
        if ttl <= 64:
            os_type = "Linux/Unix (Probable)"
            fingerprints.append(f"TTL={ttl} (Típico de Linux/Unix)")
        elif ttl <= 128:
            os_type = "Windows (Probable)"
            fingerprints.append(f"TTL={ttl} (Típico de Windows)")
        elif ttl <= 255:
            os_type = "Cisco/Network Device (Probable)"
            fingerprints.append(f"TTL={ttl} (Típico de dispositivos de red)")
        
        # Análisis TCP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        if sock.connect_ex((host, 80)) == 0:
            fingerprints.append("Puerto 80 abierto (Posible servidor web)")
            try:
                r = requests.get(f"http://{host}", timeout=TIMEOUT, verify=False)
                server = r.headers.get("Server", "")
                if server:
                    fingerprints.append(f"Servidor web: {server}")
            except:
                pass
        
        # Análisis de servicios comunes
        common_ports = {22: "SSH", 23: "Telnet", 445: "SMB"}
        for port, service in common_ports.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            if sock.connect_ex((host, port)) == 0:
                fingerprints.append(f"Puerto {port} ({service}) abierto")
            sock.close()
    
    except Exception as e:
        if VERBOSE:
            print(Fore.RED + f"[!] Error en fingerprinting: {str(e)}")
    
    return os_type, fingerprints

def ping_host(host):
    print(Fore.YELLOW + f"[+] Escaneando {host}...")
    os_type, is_alive = detect_os(host)
    if is_alive:
        print(Fore.GREEN + f"[✔] Host detectado: {os_type}")
    return is_alive

def detect_http_info(host):
    try:
        protocols = ["http", "https"]
        results = []
        
        for protocol in protocols:
            try:
                url = f"{protocol}://{host}"
                r = requests.get(url, timeout=3, verify=False)
                server = r.headers.get("Server", "Desconocido")
                powered = r.headers.get("X-Powered-By", "Desconocido")
                results.append(f"[+] {protocol.upper()} Detectado")
                results.append(f"    ├─ Servidor: {server}")
                results.append(f"    └─ Tecnología: {powered}")
            except:
                continue
                
        return "\n".join(results) if results else "[!] No se detectaron servicios web"
    except Exception as e:
        return "[!] Error al detectar servicios web"

def scan_port(host, port, results):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((host, port))
        if result == 0:
            try:
                service = socket.getservbyport(port)
                banner = get_service_banner(host, port)
                results.append((port, service, banner))
                if VERBOSE:
                    print(Fore.CYAN + f"[*] Puerto {port} ({service}) - {banner if banner else 'Sin banner'}")
            except:
                results.append((port, "desconocido", ""))
        sock.close()
    except Exception as e:
        if VERBOSE:
            print(Fore.RED + f"[!] Error escaneando puerto {port}: {str(e)}")

def get_service_banner(host, port):
    try:
        if port in [80, 443, 8080]:
            protocol = "https" if port == 443 else "http"
            r = requests.get(f"{protocol}://{host}:{port}", timeout=TIMEOUT, verify=False)
            return f"Server: {r.headers.get('Server', 'Desconocido')}"
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            sock.connect((host, port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner
    except:
        return ""

def scan_ports(host):
    print(Fore.YELLOW + "\n[+] Iniciando escaneo de puertos...")
    ports = EXTENDED_PORTS if VERBOSE else EXTENDED_PORTS[:10]
    results = []
    
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        threads = []
        for port in ports:
            thread = executor.submit(scan_port, host, port, results)
            threads.append(thread)
        
        # Esperar a que todos los hilos terminen
        for thread in threads:
            thread.result()
    
    if results:
        print(Fore.GREEN + "\n[✔] Puertos abiertos detectados:")
        for port, service, banner in sorted(results, key=lambda x: x[0]):
            banner_info = f" - {banner}" if banner else ""
            print(Fore.GREEN + f"    ├─ Puerto {port}: {service}{banner_info}")
    else:
        print(Fore.RED + "\n[!] No se encontraron puertos abiertos")

def print_status(message, status_type="info"):
    timestamp = datetime.now().strftime("%H:%M:%S")
    color = {
        "info": Fore.CYAN,
        "success": Fore.GREEN,
        "warning": Fore.YELLOW,
        "error": Fore.RED
    }.get(status_type, Fore.WHITE)
    
    if VERBOSE:
        print(f"{color}[{timestamp}] {message}")

def scan_target(host, start_time):
    results = {
        'host': host,
        'status': 'error',
        'os_info': None,
        'web_info': None,
        'vulnerabilities': [],
        'ports': []
    }
    
    if ping_host(host):
        results['status'] = 'success'
        print_status("Iniciando análisis detallado...", "info")
        
        # Escaneo de servicios web
        web_info = detect_http_info(host)
        if web_info:
            results['web_info'] = web_info
            print(Fore.MAGENTA + "\n" + web_info)
        
        # Escaneo de puertos y vulnerabilidades
        scan_ports(host)
        
        # Análisis de vulnerabilidades en puertos web
        for port in [80, 443]:
            vulns = check_common_vulnerabilities(host, port)
            if vulns:
                results['vulnerabilities'].extend(vulns)
                for vuln in vulns:
                    print(Fore.YELLOW + f"[!] {vuln}")
    
    return results

def main():
    global VERBOSE
    print_banner()
    
    # Configuración inicial
    print(Fore.CYAN + "\n[?] Ingrese IPs o dominios (separados por comas): " + Fore.RESET)
    hosts = [h.strip() for h in input().split(',')]
    verbose = input(Fore.CYAN + "[?] ¿Modo verbose? (s/N): " + Fore.RESET).strip().lower() == 's'
    VERBOSE = verbose
    
    print("\n" + "═" * 50)
    start_time = datetime.now()
    
    # Escaneo de múltiples objetivos
    results = []
    for host in hosts:
        print(Fore.CYAN + f"\n[*] Escaneando objetivo: {host}")
        result = scan_target(host, start_time)
        results.append(result)
    
    # Resumen final
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    print("\n" + "═" * 50)
    print(Fore.GREEN + "\n[+] Resumen del escaneo:")
    for result in results:
        status_color = Fore.GREEN if result['status'] == 'success' else Fore.RED
        print(f"\n{status_color}[*] Host: {result['host']}")
        if result['status'] == 'success':
            if result['vulnerabilities']:
                print(Fore.YELLOW + "    ├─ Vulnerabilidades detectadas:")
                for vuln in result['vulnerabilities']:
                    print(Fore.YELLOW + f"    │  └─ {vuln}")
    
    print("\n" + "═" * 50)
    print(Fore.GREEN + f"\n[+] Escaneo completo en {duration:.2f} segundos")
    
    if VERBOSE:
        print(Fore.CYAN + "[*] Detalles adicionales:")
        print(Fore.CYAN + f"    ├─ Objetivos escaneados: {len(hosts)}")
        print(Fore.CYAN + f"    ├─ Tiempo inicio: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(Fore.CYAN + f"    ├─ Tiempo fin: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(Fore.CYAN + f"    └─ Duración total: {duration:.2f}s")
    
    print("\n" + "═" * 50)

if __name__ == "__main__":
    main()
