import os
import platform
import socket
import requests
import time
from colorama import init, Fore, Back, Style

init(autoreset=True)

def print_banner():
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

def detect_os(host):
    try:
        # Realizar ping y capturar TTL
        if platform.system() == "Windows":
            response = os.popen(f"ping -n 1 {host}").read()
            ttl = int(response.split("TTL=")[1].split("\n")[0]) if "TTL=" in response else 0
        else:
            response = os.popen(f"ping -c 1 {host}").read()
            ttl = int(response.split("ttl=")[1].split(" ")[0]) if "ttl=" in response else 0
        
        # Determinar SO basado en TTL
        if ttl == 0:
            return "Host no alcanzable", False
        elif ttl <= 64:
            return "Linux/Unix", True
        elif ttl <= 128:
            return "Windows", True
        else:
            return "Cisco/Network Device", True
    except Exception:
        return "Error en detección", False

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

def scan_ports(host):
    common_ports = [21, 22, 23, 25, 53, 80, 443, 3306, 8080]
    open_ports = []
    
    print(Fore.YELLOW + "\n[+] Escaneando puertos comunes...")
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            service = socket.getservbyport(port)
            open_ports.append(f"    ├─ Puerto {port}: {service}")
        sock.close()
    
    if open_ports:
        print(Fore.GREEN + "[✔] Puertos abiertos detectados:")
        print(Fore.GREEN + "\n".join(open_ports))
    else:
        print(Fore.RED + "[!] No se encontraron puertos abiertos")

def main():
    print_banner()
    host = input(Fore.CYAN + "\n[?] Ingrese IP o dominio: " + Fore.RESET).strip()
    print("\n" + "═" * 50)
    
    if ping_host(host):
        web_info = detect_http_info(host)
        if web_info:
            print(Fore.MAGENTA + "\n" + web_info)
        scan_ports(host)
        print("\n" + "═" * 50)
    else:
        print(Fore.RED + "[✖] Host no alcanzable")
    
    print(Fore.GREEN + "\n[+] Escaneo completado!\n")

if __name__ == "__main__":
    main()
