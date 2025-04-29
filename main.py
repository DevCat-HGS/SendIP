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
import asyncio
import json
import csv
from datetime import datetime
from colorama import init, Fore, Back, Style
from concurrent.futures import ThreadPoolExecutor
from scanner_utils import ScannerUtils
from tqdm import tqdm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.console import Console
from rich.theme import Theme
from jinja2 import Template

init(autoreset=True)

# Global Configuration / Configuración Global

# Enable verbose output / Habilitar salida detallada
VERBOSE = False
SILENT_MODE = False

# Maximum number of concurrent threads / Número máximo de hilos concurrentes
MAX_THREADS = 10

# List of ports to scan / Lista de puertos a escanear
EXTENDED_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

# Connection timeout in seconds / Tiempo de espera de conexión en segundos
TIMEOUT = 1

# Characters for matrix effect / Caracteres para el efecto matrix
MATRIX_CHARS = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(50))

# Visual Themes / Temas Visuales
THEMES = {
    'classic': {
        'info': Fore.CYAN,
        'success': Fore.GREEN,
        'warning': Fore.YELLOW,
        'error': Fore.RED,
        'banner': Fore.GREEN,
        'accent': Fore.CYAN
    },
    'matrix': {
        'info': Fore.GREEN,
        'success': Fore.GREEN,
        'warning': Fore.GREEN,
        'error': Fore.RED,
        'banner': Fore.GREEN,
        'accent': Fore.GREEN
    },
    'minimal': {
        'info': Fore.WHITE,
        'success': Fore.WHITE,
        'warning': Fore.WHITE,
        'error': Fore.RED,
        'banner': Fore.WHITE,
        'accent': Fore.WHITE
    }
}

# Current theme / Tema actual
CURRENT_THEME = THEMES['classic']

# Rich console for advanced output / Consola Rich para salida avanzada
console = Console(theme=Theme({'info': 'cyan', 'success': 'green', 'warning': 'yellow', 'error': 'red'}))

def matrix_effect():
    """Creates a Matrix-style visual effect in the terminal.
    Crea un efecto visual estilo Matrix en la terminal.
    
    The effect displays random characters in green color, simulating the iconic Matrix digital rain.
    El efecto muestra caracteres aleatorios en color verde, simulando la icónica lluvia digital de Matrix.
    """
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
    """Check for common vulnerabilities in web servers.
    Verifica vulnerabilidades comunes en servidores web.
    
    Args:
        host (str): Target host / Host objetivo
        port (int): Port to check / Puerto a verificar
    
    Returns:
        list: List of found vulnerabilities / Lista de vulnerabilidades encontradas
    """
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
    """Detect the operating system of a remote host using TTL analysis.
    Detecta el sistema operativo de un host remoto usando análisis TTL.
    
    Args:
        host (str): Target host / Host objetivo
    
    Returns:
        tuple: (OS type, is_alive) / (Tipo de SO, está_activo)
    """
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
    """Scan ports on target host using multiple threads.
    Escanea puertos en el host objetivo usando múltiples hilos.
    
    Args:
        host (str): Target host / Host objetivo
    
    Prints:
        Information about open ports and services
        Información sobre puertos abiertos y servicios
    """
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

async def scan_target(host, start_time, progress=None):
    scanner = ScannerUtils()
    results = {
        'host': host,
        'status': 'error',
        'os_info': None,
        'web_info': None,
        'vulnerabilities': [],
        'ports': [],
        'advanced_info': None
    }
    
    if ping_host(host):
        results['status'] = 'success'
        if not SILENT_MODE:
            print_status("Iniciando análisis detallado...", "info")
        
        # Configurar barra de progreso
        if progress:
            task_id = progress.add_task(f"[cyan]Escaneando {host}", total=100)
            progress.update(task_id, advance=10)
        
        # Escaneo avanzado asíncrono
        advanced_scan = await scanner.scan_target_async(host)
        results['advanced_info'] = advanced_scan
        if progress: progress.update(task_id, advance=20)
        
        # Mostrar información de WAF si se detectó
        if advanced_scan.get('results') and advanced_scan['results'][0].get('waf_detection', {}).get('detected'):
            waf_info = advanced_scan['results'][0]['waf_detection']
            if not SILENT_MODE:
                console.print(f"\n[warning]WAF Detectado: {waf_info['waf_type']}")
        if progress: progress.update(task_id, advance=10)
        
        # Mostrar información de geolocalización
        if advanced_scan.get('results') and advanced_scan['results'][0].get('geolocation'):
            geo_info = advanced_scan['results'][0]['geolocation']
            if 'error' not in geo_info and not SILENT_MODE:
                console.print("\n[info]Geolocalización:")
                console.print(f"    ├─ País: {geo_info['country']}")
                console.print(f"    ├─ Ciudad: {geo_info['city']}")
                console.print(f"    └─ Coordenadas: {geo_info['latitude']}, {geo_info['longitude']}")
        if progress: progress.update(task_id, advance=10)
        
        # Escaneo de servicios web y SSL
        web_info = detect_http_info(host)
        if web_info:
            results['web_info'] = web_info
            if not SILENT_MODE:
                console.print(f"\n{web_info}", style="info")
            
            # Mostrar información SSL si está disponible
            if advanced_scan.get('results') and advanced_scan['results'][0].get('ssl_info'):
                ssl_info = advanced_scan['results'][0]['ssl_info']
                if 'error' not in ssl_info and not SILENT_MODE:
                    console.print("\n[success]Información SSL:")
                    console.print(f"    ├─ Versión: {ssl_info['version']}")
                    console.print(f"    ├─ Cifrado: {ssl_info['cipher']}")
                    console.print(f"    └─ Válido hasta: {ssl_info['not_after']}")
        if progress: progress.update(task_id, advance=20)
        
        # Escaneo de puertos y vulnerabilidades
        scan_ports(host)
        if progress: progress.update(task_id, advance=20)
        
        # Análisis de vulnerabilidades en puertos web
        for port in [80, 443]:
            vulns = check_common_vulnerabilities(host, port)
            if vulns:
                results['vulnerabilities'].extend(vulns)
                if not SILENT_MODE:
                    for vuln in vulns:
                        console.print(f"[warning][!] {vuln}")
        if progress: progress.update(task_id, advance=10)
    
    return results

def export_results(results, format_type, filename):
    """Export scan results in different formats.
    Exporta los resultados del escaneo en diferentes formatos.
    
    Args:
        results (list): Scan results / Resultados del escaneo
        format_type (str): Export format (json, csv, html) / Formato de exportación
        filename (str): Output filename / Nombre del archivo de salida
    """
    if format_type == 'json':
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
    
    elif format_type == 'csv':
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Host', 'Estado', 'Sistema Operativo', 'Vulnerabilidades'])
            for result in results:
                vulns = ', '.join(result.get('vulnerabilities', [])) or 'Ninguna'
                writer.writerow([result['host'], result['status'], 
                                result.get('os_info', 'Desconocido'), vulns])
    
    elif format_type == 'html':
        template_str = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Reporte de Escaneo</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .success { color: green; }
                .error { color: red; }
                .warning { color: orange; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <h1>Reporte de Escaneo de Red</h1>
            <table>
                <tr>
                    <th>Host</th>
                    <th>Estado</th>
                    <th>Sistema Operativo</th>
                    <th>Vulnerabilidades</th>
                </tr>
                {% for result in results %}
                <tr>
                    <td>{{ result.host }}</td>
                    <td class="{{ 'success' if result.status == 'success' else 'error' }}">{{ result.status }}</td>
                    <td>{{ result.os_info or 'Desconocido' }}</td>
                    <td class="{{ 'warning' if result.vulnerabilities else '' }}">
                        {% if result.vulnerabilities %}
                            <ul>
                            {% for vuln in result.vulnerabilities %}
                                <li>{{ vuln }}</li>
                            {% endfor %}
                            </ul>
                        {% else %}
                            Ninguna
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </table>
        </body>
        </html>
        """
        template = Template(template_str)
        html_content = template.render(results=results)
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)

async def main():
    global VERBOSE, SILENT_MODE, CURRENT_THEME
    print_banner()
    
    # Configuración inicial
    console.print("\n[?] Ingrese IPs o dominios (separados por comas): ", style="info")
    hosts = [h.strip() for h in input().split(',')]
    
    console.print("[?] Seleccione el tema visual (classic/matrix/minimal): ", style="info")
    theme = input().strip().lower()
    if theme in THEMES:
        CURRENT_THEME = THEMES[theme]
    
    console.print("[?] ¿Modo verbose? (s/N): ", style="info")
    VERBOSE = input().strip().lower() == 's'
    
    console.print("[?] ¿Modo silencioso? (s/N): ", style="info")
    SILENT_MODE = input().strip().lower() == 's'
    
    console.print("[?] ¿Exportar resultados? (json/csv/html/n): ", style="info")
    export_format = input().strip().lower()
    
    print("\n" + "═" * 50)
    start_time = datetime.now()
    
    # Configurar barra de progreso
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeRemainingColumn(),
        console=console,
        disable=SILENT_MODE
    ) as progress:
        # Escaneo de múltiples objetivos
        tasks = [scan_target(host, start_time, progress) for host in hosts]
        results = await asyncio.gather(*tasks)
    
    # Resumen final
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    if not SILENT_MODE:
        print("\n" + "═" * 50)
        console.print("\n[success][+] Resumen del escaneo:")
        for result in results:
            status_style = "success" if result['status'] == 'success' else "error"
            console.print(f"\n[{status_style}][*] Host: {result['host']}")
            if result['status'] == 'success' and result['vulnerabilities']:
                console.print("    ├─ Vulnerabilidades detectadas:", style="warning")
                for vuln in result['vulnerabilities']:
                    console.print(f"    │  └─ {vuln}", style="warning")
        
        print("\n" + "═" * 50)
        console.print(f"\n[success][+] Escaneo completo en {duration:.2f} segundos")
        
        if VERBOSE:
            console.print("[info][*] Detalles adicionales:")
            console.print(f"    ├─ Objetivos escaneados: {len(hosts)}")
            console.print(f"    ├─ Tiempo inicio: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
            console.print(f"    ├─ Tiempo fin: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
            console.print(f"    └─ Duración total: {duration:.2f}s")
        
        print("\n" + "═" * 50)
    
    # Exportar resultados si se solicitó
    if export_format in ['json', 'csv', 'html']:
        filename = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{export_format}"
        export_results(results, export_format, filename)
        if not SILENT_MODE:
            console.print(f"\n[success][+] Resultados exportados a: {filename}")

if __name__ == "__main__":
    asyncio.run(main())

if __name__ == "__main__":
    main()
