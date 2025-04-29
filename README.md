# SendIP - Network Reconnaissance Tool / Herramienta de Reconocimiento de Red

[English](#english) | [Español](#español)

## English

### Overview
SendIP is a powerful network reconnaissance tool designed for scanning and analyzing network hosts. It provides detailed information about operating systems, open ports, running services, and potential vulnerabilities.

### Features
- Multi-host scanning capability
- Operating system detection using TTL analysis
- Port scanning with service identification
- Web server detection and analysis
- Vulnerability checking for common web servers
- Matrix-style visual interface
- Bilingual support (English/Spanish)

### Requirements
```
colorama
requests
python 3.x
```

### Installation
1. Clone this repository
2. Install dependencies:
```bash
pip install colorama requests
```

### Usage
1. Run the script:
```bash
python main.py
```
2. Enter IP addresses or domains (comma-separated)
3. Choose verbose mode if desired (y/N)

### Features Description
- **Matrix Effect**: Visual interface with Matrix-style animation
- **OS Detection**: Uses TTL analysis to identify target operating systems
- **Port Scanning**: Checks for open ports and identifies running services
- **Vulnerability Analysis**: Detects common web server vulnerabilities
- **HTTP Information**: Analyzes web servers and their technologies

### Security Notice
This tool is for educational and ethical testing purposes only. Always obtain proper authorization before scanning any networks or systems.

---

## Español

### Descripción General
SendIP es una potente herramienta de reconocimiento de red diseñada para escanear y analizar hosts en la red. Proporciona información detallada sobre sistemas operativos, puertos abiertos, servicios en ejecución y vulnerabilidades potenciales.

### Características
- Capacidad de escaneo múltiple de hosts
- Detección de sistema operativo mediante análisis TTL
- Escaneo de puertos con identificación de servicios
- Detección y análisis de servidores web
- Verificación de vulnerabilidades en servidores web comunes
- Interfaz visual estilo Matrix
- Soporte bilingüe (Inglés/Español)

### Requisitos
```
colorama
requests
python 3.x
```

### Instalación
1. Clonar este repositorio
2. Instalar dependencias:
```bash
pip install colorama requests
```

### Uso
1. Ejecutar el script:
```bash
python main.py
```
2. Ingresar direcciones IP o dominios (separados por comas)
3. Elegir modo verbose si se desea (s/N)

### Descripción de Características
- **Efecto Matrix**: Interfaz visual con animación estilo Matrix
- **Detección de SO**: Utiliza análisis TTL para identificar sistemas operativos objetivo
- **Escaneo de Puertos**: Verifica puertos abiertos e identifica servicios en ejecución
- **Análisis de Vulnerabilidades**: Detecta vulnerabilidades comunes en servidores web
- **Información HTTP**: Analiza servidores web y sus tecnologías

### Aviso de Seguridad
Esta herramienta es solo para fines educativos y de pruebas éticas. Siempre obtenga la autorización adecuada antes de escanear cualquier red o sistema.