import random
import time
from typing import List, Dict, Any, Optional
import logging
from datetime import datetime, timedelta

class SecurityUtils:
    def __init__(self):
        self.logger = logging.getLogger('sendip.security')
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0)',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X)',
            'Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X)',
            'Mozilla/5.0 (Android 11; Mobile)',
            'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0)',
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0)',
            'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0)'
        ]
        self.honeypot_signatures = {
            'headers': [
                'server: honeypot',
                'x-honeypot',
                'x-honey-trap'
            ],
            'responses': [
                'honeypot detected',
                'honey pot system',
                'warning: this is a monitored system'
            ],
            'banners': [
                'honeynet',
                'honeypot',
                'honeytrap'
            ]
        }
        self.scan_delays = {
            'stealth': (2.0, 5.0),    # Modo sigiloso
            'normal': (0.5, 1.0),     # Modo normal
            'aggressive': (0.1, 0.3)   # Modo agresivo
        }
        self.last_scan_time = datetime.now()
        self.scan_count = 0
        self.max_scans_per_minute = 60  # Límite de escaneos por minuto
    
    def get_random_user_agent(self) -> str:
        """Obtiene un User-Agent aleatorio de la lista."""
        return random.choice(self.user_agents)
    
    def detect_honeypot(self, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detecta si un objetivo es potencialmente un honeypot.
        
        Args:
            response_data: Datos de respuesta del objetivo
            
        Returns:
            Dict con información sobre la detección de honeypot
        """
        detection_info = {
            'is_honeypot': False,
            'confidence': 0.0,
            'indicators': []
        }
        
        # Analizar headers
        headers = response_data.get('headers', {})
        for header, value in headers.items():
            for signature in self.honeypot_signatures['headers']:
                if signature.lower() in str(value).lower():
                    detection_info['indicators'].append(f'Header sospechoso: {header}')
                    detection_info['confidence'] += 0.3
        
        # Analizar respuesta del servidor
        response_body = response_data.get('body', '')
        for signature in self.honeypot_signatures['responses']:
            if signature.lower() in str(response_body).lower():
                detection_info['indicators'].append(f'Respuesta sospechosa detectada')
                detection_info['confidence'] += 0.4
        
        # Analizar banners de servicios
        banners = response_data.get('banners', [])
        for banner in banners:
            for signature in self.honeypot_signatures['banners']:
                if signature.lower() in str(banner).lower():
                    detection_info['indicators'].append(f'Banner sospechoso: {banner}')
                    detection_info['confidence'] += 0.3
        
        # Análisis de comportamiento
        if self.analyze_behavior(response_data):
            detection_info['indicators'].append('Comportamiento sospechoso detectado')
            detection_info['confidence'] += 0.2
        
        # Normalizar confianza y establecer resultado
        detection_info['confidence'] = min(detection_info['confidence'], 1.0)
        detection_info['is_honeypot'] = detection_info['confidence'] > 0.5
        
        self.logger.info(f"Análisis de honeypot completado: {detection_info}")
        return detection_info
    
    def analyze_behavior(self, response_data: Dict[str, Any]) -> bool:
        """Analiza el comportamiento del objetivo para detectar patrones sospechosos."""
        suspicious_patterns = 0
        
        # Verificar respuestas demasiado perfectas o estructuradas
        if response_data.get('all_ports_open', False):
            suspicious_patterns += 1
        
        # Verificar tiempos de respuesta inconsistentes
        response_times = response_data.get('response_times', [])
        if response_times and all(t == response_times[0] for t in response_times):
            suspicious_patterns += 1
        
        # Verificar servicios inusuales o configuraciones sospechosas
        services = response_data.get('services', {})
        if len(services) > 20:  # Demasiados servicios activos
            suspicious_patterns += 1
        
        return suspicious_patterns >= 2
    
    def control_scan_rate(self, scan_mode: str = 'normal') -> None:
        """Controla la velocidad de escaneo según el modo seleccionado.
        
        Args:
            scan_mode: Modo de escaneo ('stealth', 'normal', 'aggressive')
        """
        current_time = datetime.now()
        time_diff = (current_time - self.last_scan_time).total_seconds()
        
        # Control de límite de escaneos por minuto
        if time_diff < 60 and self.scan_count >= self.max_scans_per_minute:
            sleep_time = 60 - time_diff
            self.logger.warning(f"Límite de escaneos alcanzado, esperando {sleep_time:.2f} segundos")
            time.sleep(sleep_time)
            self.scan_count = 0
            self.last_scan_time = datetime.now()
        
        # Aplicar delay según el modo de escaneo
        min_delay, max_delay = self.scan_delays.get(scan_mode, self.scan_delays['normal'])
        delay = random.uniform(min_delay, max_delay)
        time.sleep(delay)
        
        self.scan_count += 1
        if time_diff >= 60:
            self.scan_count = 1
            self.last_scan_time = current_time
    
    def get_security_headers(self) -> Dict[str, str]:
        """Obtiene headers seguros para las peticiones HTTP."""
        return {
            'User-Agent': self.get_random_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'close'
        }