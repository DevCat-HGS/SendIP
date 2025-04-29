import asyncio
import ipaddress
import ssl
import aiohttp
import geoip2.database
import geoip2.errors
from typing import List, Dict, Any
from datetime import datetime
from colorama import Fore

class ScannerUtils:
    def __init__(self):
        self.waf_signatures = {
            'Cloudflare': ['__cfduid', 'cf-ray', 'cloudflare'],
            'AWS WAF': ['awselb', 'x-amz-cf-id'],
            'ModSecurity': ['mod_security', 'NOYB'],
            'Imperva': ['incap_ses', '_incapsula_'],
            'Akamai': ['akamai-', 'x-akamai-'],
        }

    async def scan_target_async(self, target: str) -> Dict[str, Any]:
        try:
            # Convertir CIDR a lista de IPs si es necesario
            ips = self._parse_target(target)
            results = []
            
            # Crear tareas asíncronas para cada IP
            tasks = [self._scan_single_ip(ip) for ip in ips]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            return {
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'results': [r for r in results if not isinstance(r, Exception)]
            }
        except Exception as e:
            print(f"{Fore.RED}[!] Error escaneando {target}: {str(e)}")
            return {'target': target, 'error': str(e)}

    def _parse_target(self, target: str) -> List[str]:
        try:
            # Verificar si es una notación CIDR
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                return [str(ip) for ip in network.hosts()]
            return [target]
        except ValueError as e:
            raise ValueError(f"Formato de IP/CIDR inválido: {str(e)}")

    async def _scan_single_ip(self, ip: str) -> Dict[str, Any]:
        result = {
            'ip': ip,
            'waf_detection': await self._detect_waf(ip),
            'ssl_info': await self._analyze_ssl(ip),
            'geolocation': self._get_geolocation(ip)
        }
        return result

    async def _detect_waf(self, ip: str) -> Dict[str, Any]:
        try:
            async with aiohttp.ClientSession() as session:
                urls = [f'http://{ip}', f'https://{ip}']
                waf_detected = {'detected': False, 'waf_type': None}

                for url in urls:
                    try:
                        async with session.get(url, timeout=5) as response:
                            headers = dict(response.headers)
                            
                            # Analizar headers en busca de firmas WAF
                            for waf_name, signatures in self.waf_signatures.items():
                                if any(sig.lower() in str(headers).lower() for sig in signatures):
                                    waf_detected = {
                                        'detected': True,
                                        'waf_type': waf_name,
                                        'evidence': headers
                                    }
                                    break
                    except:
                        continue

                return waf_detected
        except Exception as e:
            return {'error': f'Error en detección WAF: {str(e)}'}

    async def _analyze_ssl(self, ip: str) -> Dict[str, Any]:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(f'https://{ip}', ssl=context, timeout=5) as response:
                        ssl_info = response.connection.transport.get_extra_info('ssl_object')
                        if ssl_info:
                            return {
                                'version': ssl_info.version(),
                                'cipher': ssl_info.cipher(),
                                'issuer': dict(ssl_info.get_issuer().get_components()),
                                'subject': dict(ssl_info.get_subject().get_components()),
                                'not_before': ssl_info.get_notBefore(),
                                'not_after': ssl_info.get_notAfter()
                            }
                except:
                    return {'error': 'No se pudo obtener información SSL'}
        except Exception as e:
            return {'error': f'Error en análisis SSL: {str(e)}'}

    def _get_geolocation(self, ip: str) -> Dict[str, Any]:
        try:
            # Usar base de datos GeoIP2
            with geoip2.database.Reader('GeoLite2-City.mmdb') as reader:
                response = reader.city(ip)
                return {
                    'country': response.country.name,
                    'city': response.city.name,
                    'latitude': response.location.latitude,
                    'longitude': response.location.longitude,
                    'timezone': response.location.time_zone
                }
        except geoip2.errors.AddressNotFoundError:
            return {'error': 'IP no encontrada en la base de datos'}
        except Exception as e:
            return {'error': f'Error en geolocalización: {str(e)}'}