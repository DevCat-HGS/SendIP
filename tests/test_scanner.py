import unittest
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cache_manager import CacheManager
from logger_config import LoggerConfig
from security_utils import SecurityUtils
from connection_manager import ConnectionManager
from scanner_utils import ScannerUtils

class TestScanner(unittest.TestCase):
    def setUp(self):
        """Configuración inicial para las pruebas."""
        self.cache = CacheManager()
        self.logger = LoggerConfig.get_logger('test')
        self.security = SecurityUtils()
        self.connection = ConnectionManager()
        self.scanner = ScannerUtils()
    
    def test_cache_operations(self):
        """Prueba las operaciones básicas de caché."""
        test_data = {'test': 'data'}
        
        # Probar almacenamiento en caché
        self.assertTrue(self.cache.set('test_target', test_data))
        
        # Probar recuperación de caché
        cached_data = self.cache.get('test_target')
        self.assertEqual(cached_data, test_data)
        
        # Probar limpieza de caché
        self.assertTrue(self.cache.clear())
        self.assertIsNone(self.cache.get('test_target'))
    
    def test_security_features(self):
        """Prueba las características de seguridad."""
        # Probar rotación de User-Agent
        user_agent = self.security.get_random_user_agent()
        self.assertIsInstance(user_agent, str)
        self.assertGreater(len(user_agent), 0)
        
        # Probar detección de honeypot
        test_response = {
            'headers': {'server': 'honeypot'},
            'body': 'test body',
            'banners': ['test banner']
        }
        detection = self.security.detect_honeypot(test_response)
        self.assertTrue(detection['is_honeypot'])
        
        # Probar headers seguros
        headers = self.security.get_security_headers()
        self.assertIn('User-Agent', headers)
        self.assertIn('DNT', headers)
    
    def test_connection_management(self):
        """Prueba la gestión de conexiones."""
        # Probar optimización de timeout
        timeout = self.connection.optimize_timeout('localhost', 80)
        self.assertIsInstance(timeout, float)
        self.assertGreaterEqual(timeout, self.connection.base_timeout)
        
        # Probar estadísticas de conexión
        stats = self.connection.get_connection_stats()
        self.assertIn('attempts', stats)
        self.assertIn('successes', stats)
        self.assertIn('failures', stats)
    
    def test_scanner_utils(self):
        """Prueba las utilidades del scanner."""
        # Probar parsing de objetivo
        ips = self.scanner._parse_target('192.168.1.1')
        self.assertEqual(len(ips), 1)
        self.assertEqual(ips[0], '192.168.1.1')
        
        # Probar parsing de CIDR
        ips = self.scanner._parse_target('192.168.1.0/30')
        self.assertEqual(len(ips), 2)  # Debería devolver 2 IPs utilizables
    
    def test_logger_config(self):
        """Prueba la configuración del logger."""
        # Probar obtención de logger
        test_logger = LoggerConfig.get_logger('test_module')
        self.assertIsNotNone(test_logger)
        
        # Probar logging en diferentes niveles
        test_logger.debug('Test debug message')
        test_logger.info('Test info message')
        test_logger.warning('Test warning message')
        test_logger.error('Test error message')
        
        # Probar estadísticas de log
        logger_config = LoggerConfig()
        stats = logger_config.get_log_stats()
        self.assertIsInstance(stats, dict)

if __name__ == '__main__':
    unittest.main()