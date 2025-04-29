import socket
import time
import random
from typing import Optional, Tuple, Any
import logging
from datetime import datetime

class ConnectionManager:
    def __init__(self):
        self.logger = logging.getLogger('sendip.connection')
        self.max_retries = 3
        self.base_timeout = 1.0
        self.max_timeout = 10.0
        self.jitter = 0.1
        
        # Estadísticas de conexión
        self.connection_stats = {
            'attempts': 0,
            'successes': 0,
            'failures': 0,
            'total_retry_time': 0.0
        }
    
    def connect_with_retry(self, host: str, port: int) -> Tuple[Optional[socket.socket], bool]:
        """Intenta establecer una conexión con reintentos y backoff exponencial.
        
        Args:
            host: Host objetivo
            port: Puerto objetivo
            
        Returns:
            Tuple[Optional[socket.socket], bool]: Socket y estado de éxito
        """
        attempt = 0
        start_time = time.time()
        self.connection_stats['attempts'] += 1
        
        while attempt < self.max_retries:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                timeout = min(self.base_timeout * (2 ** attempt) + random.uniform(0, self.jitter),
                             self.max_timeout)
                sock.settimeout(timeout)
                
                self.logger.debug(f"Intento {attempt + 1} de conexión a {host}:{port} (timeout: {timeout:.2f}s)")
                result = sock.connect_ex((host, port))
                
                if result == 0:
                    self.connection_stats['successes'] += 1
                    self.logger.info(f"Conexión exitosa a {host}:{port}")
                    return sock, True
                
                sock.close()
                
            except Exception as e:
                self.logger.warning(f"Error en intento {attempt + 1}: {str(e)}")
                if sock:
                    sock.close()
            
            attempt += 1
            if attempt < self.max_retries:
                wait_time = min(self.base_timeout * (2 ** attempt), self.max_timeout)
                time.sleep(wait_time)
                self.connection_stats['total_retry_time'] += wait_time
        
        self.connection_stats['failures'] += 1
        self.logger.error(f"No se pudo establecer conexión con {host}:{port} después de {self.max_retries} intentos")
        return None, False
    
    def get_connection_stats(self) -> dict:
        """Obtiene estadísticas de las conexiones realizadas.
        
        Returns:
            dict: Estadísticas de conexión
        """
        stats = self.connection_stats.copy()
        stats['success_rate'] = (
            (stats['successes'] / stats['attempts']) * 100
            if stats['attempts'] > 0 else 0
        )
        stats['average_retry_time'] = (
            stats['total_retry_time'] / stats['attempts']
            if stats['attempts'] > 0 else 0
        )
        return stats
    
    def reset_stats(self) -> None:
        """Reinicia las estadísticas de conexión."""
        self.connection_stats = {
            'attempts': 0,
            'successes': 0,
            'failures': 0,
            'total_retry_time': 0.0
        }
    
    def optimize_timeout(self, host: str, port: int) -> float:
        """Optimiza el timeout base según el rendimiento de la conexión.
        
        Args:
            host: Host objetivo
            port: Puerto objetivo
            
        Returns:
            float: Timeout optimizado
        """
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.base_timeout)
            result = sock.connect_ex((host, port))
            connection_time = time.time() - start_time
            
            if result == 0:
                # Ajustar timeout basado en el tiempo de conexión real
                optimized_timeout = min(max(connection_time * 2, self.base_timeout),
                                      self.max_timeout)
                self.logger.info(f"Timeout optimizado para {host}:{port}: {optimized_timeout:.2f}s")
                return optimized_timeout
            
        except Exception as e:
            self.logger.warning(f"Error al optimizar timeout: {str(e)}")
        finally:
            if 'sock' in locals():
                sock.close()
        
        return self.base_timeout