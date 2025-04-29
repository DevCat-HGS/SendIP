import sqlite3
import json
from datetime import datetime, timedelta
import threading
import logging
from typing import Dict, Any, Optional

class CacheManager:
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
            
        self._initialized = True
        self.db_path = 'scan_cache.db'
        self.cache_duration = timedelta(hours=24)  # Duración predeterminada de la caché
        self.setup_logging()
        self.initialize_db()
    
    def setup_logging(self):
        """Configura el sistema de logging para la caché."""
        self.logger = logging.getLogger('cache_manager')
        self.logger.setLevel(logging.INFO)
        
        handler = logging.FileHandler('cache.log')
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
    
    def initialize_db(self):
        """Inicializa la base de datos SQLite para la caché."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_cache (
                    target TEXT PRIMARY KEY,
                    data TEXT,
                    timestamp DATETIME,
                    expiry DATETIME
                )
                """)
                conn.commit()
            self.logger.info('Base de datos de caché inicializada correctamente')
        except Exception as e:
            self.logger.error(f'Error al inicializar la base de datos: {str(e)}')
    
    def get(self, target: str) -> Optional[Dict[str, Any]]:
        """Obtiene resultados almacenados en caché para un objetivo específico."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                SELECT data, expiry FROM scan_cache 
                WHERE target = ? AND expiry > datetime('now')
                """, (target,))
                result = cursor.fetchone()
                
                if result:
                    self.logger.info(f'Caché encontrada para {target}')
                    return json.loads(result[0])
                return None
        except Exception as e:
            self.logger.error(f'Error al obtener datos de caché: {str(e)}')
            return None
    
    def set(self, target: str, data: Dict[str, Any], duration: Optional[timedelta] = None) -> bool:
        """Almacena resultados en caché para un objetivo específico."""
        try:
            if duration is None:
                duration = self.cache_duration
                
            expiry = datetime.now() + duration
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                INSERT OR REPLACE INTO scan_cache (target, data, timestamp, expiry)
                VALUES (?, ?, datetime('now'), ?)
                """, (target, json.dumps(data), expiry.isoformat()))
                conn.commit()
                
            self.logger.info(f'Datos almacenados en caché para {target}')
            return True
        except Exception as e:
            self.logger.error(f'Error al almacenar datos en caché: {str(e)}')
            return False
    
    def cleanup(self) -> None:
        """Limpia las entradas expiradas de la caché."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM scan_cache WHERE expiry <= datetime('now')")
                conn.commit()
                
            self.logger.info('Limpieza de caché completada')
        except Exception as e:
            self.logger.error(f'Error durante la limpieza de caché: {str(e)}')
    
    def clear(self) -> bool:
        """Limpia toda la caché."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM scan_cache")
                conn.commit()
                
            self.logger.info('Caché limpiada completamente')
            return True
        except Exception as e:
            self.logger.error(f'Error al limpiar la caché: {str(e)}')
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Obtiene estadísticas de la caché."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                SELECT 
                    COUNT(*) as total,
                    COUNT(CASE WHEN expiry > datetime('now') THEN 1 END) as valid,
                    COUNT(CASE WHEN expiry <= datetime('now') THEN 1 END) as expired
                FROM scan_cache
                """)
                total, valid, expired = cursor.fetchone()
                
                return {
                    'total_entries': total,
                    'valid_entries': valid,
                    'expired_entries': expired,
                    'database_size': os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0
                }
        except Exception as e:
            self.logger.error(f'Error al obtener estadísticas: {str(e)}')
            return {
                'error': str(e)
            }