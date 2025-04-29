import logging
import logging.handlers
import os
from datetime import datetime
from typing import Optional

class LoggerConfig:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
            
        self._initialized = True
        self.log_dir = 'logs'
        self.ensure_log_directory()
        self.setup_logging()
    
    def ensure_log_directory(self) -> None:
        """Asegura que el directorio de logs existe."""
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
    
    def setup_logging(self) -> None:
        """Configura el sistema de logging con rotación de archivos y diferentes niveles."""
        # Configurar el logger principal
        logger = logging.getLogger('sendip')
        logger.setLevel(logging.DEBUG)
        
        # Formato común para todos los handlers
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Handler para archivo de debug con rotación
        debug_handler = logging.handlers.RotatingFileHandler(
            os.path.join(self.log_dir, 'debug.log'),
            maxBytes=5*1024*1024,  # 5MB
            backupCount=5
        )
        debug_handler.setLevel(logging.DEBUG)
        debug_handler.setFormatter(formatter)
        
        # Handler para archivo de errores con rotación
        error_handler = logging.handlers.RotatingFileHandler(
            os.path.join(self.log_dir, 'error.log'),
            maxBytes=5*1024*1024,  # 5MB
            backupCount=5
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(formatter)
        
        # Handler para la consola
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        
        # Agregar todos los handlers al logger
        logger.addHandler(debug_handler)
        logger.addHandler(error_handler)
        logger.addHandler(console_handler)
    
    @staticmethod
    def get_logger(name: Optional[str] = None) -> logging.Logger:
        """Obtiene un logger configurado.
        
        Args:
            name: Nombre del logger. Si es None, se usa el logger principal.
            
        Returns:
            logging.Logger: Logger configurado
        """
        if name:
            return logging.getLogger(f'sendip.{name}')
        return logging.getLogger('sendip')
    
    def set_log_level(self, level: int) -> None:
        """Cambia el nivel de logging.
        
        Args:
            level: Nivel de logging (e.g., logging.DEBUG, logging.INFO)
        """
        logger = logging.getLogger('sendip')
        logger.setLevel(level)
    
    def get_log_stats(self) -> dict:
        """Obtiene estadísticas de los archivos de log.
        
        Returns:
            dict: Estadísticas de los archivos de log
        """
        stats = {}
        for log_file in ['debug.log', 'error.log']:
            path = os.path.join(self.log_dir, log_file)
            if os.path.exists(path):
                stats[log_file] = {
                    'size': os.path.getsize(path),
                    'last_modified': datetime.fromtimestamp(
                        os.path.getmtime(path)
                    ).isoformat()
                }
        return stats