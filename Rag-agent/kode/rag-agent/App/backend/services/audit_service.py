"""
Audit Logging Service
=====================
Logger alle API requests til en flad fil for audit formål.
Kan slås til/fra via AUDIT_LOGGING_ENABLED environment variable.
"""
import os
import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any
from logging.handlers import RotatingFileHandler

from backend.config import (
    AUDIT_LOGGING_ENABLED,
    AUDIT_LOG_FILE,
    AUDIT_LOG_MAX_SIZE_MB,
    AUDIT_LOG_BACKUP_COUNT,
    logger as app_logger,
)


class AuditLogger:
    """
    Audit logger til at tracke alle API requests.
    
    Logger følgende information:
    - Timestamp
    - User ID (fra JWT eller 'anonymous')
    - IP adresse
    - HTTP metode
    - Endpoint
    - Request body (saniteret)
    - Response status
    - Response time
    - Token forbrug (for chat requests)
    """
    
    def __init__(self):
        self._logger: Optional[logging.Logger] = None
        self._enabled = AUDIT_LOGGING_ENABLED
        
        if self._enabled:
            self._setup_logger()
    
    def _setup_logger(self):
        """Konfigurer audit logger med rotating file handler"""
        try:
            # Opret log directory hvis det ikke findes
            log_dir = os.path.dirname(AUDIT_LOG_FILE)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
            
            # Opret dedicated logger for audit
            self._logger = logging.getLogger("audit")
            self._logger.setLevel(logging.INFO)
            self._logger.propagate = False  # Undgå dobbelt logging
            
            # Fjern eksisterende handlers
            self._logger.handlers = []
            
            # Rotating file handler
            max_bytes = AUDIT_LOG_MAX_SIZE_MB * 1024 * 1024
            handler = RotatingFileHandler(
                AUDIT_LOG_FILE,
                maxBytes=max_bytes,
                backupCount=AUDIT_LOG_BACKUP_COUNT,
                encoding='utf-8'
            )
            
            # Simpelt format - én JSON linje per entry
            handler.setFormatter(logging.Formatter('%(message)s'))
            self._logger.addHandler(handler)
            
            app_logger.info(f"✅ Audit logging aktiveret: {AUDIT_LOG_FILE}")
            
        except Exception as e:
            app_logger.error(f"❌ Kunne ikke aktivere audit logging: {e}")
            self._enabled = False
    
    @property
    def is_enabled(self) -> bool:
        """Check om audit logging er aktiveret"""
        return self._enabled and self._logger is not None
    
    def _sanitize_body(self, body: Optional[Dict]) -> Optional[Dict]:
        """
        Fjern sensitive data fra request body før logging.
        """
        if not body:
            return None
        
        sanitized = body.copy()
        
        # Felter der skal maskeres
        sensitive_fields = [
            'password', 'token', 'secret', 'api_key', 'apikey',
            'authorization', 'auth', 'credential', 'private_key'
        ]
        
        for field in sensitive_fields:
            if field in sanitized:
                sanitized[field] = '[REDACTED]'
            # Check også nested fields
            for key in list(sanitized.keys()):
                if field in key.lower():
                    sanitized[key] = '[REDACTED]'
        
        # Begræns message længde for at undgå kæmpe log entries
        if 'message' in sanitized and len(str(sanitized['message'])) > 500:
            sanitized['message'] = str(sanitized['message'])[:500] + '...[truncated]'
        
        return sanitized
    
    def log_request(
        self,
        user_id: Optional[str],
        ip_address: str,
        method: str,
        endpoint: str,
        request_body: Optional[Dict] = None,
        response_status: int = 200,
        response_time_ms: float = 0,
        token_usage: Optional[Dict] = None,
        error: Optional[str] = None,
        extra: Optional[Dict] = None,
    ):
        """
        Log en API request.
        
        Args:
            user_id: Bruger ID fra JWT eller None for anonymous
            ip_address: Klient IP adresse
            method: HTTP metode (GET, POST, etc.)
            endpoint: API endpoint path
            request_body: Request body (vil blive saniteret)
            response_status: HTTP response status code
            response_time_ms: Response tid i millisekunder
            token_usage: Token forbrug dict (for chat requests)
            error: Fejlbesked hvis relevant
            extra: Ekstra data at inkludere
        """
        if not self.is_enabled:
            return
        
        try:
            entry = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "user_id": user_id or "anonymous",
                "ip_address": ip_address,
                "method": method,
                "endpoint": endpoint,
                "status": response_status,
                "response_time_ms": round(response_time_ms, 2),
            }
            
            # Tilføj saniteret request body
            if request_body:
                entry["request_body"] = self._sanitize_body(request_body)
            
            # Tilføj token usage
            if token_usage:
                entry["token_usage"] = {
                    "input": token_usage.get("input"),
                    "output": token_usage.get("output"),
                    "cost": token_usage.get("total_cost"),
                }
            
            # Tilføj fejl
            if error:
                entry["error"] = str(error)[:500]  # Begræns fejl længde
            
            # Tilføj extra data
            if extra:
                entry["extra"] = extra
            
            # Log som JSON linje
            self._logger.info(json.dumps(entry, ensure_ascii=False))
            
        except Exception as e:
            app_logger.error(f"Audit logging fejl: {e}")
    
    def log_auth_event(
        self,
        event_type: str,
        user_id: Optional[str],
        ip_address: str,
        success: bool,
        details: Optional[str] = None,
    ):
        """
        Log authentication events (login, logout, token refresh, etc.)
        
        Args:
            event_type: Type af event (login, logout, token_refresh, etc.)
            user_id: Bruger ID
            ip_address: Klient IP
            success: Om event var succesfuld
            details: Ekstra detaljer
        """
        if not self.is_enabled:
            return
        
        try:
            entry = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "event_type": f"auth_{event_type}",
                "user_id": user_id or "unknown",
                "ip_address": ip_address,
                "success": success,
            }
            
            if details:
                entry["details"] = details[:200]
            
            self._logger.info(json.dumps(entry, ensure_ascii=False))
            
        except Exception as e:
            app_logger.error(f"Audit logging fejl: {e}")


# Singleton instance
audit_logger = AuditLogger()
