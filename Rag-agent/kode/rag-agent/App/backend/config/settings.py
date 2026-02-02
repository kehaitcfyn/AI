"""
Konfigurationsindstillinger for AI Chat RAG API
================================================
Inkluderer JWT authentication, Azure AD SSO og audit logging.
"""
import os
import json
import logging
from typing import List, Dict, Optional, Union, Any
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator, model_validator
from datetime import timedelta


# ============================================================
# Logging Setup
# ============================================================
def setup_logging(level: str = "INFO") -> logging.Logger:
    """Konfigurer logging for applikationen"""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    return logging.getLogger("rag-api")


# ============================================================
# Settings Class med Validering
# ============================================================
class Settings(BaseSettings):
    """Applikationsindstillinger med automatisk environment variable loading."""
    
    # API Settings
    api_title: str = "AI Chat RAG API"
    api_version: str = "2.3.0"
    
    # Påkrævede secrets
    openai_api_key: str
    api_secret_key: str
    
    # JWT Settings
    jwt_enabled: bool = False
    jwt_secret_key: str = ""
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 60
    jwt_refresh_token_expire_days: int = 7
    
    # Azure AD / Entra ID Settings
    azure_ad_enabled: bool = False
    azure_ad_tenant_id: str = ""
    azure_ad_client_id: str = ""
    azure_ad_client_secret: str = ""
    azure_ad_redirect_uri: str = ""
    
    # Cookie Settings (for HttpOnly token storage)
    cookie_domain: Optional[str] = None  # None = current domain
    cookie_secure: bool = True  # Set to False for localhost development
    cookie_samesite: str = "lax"  # "lax" for OAuth, "strict" for max security
    
    # Audit Logging Settings
    audit_logging_enabled: bool = False
    audit_log_file: str = "/app/logs/audit.log"
    audit_log_max_size_mb: int = 100
    audit_log_backup_count: int = 5
    
    # Environment
    environment: str = "development"
    log_level: str = "INFO"
    
    # Token Begrænsninger
    max_input_tokens: int = 2500
    max_output_tokens: int = 3000
    
    # Session Management
    max_sessions: int = 1000
    session_timeout_hours: int = 2
    
    # RAG Settings
    prompt_dir: str = "/app/prompts"
    chroma_base_dir: str = "/app/chroma_collections"
    top_k: int = 3
    
    # OpenAI Settings
    openai_model: str = "gpt-4o-mini"
    openai_temperature: float = 0.2
    
    # Rate Limiting
    rate_limit_root: str = "30/minute"
    rate_limit_health: str = "60/minute"
    rate_limit_prompts: str = "20/minute"
    rate_limit_chat: str = "10/minute"
    rate_limit_history: str = "30/minute"
    rate_limit_reset: str = "10/minute"
    rate_limit_collections: str = "20/minute"
    rate_limit_auth: str = "5/minute"
    
    # CORS Origins
    # VIGTIGT: Ingen trailing slashes! Og specifikke origins (ikke "*") når credentials=True
    # Kan sættes via env som kommasepareret string: CORS_ORIGINS=http://a.com,http://b.com
    # Eller som JSON array: CORS_ORIGINS=["http://a.com","http://b.com"]
    cors_origins: str = "http://chat-assistant.itcfyn.ai,https://chat-assistant.itcfyn.ai,http://localhost,http://localhost:8000,http://localhost:3000,http://127.0.0.1,http://127.0.0.1:8000"
    
    # Parsed CORS origins (populated by validator)
    _cors_origins_list: List[str] = []
    
    @model_validator(mode='after')
    def parse_cors_origins(self) -> 'Settings':
        """Parser CORS origins fra kommasepareret string eller JSON array."""
        raw_value = self.cors_origins
        
        if isinstance(raw_value, str):
            raw_value = raw_value.strip()
            # Prøv først at parse som JSON array
            if raw_value.startswith('['):
                try:
                    parsed = json.loads(raw_value)
                    if isinstance(parsed, list):
                        self._cors_origins_list = [str(origin).strip().rstrip('/') for origin in parsed if origin and str(origin).strip()]
                        return self
                except json.JSONDecodeError:
                    pass
            # Fallback til kommasepareret string
            self._cors_origins_list = [origin.strip().rstrip('/') for origin in raw_value.split(',') if origin.strip()]
        elif isinstance(raw_value, list):
            self._cors_origins_list = [str(origin).strip().rstrip('/') for origin in raw_value if origin and str(origin).strip()]
        else:
            self._cors_origins_list = []
        
        return self
    
    def get_cors_origins(self) -> List[str]:
        """Returnerer parsed CORS origins som liste."""
        return self._cors_origins_list if self._cors_origins_list else [
            "http://chat-assistant.itcfyn.ai",
            "https://chat-assistant.itcfyn.ai",
            "http://localhost",
            "http://localhost:8000",
            "http://localhost:3000",
            "http://127.0.0.1",
            "http://127.0.0.1:8000",
        ]
    
    # Tilladte IP-ranges
    # Kan sættes via env som kommasepareret string: ALLOWED_IPS=172.16.0.0/12,127.0.0.1/32
    allowed_ips: str = "172.16.0.0/12,127.0.0.1/32"
    
    # Parsed allowed IPs (populated by validator)
    _allowed_ips_list: List[str] = []
    
    @model_validator(mode='after')
    def parse_allowed_ips(self) -> 'Settings':
        """Parser allowed IPs fra kommasepareret string eller JSON array."""
        raw_value = self.allowed_ips
        
        if isinstance(raw_value, str):
            raw_value = raw_value.strip()
            # Prøv først at parse som JSON array
            if raw_value.startswith('['):
                try:
                    parsed = json.loads(raw_value)
                    if isinstance(parsed, list):
                        self._allowed_ips_list = [str(ip).strip() for ip in parsed if ip and str(ip).strip()]
                        return self
                except json.JSONDecodeError:
                    pass
            # Fallback til kommasepareret string
            self._allowed_ips_list = [ip.strip() for ip in raw_value.split(',') if ip.strip()]
        elif isinstance(raw_value, list):
            self._allowed_ips_list = [str(ip).strip() for ip in raw_value if ip and str(ip).strip()]
        else:
            self._allowed_ips_list = []
        
        return self
    
    def get_allowed_ips(self) -> List[str]:
        """Returnerer parsed allowed IPs som liste."""
        return self._allowed_ips_list if self._allowed_ips_list else [
            "172.16.0.0/12",
            "127.0.0.1/32",
        ]
    
    @field_validator('openai_api_key')
    @classmethod
    def validate_openai_key(cls, v: str) -> str:
        if not v or not v.startswith('sk-'):
            raise ValueError("Ugyldig OpenAI API key format")
        return v
    
    @field_validator('api_secret_key')
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        if not v or len(v) < 16:
            raise ValueError("API_SECRET_KEY skal være mindst 16 karakterer")
        return v
    
    def validate_jwt_config(self):
        """Valider JWT config ved runtime"""
        if self.jwt_enabled and (not self.jwt_secret_key or len(self.jwt_secret_key) < 32):
            raise ValueError("JWT_SECRET_KEY skal være mindst 32 karakterer når JWT er aktiveret")
    
    def validate_azure_config(self):
        """Valider Azure AD config ved runtime"""
        if self.azure_ad_enabled:
            missing = []
            if not self.azure_ad_tenant_id:
                missing.append("AZURE_AD_TENANT_ID")
            if not self.azure_ad_client_id:
                missing.append("AZURE_AD_CLIENT_ID")
            if not self.azure_ad_client_secret:
                missing.append("AZURE_AD_CLIENT_SECRET")
            if not self.azure_ad_redirect_uri:
                missing.append("AZURE_AD_REDIRECT_URI")
            
            if missing:
                raise ValueError(f"Azure AD er aktiveret men mangler: {', '.join(missing)}")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


# ============================================================
# Token Pricing
# ============================================================
TOKEN_PRICING: Dict[str, Dict[str, float]] = {
    "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
    "gpt-4o": {"input": 0.0025, "output": 0.01},
    "gpt-4-turbo": {"input": 0.01, "output": 0.03},
    "gpt-3.5-turbo": {"input": 0.0005, "output": 0.0015},
}


def get_token_cost(model: str, input_tokens: int, output_tokens: int) -> Dict[str, float]:
    """Beregn token-omkostninger baseret på model og forbrug."""
    pricing = TOKEN_PRICING.get(model, TOKEN_PRICING["gpt-4o-mini"])
    input_cost = (input_tokens / 1000) * pricing["input"]
    output_cost = (output_tokens / 1000) * pricing["output"]
    total_cost = input_cost + output_cost
    return {
        "input_cost": round(input_cost, 6),
        "output_cost": round(output_cost, 6),
        "total_cost": round(total_cost, 6),
    }


# ============================================================
# Initialize Settings
# ============================================================
try:
    settings = Settings()
    settings.validate_jwt_config()
    settings.validate_azure_config()
except Exception as e:
    print(f"❌ Fejl ved indlæsning af settings: {e}")
    raise

logger = setup_logging(settings.log_level)

# ============================================================
# Exports
# ============================================================
API_TITLE = settings.api_title
API_VERSION = settings.api_version
API_SECRET_KEY = settings.api_secret_key
MAX_INPUT_TOKENS = settings.max_input_tokens
MAX_OUTPUT_TOKENS = settings.max_output_tokens
MAX_SESSIONS = settings.max_sessions
SESSION_TIMEOUT_HOURS = settings.session_timeout_hours
CORS_ORIGINS = settings.get_cors_origins()
ALLOWED_IPS = settings.get_allowed_ips()
PROMPT_DIR = settings.prompt_dir
CHROMA_BASE_DIR = settings.chroma_base_dir
TOP_K = settings.top_k
OPENAI_MODEL = settings.openai_model
OPENAI_TEMPERATURE = settings.openai_temperature

# JWT
JWT_ENABLED = settings.jwt_enabled
JWT_SECRET_KEY = settings.jwt_secret_key
JWT_ALGORITHM = settings.jwt_algorithm
JWT_ACCESS_TOKEN_EXPIRE = timedelta(minutes=settings.jwt_access_token_expire_minutes)
JWT_REFRESH_TOKEN_EXPIRE = timedelta(days=settings.jwt_refresh_token_expire_days)

# Azure AD
AZURE_AD_ENABLED = settings.azure_ad_enabled
AZURE_AD_TENANT_ID = settings.azure_ad_tenant_id
AZURE_AD_CLIENT_ID = settings.azure_ad_client_id

# Cookie Settings
COOKIE_DOMAIN = settings.cookie_domain
COOKIE_SECURE = settings.cookie_secure
COOKIE_SAMESITE = settings.cookie_samesite

# Audit
AUDIT_LOGGING_ENABLED = settings.audit_logging_enabled
AUDIT_LOG_FILE = settings.audit_log_file
AUDIT_LOG_MAX_SIZE_MB = settings.audit_log_max_size_mb
AUDIT_LOG_BACKUP_COUNT = settings.audit_log_backup_count

RATE_LIMITS = {
    "root": settings.rate_limit_root,
    "health": settings.rate_limit_health,
    "prompts": settings.rate_limit_prompts,
    "chat": settings.rate_limit_chat,
    "history": settings.rate_limit_history,
    "reset": settings.rate_limit_reset,
    "collections": settings.rate_limit_collections,
    "auth": settings.rate_limit_auth,
}
