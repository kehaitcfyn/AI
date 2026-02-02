"""
Config Package - Eksporter alle konfigurationsindstillinger
"""
from backend.config.settings import (
    # Settings instance og logger
    settings,
    logger,
    
    # Token pricing
    TOKEN_PRICING,
    get_token_cost,
    
    # API Settings
    API_TITLE,
    API_VERSION,
    
    # Sikkerhed
    API_SECRET_KEY,
    CORS_ORIGINS,
    ALLOWED_IPS,
    
    # Token Limits
    MAX_INPUT_TOKENS,
    MAX_OUTPUT_TOKENS,
    
    # Session Management
    MAX_SESSIONS,
    SESSION_TIMEOUT_HOURS,
    
    # RAG Settings
    PROMPT_DIR,
    CHROMA_BASE_DIR,
    TOP_K,
    
    # OpenAI Settings
    OPENAI_MODEL,
    OPENAI_TEMPERATURE,
    
    # Rate Limits
    RATE_LIMITS,
    
    # JWT Settings
    JWT_ENABLED,
    JWT_SECRET_KEY,
    JWT_ALGORITHM,
    JWT_ACCESS_TOKEN_EXPIRE,
    JWT_REFRESH_TOKEN_EXPIRE,
    
    # Azure AD Settings
    AZURE_AD_ENABLED,
    AZURE_AD_TENANT_ID,
    AZURE_AD_CLIENT_ID,
    
    # Cookie Settings (HttpOnly token security)
    COOKIE_DOMAIN,
    COOKIE_SECURE,
    COOKIE_SAMESITE,
    
    # Audit Logging Settings
    AUDIT_LOGGING_ENABLED,
    AUDIT_LOG_FILE,
    AUDIT_LOG_MAX_SIZE_MB,
    AUDIT_LOG_BACKUP_COUNT,
)

__all__ = [
    "settings",
    "logger",
    "TOKEN_PRICING",
    "get_token_cost",
    "API_TITLE",
    "API_VERSION",
    "API_SECRET_KEY",
    "CORS_ORIGINS",
    "ALLOWED_IPS",
    "MAX_INPUT_TOKENS",
    "MAX_OUTPUT_TOKENS",
    "MAX_SESSIONS",
    "SESSION_TIMEOUT_HOURS",
    "PROMPT_DIR",
    "CHROMA_BASE_DIR",
    "TOP_K",
    "OPENAI_MODEL",
    "OPENAI_TEMPERATURE",
    "RATE_LIMITS",
    "JWT_ENABLED",
    "JWT_SECRET_KEY",
    "JWT_ALGORITHM",
    "JWT_ACCESS_TOKEN_EXPIRE",
    "JWT_REFRESH_TOKEN_EXPIRE",
    "AZURE_AD_ENABLED",
    "AZURE_AD_TENANT_ID",
    "AZURE_AD_CLIENT_ID",
    "COOKIE_DOMAIN",
    "COOKIE_SECURE",
    "COOKIE_SAMESITE",
    "AUDIT_LOGGING_ENABLED",
    "AUDIT_LOG_FILE",
    "AUDIT_LOG_MAX_SIZE_MB",
    "AUDIT_LOG_BACKUP_COUNT",
]
