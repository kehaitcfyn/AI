"""
AI Chat RAG API - Main Application
===================================
FastAPI applikation med RAG (Retrieval Augmented Generation) funktionalitet.

Features:
- RAG-baseret chat med ChromaDB
- JWT Authentication (valgfri)
- Audit Logging (valgfri)
- Rate Limiting
- Session Management
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Import config
from backend.config import (
    API_TITLE,
    API_VERSION,
    CORS_ORIGINS,
    MAX_INPUT_TOKENS,
    MAX_OUTPUT_TOKENS,
    JWT_ENABLED,
    AUDIT_LOGGING_ENABLED,
    logger,
)

# Import middleware
from backend.middleware import verify_internal_ip, verify_internal_secret

# Import routers
from backend.routers import (
    chat_router,
    prompts_router,
    collections_router,
    health_router,
    auth_router,
)


# ============================================================
# Lifespan Context Manager
# ============================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Håndterer startup og shutdown events."""
    # Startup
    logger.info("=" * 60)
    logger.info(f"🚀 {API_TITLE} v{API_VERSION} starting...")
    logger.info("=" * 60)
    logger.info("✅ Internal secret loaded: [REDACTED]")
    logger.info(f"✅ Token limits: Input={MAX_INPUT_TOKENS}, Output={MAX_OUTPUT_TOKENS}")
    logger.info(f"✅ JWT Authentication: {'ENABLED' if JWT_ENABLED else 'DISABLED'}")
    logger.info(f"✅ Audit Logging: {'ENABLED' if AUDIT_LOGGING_ENABLED else 'DISABLED'}")
    logger.info("✅ All routers registered")
    logger.info("=" * 60)
    
    yield
    
    # Shutdown
    logger.info("🛑 Shutting down...")
    logger.info("=" * 60)


# ============================================================
# App Initialization
# ============================================================
app = FastAPI(
    title=API_TITLE,
    version=API_VERSION,
    description="""
AI Chat API med RAG (Retrieval Augmented Generation) funktionalitet.

## Features

- **RAG Chat**: Intelligent chat med dokument-kontekst fra ChromaDB
- **JWT Authentication**: Valgfri bruger-authentication (aktiver med JWT_ENABLED=true)
- **Audit Logging**: Request logging til fil (aktiver med AUDIT_LOGGING_ENABLED=true)
- **Rate Limiting**: Beskyttelse mod misbrug
- **Session Management**: Automatisk cleanup af inaktive sessions

## Authentication

Hvis JWT er aktiveret:
1. Login via `/auth/login` med username/password
2. Brug `Authorization: Bearer <token>` header på alle requests
3. Refresh token via `/auth/refresh` før udløb
    """,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)


# ============================================================
# Rate Limiter Setup
# ============================================================
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# ============================================================
# Middleware (rækkefølge er vigtig!)
# ============================================================
# 1. IP Whitelist - første check
app.middleware("http")(verify_internal_ip)

# 2. Secret verification - andet check
app.middleware("http")(verify_internal_secret)

# 3. CORS middleware
# VIGTIGT: For HttpOnly cookies + CSRF protection kræves:
# - allow_credentials=True (for at sende cookies)
# - Specifikke origins (ikke "*" når credentials=True)
# - X-CSRF-Token header tilladt
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,  # KRITISK: Tillader cookies at blive sendt
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=[
        "Content-Type",
        "X-Internal-Secret",
        "Authorization",
        "X-CSRF-Token",  # KRITISK: Tillader CSRF token header
    ],
    expose_headers=[
        "X-CSRF-Token",  # Tillader frontend at læse denne header i response
    ],
    max_age=3600,
)


# ============================================================
# Include Routers
# ============================================================
app.include_router(health_router)
app.include_router(auth_router)  # Authentication endpoints
app.include_router(prompts_router)
app.include_router(collections_router)
app.include_router(chat_router)


# ============================================================
# For development/testing
# ============================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
