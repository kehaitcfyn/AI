"""
Health Router - Enhanced health check endpoints med dependency checks
"""
import os
from fastapi import APIRouter, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from backend.models import HealthResponse
from backend.services import chat_service
from backend.config import logger, API_TITLE, API_VERSION

# Opret router
router = APIRouter(tags=["Health"])

# Rate limiter
limiter = Limiter(key_func=get_remote_address)


@router.get("/", response_model=HealthResponse)
@limiter.limit("30/minute")
async def root(request: Request):
    """
    Root endpoint - simpel health check.
    
    Returnerer API navn og status.
    """
    return HealthResponse(
        status="healthy",
        service=f"{API_TITLE} v{API_VERSION}"
    )


@router.get("/health", response_model=HealthResponse)
@limiter.limit("60/minute")
async def health_check(request: Request):
    """
    Detaljeret health check med dependency verification.
    
    Checker:
    - API status
    - ChromaDB tilgængelighed
    - OpenAI API key tilstedeværelse
    - Session statistik
    
    Returns:
        HealthResponse med status og checks dict
    """
    checks = {
        "api": "healthy",
        "chroma": "unknown",
        "openai": "unknown",
        "sessions": "unknown",
    }
    
    details = {}
    
    # Check ChromaDB
    try:
        collections = chat_service.list_collections()
        checks["chroma"] = "healthy"
        details["chroma_collections"] = len(collections)
    except Exception as e:
        checks["chroma"] = "unhealthy"
        details["chroma_error"] = str(e)
        logger.error(f"Health check - ChromaDB fejl: {e}")
    
    # Check OpenAI (verificer at API key eksisterer og har korrekt format)
    try:
        api_key = os.getenv("OPENAI_API_KEY", "")
        if api_key and api_key.startswith("sk-"):
            checks["openai"] = "healthy"
            details["openai_key_present"] = True
        else:
            checks["openai"] = "unhealthy"
            details["openai_key_present"] = False
    except Exception as e:
        checks["openai"] = "unhealthy"
        details["openai_error"] = str(e)
        logger.error(f"Health check - OpenAI fejl: {e}")
    
    # Check sessions
    try:
        session_stats = chat_service.get_session_stats()
        checks["sessions"] = "healthy"
        details["sessions"] = session_stats
    except Exception as e:
        checks["sessions"] = "unhealthy"
        details["sessions_error"] = str(e)
        logger.error(f"Health check - Sessions fejl: {e}")
    
    # Bestem overordnet status
    if all(v == "healthy" for v in checks.values()):
        overall_status = "healthy"
    elif checks["api"] == "healthy" and checks["openai"] == "healthy":
        overall_status = "degraded"
    else:
        overall_status = "unhealthy"
    
    # Log hvis ikke healthy
    if overall_status != "healthy":
        logger.warning(f"Health check status: {overall_status}, checks: {checks}")
    
    return HealthResponse(
        status=overall_status,
        service=f"{API_TITLE} v{API_VERSION}",
        checks={**checks, "details": details}
    )


@router.get("/health/live")
@limiter.limit("120/minute")
async def liveness_probe(request: Request):
    """
    Kubernetes liveness probe - simpelt tjek om API'et kører.
    
    Returns:
        {"status": "alive"}
    """
    return {"status": "alive"}


@router.get("/health/ready")
@limiter.limit("60/minute")
async def readiness_probe(request: Request):
    """
    Kubernetes readiness probe - tjek om API'et er klar til trafik.
    
    Returns:
        {"status": "ready"} eller {"status": "not_ready", "reason": "..."}
    """
    # Check kritiske dependencies
    try:
        # Må kunne liste collections
        chat_service.list_collections()
        
        # OpenAI key skal være sat
        api_key = os.getenv("OPENAI_API_KEY", "")
        if not api_key or not api_key.startswith("sk-"):
            return {"status": "not_ready", "reason": "OpenAI API key not configured"}
        
        return {"status": "ready"}
        
    except Exception as e:
        logger.error(f"Readiness check fejlede: {e}")
        return {"status": "not_ready", "reason": str(e)}
