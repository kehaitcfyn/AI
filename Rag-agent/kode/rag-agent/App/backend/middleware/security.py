"""
Sikkerhedsmiddleware for API
============================
Håndterer IP whitelist og secret verification.
"""
from fastapi import Request, HTTPException
from ipaddress import ip_address, ip_network

from backend.config import API_SECRET_KEY, ALLOWED_IPS, logger


# Endpoints der ikke kræver autentificering
PUBLIC_ENDPOINTS = [
    "/health",
    "/health/live",
    "/health/ready",
    "/",
]


async def verify_internal_ip(request: Request, call_next):
    if request.url.path.startswith("/auth") or request.url.path.startswith("/prompts") or request.url.path.startswith("/health") or request.url.path.startswith("/chat") or request.url.path.startswith("/collections") or request.url.path.startswith("/history") or request.url.path.startswith("/reset"):
        return await call_next(request)
    """
    Verificer at request kommer fra tilladt IP (Docker netværk).
    Blokerer eksterne direkte forbindelser.
    """
    # Tillad public endpoints uden IP check
    if request.url.path in PUBLIC_ENDPOINTS:
        return await call_next(request)
    
    # Hent klient IP (via NGINX proxy eller direkte)
    client_ip = (
        request.headers.get("x-real-ip") or
        request.headers.get("x-forwarded-for", "").split(",")[0].strip() or
        request.client.host
    )
    
    try:
        # Check om IP er i tilladt range
        ip_obj = ip_address(client_ip)
        is_allowed = any(ip_obj in ip_network(allowed) for allowed in ALLOWED_IPS)
        
        if not is_allowed:
            logger.warning(
                f"BLOKERET - Ulovlig IP: {client_ip}, "
                f"Path: {request.url.path}, "
                f"User-Agent: {request.headers.get('user-agent', 'N/A')[:50]}"
            )
            raise HTTPException(
                status_code=403,
                detail="Access denied - external access not allowed"
            )
        
        logger.debug(f"Tilladt IP: {client_ip}")
        
    except ValueError:
        logger.warning(f"Ugyldig IP format: {client_ip}")
        raise HTTPException(
            status_code=403,
            detail="Invalid IP address"
        )
    
    return await call_next(request)


async def verify_internal_secret(request: Request, call_next):
    """
    Verificer at request kommer fra NGINX med korrekt secret token.
    Beskytter mod direkte adgang til FastAPI containeren.
    
    BEMÆRK: Logger IKKE secret værdien af sikkerhedshensyn.
    """
    # Tillad public endpoints uden secret
    if request.url.path in PUBLIC_ENDPOINTS:
        return await call_next(request)
    
    # Check X-Internal-Secret header (tilføjet af NGINX)
    secret = request.headers.get("x-internal-secret")
    
    if secret != API_SECRET_KEY:
        # Log uden at afsløre secret værdi
        logger.warning(
            f"BLOKERET - Ugyldig secret, "
            f"Path: {request.url.path}, "
            f"Client IP: {request.client.host}, "
            f"Secret provided: {'yes' if secret else 'no'}"
        )
        
        raise HTTPException(
            status_code=403,
            detail="Access forbidden - requests must come through proxy"
        )
    
    return await call_next(request)
