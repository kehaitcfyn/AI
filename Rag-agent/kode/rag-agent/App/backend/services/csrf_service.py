"""
CSRF Protection Service
========================
Implementerer Double Submit Cookie pattern for CSRF beskyttelse.

Hvordan det virker:
1. Ved login genereres en CSRF token og gemmes i en cookie (læsbar af JS)
2. Frontend læser token fra cookie og sender den i X-CSRF-Token header
3. Backend verificerer at header matcher cookie

Fordele:
- Stateless (ingen server-side token storage nødvendig)
- Kompatibel med HttpOnly auth cookies
- Beskytter mod cross-site request forgery
"""
import secrets
import hmac
import hashlib
from typing import Optional, Tuple
from datetime import datetime, timedelta

from fastapi import Request, HTTPException, Header, Cookie
from fastapi.responses import Response

from backend.config import JWT_SECRET_KEY, COOKIE_DOMAIN, COOKIE_SECURE, COOKIE_SAMESITE, logger


# ============================================================
# CSRF Configuration
# ============================================================
CSRF_TOKEN_COOKIE = "csrf_token"
CSRF_TOKEN_HEADER = "X-CSRF-Token"
CSRF_TOKEN_LENGTH = 32  # bytes
CSRF_TOKEN_MAX_AGE = 3600  # 1 time (matcher access token)

# Endpoints der er undtaget fra CSRF check (GET, HEAD, OPTIONS er altid undtaget)
CSRF_EXEMPT_PATHS = [
    "/api/auth/login",      # Login er undtaget (ingen session endnu)
    "/api/auth/status",     # Status check
    "/api/auth/azure/login",
    "/api/auth/azure/callback",
    "/api/health",
    "/docs",
    "/redoc",
    "/openapi.json",
]


class CSRFProtection:
    """
    CSRF Protection using Double Submit Cookie pattern.
    
    Sikkerhedsmodel:
    - CSRF token cookie: Læsbar af JavaScript (httponly=False)
    - CSRF token header: Sendes af frontend fra cookie-værdi
    - Verifikation: Cookie og header skal matche
    
    Hvorfor dette virker:
    - En angriber kan få browseren til at sende cookies automatisk
    - Men en angriber kan IKKE læse cookies fra et andet domæne (Same-Origin Policy)
    - Derfor kan angriberen ikke sætte den korrekte header
    """
    
    def __init__(self):
        self.secret_key = JWT_SECRET_KEY
    
    def generate_token(self) -> str:
        """
        Genererer en kryptografisk sikker CSRF token.
        
        Token format: random_bytes + "." + timestamp + "." + signature
        """
        # Random bytes for unikhed
        random_part = secrets.token_urlsafe(CSRF_TOKEN_LENGTH)
        
        # Timestamp for optional expiry validation
        timestamp = str(int(datetime.utcnow().timestamp()))
        
        # Signatur for at verificere integritet
        message = f"{random_part}.{timestamp}"
        signature = self._sign(message)
        
        return f"{random_part}.{timestamp}.{signature}"
    
    def _sign(self, message: str) -> str:
        """Opretter HMAC signatur af besked."""
        return hmac.new(
            self.secret_key.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()[:16]  # Kort signatur er nok
    
    def verify_token(self, token: str) -> Tuple[bool, str]:
        """
        Verificerer CSRF token integritet og alder.
        
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        if not token:
            return False, "Missing CSRF token"
        
        parts = token.split(".")
        if len(parts) != 3:
            return False, "Invalid CSRF token format"
        
        random_part, timestamp_str, signature = parts
        
        # Verificer signatur
        expected_signature = self._sign(f"{random_part}.{timestamp_str}")
        if not hmac.compare_digest(signature, expected_signature):
            return False, "Invalid CSRF token signature"
        
        # Verificer timestamp (optional - tokens udløber med cookie)
        try:
            timestamp = int(timestamp_str)
            token_age = datetime.utcnow().timestamp() - timestamp
            if token_age > CSRF_TOKEN_MAX_AGE:
                return False, "CSRF token expired"
        except ValueError:
            return False, "Invalid CSRF token timestamp"
        
        return True, ""
    
    def set_csrf_cookie(self, response: Response, token: str) -> Response:
        """
        Sætter CSRF token cookie.
        
        VIGTIGT: httponly=False så JavaScript kan læse den!
        """
        response.set_cookie(
            key=CSRF_TOKEN_COOKIE,
            value=token,
            httponly=False,      # SKAL være False så JS kan læse den
            secure=COOKIE_SECURE,
            samesite=CSRF_SAMESITE_POLICY,
            max_age=CSRF_TOKEN_MAX_AGE,
            path="/",
            domain=COOKIE_DOMAIN,
        )
        return response
    
    def clear_csrf_cookie(self, response: Response) -> Response:
        """Fjerner CSRF cookie ved logout."""
        response.delete_cookie(
            key=CSRF_TOKEN_COOKIE,
            path="/",
            domain=COOKIE_DOMAIN,
        )
        return response


# SameSite policy for CSRF cookie
# "strict" giver bedst CSRF beskyttelse, men kan give problemer med OAuth redirects
# "lax" er et godt kompromis
CSRF_SAMESITE_POLICY = "strict" if COOKIE_SAMESITE == "strict" else "lax"


# Singleton instance
csrf_protection = CSRFProtection()


# ============================================================
# FastAPI Dependencies
# ============================================================
async def verify_csrf_token(
    request: Request,
    csrf_cookie: Optional[str] = Cookie(None, alias=CSRF_TOKEN_COOKIE),
    csrf_header: Optional[str] = Header(None, alias=CSRF_TOKEN_HEADER),
) -> bool:
    """
    FastAPI dependency til at verificere CSRF token.
    
    Bruger Double Submit Cookie pattern:
    1. CSRF token sendes i cookie (automatisk af browser)
    2. CSRF token sendes i header (manuelt af JavaScript)
    3. Begge skal matche
    
    Usage:
        @router.post("/sensitive-action")
        async def sensitive_action(
            _csrf: bool = Depends(verify_csrf_token),
            ...
        ):
    """
    # Skip CSRF check for safe methods
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return True
    
    # Skip for exempt paths
    path = request.url.path
    for exempt_path in CSRF_EXEMPT_PATHS:
        if path.startswith(exempt_path):
            return True
    
    # Verificer at cookie er til stede
    if not csrf_cookie:
        logger.warning(f"CSRF check failed: No cookie - {request.method} {path}")
        raise HTTPException(
            status_code=403,
            detail="CSRF token missing from cookie"
        )
    
    # Verificer at header er til stede
    if not csrf_header:
        logger.warning(f"CSRF check failed: No header - {request.method} {path}")
        raise HTTPException(
            status_code=403,
            detail="CSRF token missing from header"
        )
    
    # Verificer at cookie og header matcher (Double Submit)
    if not hmac.compare_digest(csrf_cookie, csrf_header):
        logger.warning(f"CSRF check failed: Mismatch - {request.method} {path}")
        raise HTTPException(
            status_code=403,
            detail="CSRF token mismatch"
        )
    
    # Verificer token integritet
    is_valid, error_msg = csrf_protection.verify_token(csrf_cookie)
    if not is_valid:
        logger.warning(f"CSRF check failed: {error_msg} - {request.method} {path}")
        raise HTTPException(
            status_code=403,
            detail=f"CSRF validation failed: {error_msg}"
        )
    
    return True


def get_csrf_token_for_response() -> str:
    """Genererer ny CSRF token til response."""
    return csrf_protection.generate_token()
