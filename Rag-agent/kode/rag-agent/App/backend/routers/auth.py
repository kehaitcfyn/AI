"""
Auth Router - Authentication endpoints med Azure AD SSO
=======================================================
Håndterer login, token refresh, Azure AD SSO og bruger management.
Bruger HttpOnly cookies til token-sikkerhed (forhindrer XSS token-tyveri).
Inkluderer CSRF protection med Double Submit Cookie pattern.
"""
from fastapi import APIRouter, HTTPException, Request, Depends, Query, Cookie, Header
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse, JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from pydantic import BaseModel
from typing import Optional, List
import secrets

from backend.services import auth_service, audit_logger, User
from backend.services.csrf_service import (
    csrf_protection, 
    verify_csrf_token, 
    get_csrf_token_for_response,
    CSRF_TOKEN_COOKIE,
)
from backend.config import JWT_ENABLED, AZURE_AD_ENABLED, logger

# ============================================================
# Cookie Configuration
# ============================================================
# Sikkerhedsindstillinger for cookies
from backend.config import COOKIE_DOMAIN, COOKIE_SECURE, COOKIE_SAMESITE
COOKIE_PATH = "/"

# Cookie navne
ACCESS_TOKEN_COOKIE = "access_token"
REFRESH_TOKEN_COOKIE = "refresh_token"


def set_auth_cookies(response: JSONResponse, access_token: str, refresh_token: str) -> JSONResponse:
    """
    Sætter HttpOnly cookies med tokens.
    
    HttpOnly: JavaScript kan IKKE læse disse cookies (forhindrer XSS token-tyveri)
    Secure: Cookies sendes kun over HTTPS (i produktion)
    SameSite: Beskytter mod CSRF-angreb
    """
    # Access token cookie (kort levetid)
    response.set_cookie(
        key=ACCESS_TOKEN_COOKIE,
        value=access_token,
        httponly=True,           # KRITISK: JavaScript kan ikke læse denne
        secure=COOKIE_SECURE,    # Kun HTTPS i produktion
        samesite=COOKIE_SAMESITE,
        max_age=3600,            # 1 time
        path=COOKIE_PATH,
        domain=COOKIE_DOMAIN,
    )
    
    # Refresh token cookie (længere levetid)
    response.set_cookie(
        key=REFRESH_TOKEN_COOKIE,
        value=refresh_token,
        httponly=True,           # KRITISK: JavaScript kan ikke læse denne
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        max_age=7 * 24 * 3600,   # 7 dage
        path=COOKIE_PATH,
        domain=COOKIE_DOMAIN,
    )
    
    return response


def clear_auth_cookies(response: JSONResponse) -> JSONResponse:
    """Fjerner auth cookies og CSRF cookie ved logout."""
    response.delete_cookie(
        key=ACCESS_TOKEN_COOKIE,
        path=COOKIE_PATH,
        domain=COOKIE_DOMAIN,
    )
    response.delete_cookie(
        key=REFRESH_TOKEN_COOKIE,
        path=COOKIE_PATH,
        domain=COOKIE_DOMAIN,
    )
    # Ryd også CSRF cookie
    csrf_protection.clear_csrf_cookie(response)
    return response

# Opret router
router = APIRouter(prefix="/auth", tags=["Authentication"])

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)

# State storage for CSRF protection (i produktion: brug Redis)
_oauth_states: dict = {}


# ============================================================
# Request/Response Models
# ============================================================
class TokenResponse(BaseModel):
    """Response med access og refresh tokens"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: Optional[dict] = None


class RefreshRequest(BaseModel):
    """Request til token refresh"""
    refresh_token: str


class CreateUserRequest(BaseModel):
    """Request til oprettelse af bruger"""
    username: str
    password: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    roles: Optional[List[str]] = None


class ChangePasswordRequest(BaseModel):
    """Request til password ændring"""
    current_password: str
    new_password: str


class MessageResponse(BaseModel):
    """Simpel message response"""
    message: str


class AuthStatusResponse(BaseModel):
    """Status for authentication"""
    jwt_enabled: bool
    azure_ad_enabled: bool
    azure_ad_login_url: Optional[str] = None


# ============================================================
# Helper Functions
# ============================================================
def get_client_ip(request: Request) -> str:
    """Hent klient IP fra request"""
    return (
        request.headers.get("x-real-ip") or
        request.headers.get("x-forwarded-for", "").split(",")[0].strip() or
        request.client.host
    )


async def get_current_user_optional(
    request: Request,
    access_token: Optional[str] = Cookie(None, alias=ACCESS_TOKEN_COOKIE),
) -> Optional[User]:
    """
    Dependency til at hente current user (valgfri).
    Læser token fra HttpOnly cookie i stedet for Authorization header.
    """
    if not JWT_ENABLED or not access_token:
        return None
    return auth_service.get_current_user(access_token)


async def get_current_user_required(
    request: Request,
    access_token: Optional[str] = Cookie(None, alias=ACCESS_TOKEN_COOKIE),
) -> User:
    """
    Dependency til at hente current user (påkrævet).
    Læser token fra HttpOnly cookie.
    """
    if not JWT_ENABLED:
        raise HTTPException(status_code=503, detail="Authentication er ikke aktiveret")
    
    if not access_token:
        raise HTTPException(
            status_code=401,
            detail="Ikke autentificeret",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = auth_service.get_current_user(access_token)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Ugyldig eller udløbet token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return user


async def require_admin(user: User = Depends(get_current_user_required)) -> User:
    """Dependency der kræver admin rolle"""
    if "admin" not in user.roles:
        raise HTTPException(status_code=403, detail="Admin rettigheder påkrævet")
    return user


# ============================================================
# Status Endpoint
# ============================================================
@router.get("/status", response_model=AuthStatusResponse)
async def auth_status():
    """
    Check authentication status og tilgængelige login metoder.
    
    Returnerer:
    - Om JWT er aktiveret
    - Om Azure AD SSO er aktiveret
    - Azure AD login URL (hvis aktiveret)
    """
    azure_login_url = None
    if AZURE_AD_ENABLED and auth_service.azure_config.is_configured():
        azure_login_url = "/api/auth/azure/login"
    
    return AuthStatusResponse(
        jwt_enabled=JWT_ENABLED,
        azure_ad_enabled=AZURE_AD_ENABLED,
        azure_ad_login_url=azure_login_url,
    )


# ============================================================
# Local Login Endpoints
# ============================================================
@router.post("/login")
@limiter.limit("5/minute")
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends()
):
    """
    Login med username og password (lokal authentication).
    
    Sætter HttpOnly cookies med access_token og refresh_token.
    Sætter CSRF token cookie (læsbar af JavaScript).
    Returnerer bruger info (IKKE tokens - de er i cookies).
    """
    if not JWT_ENABLED:
        raise HTTPException(status_code=503, detail="Authentication er ikke aktiveret")
    
    client_ip = get_client_ip(request)
    
    user = auth_service.authenticate_user(form_data.username, form_data.password)
    
    if not user:
        audit_logger.log_auth_event(
            event_type="login",
            user_id=None,
            ip_address=client_ip,
            success=False,
            details=f"Failed login: {form_data.username}"
        )
        raise HTTPException(
            status_code=401,
            detail="Forkert brugernavn eller password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = auth_service.create_access_token(user)
    refresh_token = auth_service.create_refresh_token(user)
    
    audit_logger.log_auth_event(
        event_type="login",
        user_id=user.user_id,
        ip_address=client_ip,
        success=True,
        details=f"Local login: {user.username}"
    )
    
    logger.info(f"Login: {user.username} fra {client_ip}")
    
    # Generer CSRF token
    csrf_token = get_csrf_token_for_response()
    
    # Opret response med bruger info (IKKE tokens)
    response = JSONResponse(content={
        "message": "Login successful",
        "token_type": "cookie",
        "expires_in": 3600,
        "user": user.model_dump(),
    })
    
    # Sæt HttpOnly cookies med auth tokens
    set_auth_cookies(response, access_token, refresh_token)
    
    # Sæt CSRF token cookie (læsbar af JavaScript)
    csrf_protection.set_csrf_cookie(response, csrf_token)
    
    return response


@router.post("/refresh")
@limiter.limit("10/minute")
async def refresh_token_endpoint(
    request: Request,
    refresh_token: Optional[str] = Cookie(None, alias=REFRESH_TOKEN_COOKIE),
):
    """
    Forny access token med refresh token fra cookie.
    Sætter ny access_token cookie og fornyer CSRF token.
    """
    if not JWT_ENABLED:
        raise HTTPException(status_code=503, detail="Authentication er ikke aktiveret")
    
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Ingen refresh token")
    
    client_ip = get_client_ip(request)
    
    result = auth_service.refresh_access_token(refresh_token)
    
    if not result:
        audit_logger.log_auth_event(
            event_type="token_refresh",
            user_id=None,
            ip_address=client_ip,
            success=False,
        )
        raise HTTPException(status_code=401, detail="Ugyldig refresh token")
    
    # Generer ny CSRF token ved refresh
    csrf_token = get_csrf_token_for_response()
    
    # Opret response
    response = JSONResponse(content={
        "message": "Token refreshed",
        "token_type": "cookie",
        "expires_in": 3600,
    })
    
    # Sæt nye cookies (refresh token forbliver den samme)
    set_auth_cookies(response, result["access_token"], refresh_token)
    
    # Sæt ny CSRF token
    csrf_protection.set_csrf_cookie(response, csrf_token)
    
    return response


# ============================================================
# Azure AD SSO Endpoints
# ============================================================
@router.get("/azure/login")
@limiter.limit("10/minute")
async def azure_login(request: Request, redirect_url: Optional[str] = Query(None)):
    """
    Start Azure AD SSO login flow.
    
    Redirecter til Microsoft login side.
    
    - **redirect_url**: Valgfri URL at redirecte til efter login (default: /)
    """
    if not AZURE_AD_ENABLED or not auth_service.azure_config.is_configured():
        raise HTTPException(status_code=503, detail="Azure AD SSO er ikke aktiveret")
    
    # Generer state for CSRF protection
    state = secrets.token_urlsafe(32)
    _oauth_states[state] = {
        "redirect_url": redirect_url or "/",
        "ip": get_client_ip(request),
    }
    
    # Generer Azure login URL
    login_url = auth_service.get_azure_login_url(state=state)
    
    if not login_url:
        raise HTTPException(status_code=500, detail="Kunne ikke generere login URL")
    
    logger.info(f"Azure AD login started fra {get_client_ip(request)}")
    
    return RedirectResponse(url=login_url)


@router.get("/azure/callback")
async def azure_callback(
    request: Request,
    code: str = Query(...),
    state: str = Query(...),
    error: Optional[str] = Query(None),
    error_description: Optional[str] = Query(None),
):
    """
    Azure AD SSO callback endpoint.
    
    Microsoft redirecter hertil efter login.
    Sætter HttpOnly cookies, CSRF token og redirecter til frontend.
    """
    client_ip = get_client_ip(request)
    
    # Check for errors from Azure
    if error:
        logger.error(f"Azure AD error: {error} - {error_description}")
        audit_logger.log_auth_event(
            event_type="azure_login",
            user_id=None,
            ip_address=client_ip,
            success=False,
            details=f"Azure error: {error}"
        )
        # Redirect til frontend med fejl
        return RedirectResponse(url=f"/?error=azure_login_failed&message={error_description or error}")
    
    # Verificer state (CSRF protection for OAuth flow)
    state_data = _oauth_states.pop(state, None)
    if not state_data:
        logger.warning(f"Invalid OAuth state from {client_ip}")
        return RedirectResponse(url="/?error=invalid_state")
    
    redirect_url = state_data.get("redirect_url", "/")
    
    # Exchange code for tokens
    result = await auth_service.authenticate_azure_user(code)
    
    if not result:
        audit_logger.log_auth_event(
            event_type="azure_login",
            user_id=None,
            ip_address=client_ip,
            success=False,
            details="Token exchange failed"
        )
        return RedirectResponse(url="/?error=authentication_failed")
    
    user = result.get("user", {})
    
    audit_logger.log_auth_event(
        event_type="azure_login",
        user_id=user.get("user_id"),
        ip_address=client_ip,
        success=True,
        details=f"Azure login: {user.get('email')}"
    )
    
    logger.info(f"Azure AD login success: {user.get('email')} fra {client_ip}")
    
    # SIKKER TILGANG: Redirect med cookies i stedet for tokens i URL
    # Tokens gemmes i HttpOnly cookies som JavaScript IKKE kan læse
    access_token = result["access_token"]
    refresh_token = result["refresh_token"]
    
    # Generer CSRF token
    csrf_token = get_csrf_token_for_response()
    
    # Opret redirect response
    response = RedirectResponse(url=f"{redirect_url}?login=success", status_code=302)
    
    # Sæt HttpOnly auth cookies
    response.set_cookie(
        key=ACCESS_TOKEN_COOKIE,
        value=access_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        max_age=3600,
        path=COOKIE_PATH,
        domain=COOKIE_DOMAIN,
    )
    response.set_cookie(
        key=REFRESH_TOKEN_COOKIE,
        value=refresh_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        max_age=7 * 24 * 3600,
        path=COOKIE_PATH,
        domain=COOKIE_DOMAIN,
    )
    
    # Sæt CSRF token cookie (læsbar af JavaScript)
    csrf_protection.set_csrf_cookie(response, csrf_token)
    
    return response


@router.get("/azure/logout")
async def azure_logout(
    request: Request,
    post_logout_redirect_uri: Optional[str] = Query(None)
):
    """
    Logout fra Azure AD.
    
    Rydder auth cookies og redirecter til Microsoft logout side.
    """
    if not AZURE_AD_ENABLED or not auth_service.azure_config.is_configured():
        raise HTTPException(status_code=503, detail="Azure AD SSO er ikke aktiveret")
    
    logout_url = f"https://login.microsoftonline.com/{auth_service.azure_config.tenant_id}/oauth2/v2.0/logout"
    
    if post_logout_redirect_uri:
        logout_url += f"?post_logout_redirect_uri={post_logout_redirect_uri}"
    
    # Opret redirect response og ryd cookies
    response = RedirectResponse(url=logout_url)
    response.delete_cookie(key=ACCESS_TOKEN_COOKIE, path=COOKIE_PATH, domain=COOKIE_DOMAIN)
    response.delete_cookie(key=REFRESH_TOKEN_COOKIE, path=COOKIE_PATH, domain=COOKIE_DOMAIN)
    
    return response


@router.post("/logout")
async def logout(
    request: Request,
    _csrf: bool = Depends(verify_csrf_token),  # CSRF protection
):
    """
    Logout endpoint - rydder auth cookies og CSRF cookie.
    
    For Azure AD brugere: Brug /auth/azure/logout i stedet for fuld logout.
    """
    response = JSONResponse(content={"message": "Logged out successfully"})
    clear_auth_cookies(response)
    return response


# ============================================================
# User Info Endpoints
# ============================================================
@router.get("/me", response_model=User)
async def get_current_user_info(
    request: Request,
    user: User = Depends(get_current_user_required)
):
    """Hent information om den aktuelle bruger."""
    return user


@router.post("/change-password", response_model=MessageResponse)
@limiter.limit("3/minute")
async def change_password(
    request: Request,
    password_request: ChangePasswordRequest,
    user: User = Depends(get_current_user_required),
    _csrf: bool = Depends(verify_csrf_token),  # CSRF protection
):
    """Skift password (kun for lokale brugere)."""
    client_ip = get_client_ip(request)
    
    # Azure AD brugere kan ikke skifte password her
    if user.auth_provider == "azure_ad":
        raise HTTPException(
            status_code=400,
            detail="Azure AD brugere skal skifte password via Microsoft"
        )
    
    user_db = auth_service.user_store.get_user(user.username)
    if not user_db or not auth_service.verify_password(
        password_request.current_password, 
        user_db.hashed_password
    ):
        audit_logger.log_auth_event(
            event_type="password_change",
            user_id=user.user_id,
            ip_address=client_ip,
            success=False,
        )
        raise HTTPException(status_code=400, detail="Forkert nuværende password")
    
    success = auth_service.user_store.update_password(
        user.user_id, 
        password_request.new_password
    )
    
    if not success:
        raise HTTPException(status_code=500, detail="Kunne ikke opdatere password")
    
    audit_logger.log_auth_event(
        event_type="password_change",
        user_id=user.user_id,
        ip_address=client_ip,
        success=True,
    )
    
    return MessageResponse(message="Password opdateret")


# ============================================================
# Admin Endpoints
# ============================================================
@router.post("/users", response_model=User)
@limiter.limit("5/minute")
async def create_user(
    request: Request,
    user_request: CreateUserRequest,
    admin: User = Depends(require_admin),
    _csrf: bool = Depends(verify_csrf_token),  # CSRF protection
):
    """Opret ny lokal bruger (kun admin)."""
    client_ip = get_client_ip(request)
    
    new_user = auth_service.user_store.create_user(
        username=user_request.username,
        password=user_request.password,
        email=user_request.email,
        full_name=user_request.full_name,
        roles=user_request.roles,
        auth_provider="local",
    )
    
    if not new_user:
        raise HTTPException(
            status_code=400,
            detail=f"Brugernavn '{user_request.username}' er allerede i brug"
        )
    
    audit_logger.log_auth_event(
        event_type="user_created",
        user_id=admin.user_id,
        ip_address=client_ip,
        success=True,
        details=f"Created: {new_user.username}"
    )
    
    return new_user


@router.get("/users", response_model=List[User])
async def list_users(
    request: Request,
    admin: User = Depends(require_admin)
):
    """List alle brugere (kun admin)."""
    return auth_service.user_store.list_users()


@router.post("/users/{user_id}/disable", response_model=MessageResponse)
async def disable_user(
    request: Request,
    user_id: str,
    admin: User = Depends(require_admin),
    _csrf: bool = Depends(verify_csrf_token),  # CSRF protection
):
    """Deaktiver en bruger (kun admin)."""
    if user_id == admin.user_id:
        raise HTTPException(status_code=400, detail="Du kan ikke deaktivere dig selv")
    
    client_ip = get_client_ip(request)
    
    success = auth_service.user_store.disable_user(user_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="Bruger ikke fundet")
    
    audit_logger.log_auth_event(
        event_type="user_disabled",
        user_id=admin.user_id,
        ip_address=client_ip,
        success=True,
        details=f"Disabled: {user_id}"
    )
    
    return MessageResponse(message="Bruger deaktiveret")
