"""
JWT Authentication Service med Azure AD/Entra ID SSO
=====================================================
Håndterer både lokal login og Azure AD SSO authentication.
Kan slås til/fra via environment variables.
"""
import os
import json
import hashlib
import httpx
from datetime import datetime, timedelta
from typing import Optional, Dict, List
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from backend.config import (
    JWT_ENABLED,
    JWT_SECRET_KEY,
    JWT_ALGORITHM,
    JWT_ACCESS_TOKEN_EXPIRE,
    JWT_REFRESH_TOKEN_EXPIRE,
    settings,
    logger,
)


# ============================================================
# Password Hashing
# ============================================================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ============================================================
# User Models
# ============================================================
class User(BaseModel):
    """Bruger model"""
    user_id: str
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: bool = False
    roles: List[str] = ["user"]
    created_at: Optional[str] = None
    auth_provider: str = "local"  # "local" eller "azure_ad"


class UserInDB(User):
    """Bruger model med hashed password"""
    hashed_password: Optional[str] = None  # None for Azure AD brugere


class TokenData(BaseModel):
    """Data indeholdt i JWT token"""
    user_id: str
    username: str
    email: Optional[str] = None
    roles: List[str] = ["user"]
    exp: Optional[datetime] = None
    token_type: str = "access"
    auth_provider: str = "local"


# ============================================================
# Azure AD Configuration
# ============================================================
class AzureADConfig:
    """Azure AD/Entra ID konfiguration"""
    
    def __init__(self):
        self.enabled = settings.azure_ad_enabled
        self.tenant_id = settings.azure_ad_tenant_id
        self.client_id = settings.azure_ad_client_id
        self.client_secret = settings.azure_ad_client_secret
        self.redirect_uri = settings.azure_ad_redirect_uri
        
        # Azure AD endpoints
        if self.tenant_id:
            self.authority = f"https://login.microsoftonline.com/{self.tenant_id}"
            self.authorize_url = f"{self.authority}/oauth2/v2.0/authorize"
            self.token_url = f"{self.authority}/oauth2/v2.0/token"
            self.jwks_url = f"{self.authority}/discovery/v2.0/keys"
            self.userinfo_url = "https://graph.microsoft.com/v1.0/me"
        
        # Scopes
        self.scopes = ["openid", "profile", "email", "User.Read"]
    
    def is_configured(self) -> bool:
        """Check om Azure AD er korrekt konfigureret"""
        return all([
            self.enabled,
            self.tenant_id,
            self.client_id,
            self.client_secret,
            self.redirect_uri,
        ])


azure_config = AzureADConfig()


# ============================================================
# Simple File-based User Store
# ============================================================
class UserStore:
    """
    Simpel fil-baseret bruger storage.
    Understøtter både lokale og Azure AD brugere.
    """
    
    def __init__(self, users_file: str = "/app/data/users.json"):
        self.users_file = users_file
        self._users: Dict[str, UserInDB] = {}
        self._load_users()
    
    def _load_users(self):
        """Indlæs brugere fra fil"""
        if os.path.exists(self.users_file):
            try:
                with open(self.users_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for user_id, user_data in data.items():
                        self._users[user_id] = UserInDB(**user_data)
                logger.info(f"Indlæst {len(self._users)} brugere fra {self.users_file}")
            except Exception as e:
                logger.error(f"Fejl ved indlæsning af brugere: {e}")
        else:
            self._create_default_admin()
    
    def _save_users(self):
        """Gem brugere til fil"""
        try:
            os.makedirs(os.path.dirname(self.users_file), exist_ok=True)
            
            data = {
                user_id: user.model_dump() 
                for user_id, user in self._users.items()
            }
            with open(self.users_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Fejl ved gemning af brugere: {e}")
    
    def _create_default_admin(self):
        """Opret default admin bruger"""
        admin_password = os.getenv("DEFAULT_ADMIN_PASSWORD", "changeme123!")
        
        admin = UserInDB(
            user_id="admin",
            username="admin",
            email="admin@example.com",
            full_name="Administrator",
            disabled=False,
            roles=["admin", "user"],
            hashed_password=pwd_context.hash(admin_password),
            created_at=datetime.utcnow().isoformat(),
            auth_provider="local"
        )
        
        self._users["admin"] = admin
        self._save_users()
        
        logger.warning("=" * 60)
        logger.warning("⚠️  DEFAULT ADMIN BRUGER OPRETTET!")
        logger.warning(f"    Username: admin")
        logger.warning(f"    Password: {admin_password}")
        logger.warning("    SKIFT DETTE PASSWORD STRAKS!")
        logger.warning("=" * 60)
    
    def get_user(self, username: str) -> Optional[UserInDB]:
        """Hent bruger fra username"""
        for user in self._users.values():
            if user.username == username:
                return user
        return None
    
    def get_user_by_id(self, user_id: str) -> Optional[UserInDB]:
        """Hent bruger fra user_id"""
        return self._users.get(user_id)
    
    def get_user_by_email(self, email: str) -> Optional[UserInDB]:
        """Hent bruger fra email"""
        for user in self._users.values():
            if user.email and user.email.lower() == email.lower():
                return user
        return None
    
    def create_user(
        self,
        username: str,
        password: Optional[str] = None,
        email: Optional[str] = None,
        full_name: Optional[str] = None,
        roles: List[str] = None,
        auth_provider: str = "local",
    ) -> Optional[User]:
        """Opret ny bruger"""
        if self.get_user(username):
            return None
        
        user_id = hashlib.md5(username.encode()).hexdigest()[:12]
        
        user = UserInDB(
            user_id=user_id,
            username=username,
            email=email,
            full_name=full_name,
            disabled=False,
            roles=roles or ["user"],
            hashed_password=pwd_context.hash(password) if password else None,
            created_at=datetime.utcnow().isoformat(),
            auth_provider=auth_provider,
        )
        
        self._users[user_id] = user
        self._save_users()
        
        logger.info(f"Bruger oprettet: {username} (id: {user_id}, provider: {auth_provider})")
        
        return User(**user.model_dump(exclude={'hashed_password'}))
    
    def create_or_update_azure_user(
        self,
        azure_id: str,
        email: str,
        display_name: str,
        roles: List[str] = None,
    ) -> User:
        """Opret eller opdater Azure AD bruger"""
        # Check om bruger allerede eksisterer (via email)
        existing = self.get_user_by_email(email)
        
        if existing:
            # Opdater eksisterende bruger
            existing.full_name = display_name
            existing.auth_provider = "azure_ad"
            self._save_users()
            return User(**existing.model_dump(exclude={'hashed_password'}))
        
        # Opret ny bruger
        username = email.split('@')[0]  # Brug email prefix som username
        
        # Sikr unikt username
        base_username = username
        counter = 1
        while self.get_user(username):
            username = f"{base_username}{counter}"
            counter += 1
        
        user = UserInDB(
            user_id=azure_id[:12],
            username=username,
            email=email,
            full_name=display_name,
            disabled=False,
            roles=roles or ["user"],
            hashed_password=None,
            created_at=datetime.utcnow().isoformat(),
            auth_provider="azure_ad",
        )
        
        self._users[user.user_id] = user
        self._save_users()
        
        logger.info(f"Azure AD bruger oprettet: {username} ({email})")
        
        return User(**user.model_dump(exclude={'hashed_password'}))
    
    def update_password(self, user_id: str, new_password: str) -> bool:
        """Opdater brugers password"""
        user = self._users.get(user_id)
        if not user or user.auth_provider != "local":
            return False
        
        user.hashed_password = pwd_context.hash(new_password)
        self._save_users()
        return True
    
    def disable_user(self, user_id: str) -> bool:
        """Deaktiver bruger"""
        user = self._users.get(user_id)
        if not user:
            return False
        
        user.disabled = True
        self._save_users()
        return True
    
    def list_users(self) -> List[User]:
        """List alle brugere (uden passwords)"""
        return [
            User(**user.model_dump(exclude={'hashed_password'}))
            for user in self._users.values()
        ]


# ============================================================
# JWT Authentication Service
# ============================================================
class JWTAuthService:
    """
    JWT Authentication Service med Azure AD SSO support.
    """
    
    def __init__(self):
        self.enabled = JWT_ENABLED
        self.user_store = UserStore() if self.enabled else None
        self.azure_config = azure_config
        
        if self.enabled:
            logger.info("✅ JWT Authentication aktiveret")
            if self.azure_config.is_configured():
                logger.info("✅ Azure AD SSO aktiveret")
            else:
                logger.info("ℹ️  Azure AD SSO ikke konfigureret")
        else:
            logger.info("ℹ️  JWT Authentication deaktiveret")
    
    # --------------------------------------------------------
    # Local Authentication
    # --------------------------------------------------------
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verificer password mod hash"""
        return pwd_context.verify(plain_password, hashed_password)
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Autentificer bruger med username og password."""
        if not self.enabled or not self.user_store:
            return None
        
        user = self.user_store.get_user(username)
        if not user:
            return None
        
        # Azure AD brugere kan ikke logge ind med password
        if user.auth_provider == "azure_ad":
            return None
        
        if not user.hashed_password or not self.verify_password(password, user.hashed_password):
            return None
        
        if user.disabled:
            return None
        
        return User(**user.model_dump(exclude={'hashed_password'}))
    
    # --------------------------------------------------------
    # Token Generation
    # --------------------------------------------------------
    def create_access_token(self, user: User) -> str:
        """Opret JWT access token for bruger."""
        expire = datetime.utcnow() + JWT_ACCESS_TOKEN_EXPIRE
        
        payload = {
            "sub": user.user_id,
            "username": user.username,
            "email": user.email,
            "roles": user.roles,
            "auth_provider": user.auth_provider,
            "type": "access",
            "exp": expire,
            "iat": datetime.utcnow(),
        }
        
        return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    
    def create_refresh_token(self, user: User) -> str:
        """Opret JWT refresh token for bruger."""
        expire = datetime.utcnow() + JWT_REFRESH_TOKEN_EXPIRE
        
        payload = {
            "sub": user.user_id,
            "type": "refresh",
            "exp": expire,
            "iat": datetime.utcnow(),
        }
        
        return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    
    def verify_token(self, token: str, token_type: str = "access") -> Optional[TokenData]:
        """Verificer og decode JWT token."""
        if not self.enabled:
            return None
        
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            
            if payload.get("type") != token_type:
                return None
            
            user_id = payload.get("sub")
            if not user_id:
                return None
            
            return TokenData(
                user_id=user_id,
                username=payload.get("username", ""),
                email=payload.get("email"),
                roles=payload.get("roles", ["user"]),
                exp=datetime.fromtimestamp(payload.get("exp", 0)),
                token_type=token_type,
                auth_provider=payload.get("auth_provider", "local"),
            )
            
        except JWTError as e:
            logger.debug(f"JWT verification failed: {e}")
            return None
    
    def refresh_access_token(self, refresh_token: str) -> Optional[Dict[str, str]]:
        """Brug refresh token til at få ny access token."""
        token_data = self.verify_token(refresh_token, token_type="refresh")
        if not token_data:
            return None
        
        user = self.user_store.get_user_by_id(token_data.user_id)
        if not user or user.disabled:
            return None
        
        user_model = User(**user.model_dump(exclude={'hashed_password'}))
        access_token = self.create_access_token(user_model)
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
        }
    
    def get_current_user(self, token: str) -> Optional[User]:
        """Hent current user fra access token."""
        token_data = self.verify_token(token, token_type="access")
        if not token_data:
            return None
        
        user = self.user_store.get_user_by_id(token_data.user_id)
        if not user or user.disabled:
            return None
        
        return User(**user.model_dump(exclude={'hashed_password'}))
    
    # --------------------------------------------------------
    # Azure AD SSO
    # --------------------------------------------------------
    def get_azure_login_url(self, state: Optional[str] = None) -> Optional[str]:
        """Generer Azure AD login URL."""
        if not self.azure_config.is_configured():
            return None
        
        import urllib.parse
        
        params = {
            "client_id": self.azure_config.client_id,
            "response_type": "code",
            "redirect_uri": self.azure_config.redirect_uri,
            "response_mode": "query",
            "scope": " ".join(self.azure_config.scopes),
        }
        
        if state:
            params["state"] = state
        
        return f"{self.azure_config.authorize_url}?{urllib.parse.urlencode(params)}"
    
    async def exchange_azure_code(self, code: str) -> Optional[Dict]:
        """
        Exchange Azure AD authorization code for tokens.
        Returnerer dict med access_token, id_token, etc.
        """
        if not self.azure_config.is_configured():
            return None
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.azure_config.token_url,
                    data={
                        "client_id": self.azure_config.client_id,
                        "client_secret": self.azure_config.client_secret,
                        "code": code,
                        "redirect_uri": self.azure_config.redirect_uri,
                        "grant_type": "authorization_code",
                        "scope": " ".join(self.azure_config.scopes),
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                
                if response.status_code != 200:
                    logger.error(f"Azure token exchange failed: {response.text}")
                    return None
                
                return response.json()
                
        except Exception as e:
            logger.error(f"Azure token exchange error: {e}")
            return None
    
    async def get_azure_user_info(self, azure_access_token: str) -> Optional[Dict]:
        """Hent bruger info fra Microsoft Graph API."""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    self.azure_config.userinfo_url,
                    headers={"Authorization": f"Bearer {azure_access_token}"},
                )
                
                if response.status_code != 200:
                    logger.error(f"Azure user info failed: {response.text}")
                    return None
                
                return response.json()
                
        except Exception as e:
            logger.error(f"Azure user info error: {e}")
            return None
    
    async def authenticate_azure_user(self, code: str) -> Optional[Dict]:
        """
        Fuld Azure AD authentication flow.
        
        Returns:
            Dict med access_token, refresh_token og user info
        """
        # Exchange code for Azure tokens
        azure_tokens = await self.exchange_azure_code(code)
        if not azure_tokens:
            return None
        
        # Get user info from Microsoft Graph
        user_info = await self.get_azure_user_info(azure_tokens.get("access_token"))
        if not user_info:
            return None
        
        # Create or update user in our system
        azure_id = user_info.get("id")
        email = user_info.get("mail") or user_info.get("userPrincipalName")
        display_name = user_info.get("displayName", email)
        
        if not email:
            logger.error("Azure user has no email")
            return None
        
        # Determine roles based on Azure groups (optional)
        roles = ["user"]
        
        # Create/update user
        user = self.user_store.create_or_update_azure_user(
            azure_id=azure_id,
            email=email,
            display_name=display_name,
            roles=roles,
        )
        
        # Generate our JWT tokens
        access_token = self.create_access_token(user)
        refresh_token = self.create_refresh_token(user)
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": int(JWT_ACCESS_TOKEN_EXPIRE.total_seconds()),
            "user": user.model_dump(),
        }


# ============================================================
# Singleton Instance
# ============================================================
auth_service = JWTAuthService()
