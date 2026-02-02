"""
Routers Package - API endpoints
"""
from backend.routers.chat import router as chat_router
from backend.routers.prompts import router as prompts_router
from backend.routers.collections import router as collections_router
from backend.routers.health import router as health_router
from backend.routers.auth import router as auth_router

# Export dependencies for use in other routers
from backend.routers.auth import (
    get_current_user_optional,
    get_current_user_required,
    require_admin,
    get_client_ip,
)

__all__ = [
    "chat_router",
    "prompts_router",
    "collections_router",
    "health_router",
    "auth_router",
    "get_current_user_optional",
    "get_current_user_required",
    "require_admin",
    "get_client_ip",
]
