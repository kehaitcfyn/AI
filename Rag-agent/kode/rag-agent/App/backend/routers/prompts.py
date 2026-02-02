"""
Prompts Router - Endpoints for system prompts
"""
from fastapi import APIRouter, Request, Depends
from slowapi import Limiter
from slowapi.util import get_remote_address

from backend.models import PromptsResponse
from backend.services import chat_service
from backend.routers.auth import get_current_user_required
from backend.services.auth_service import User
from backend.config import JWT_ENABLED

# Opret router
router = APIRouter(prefix="", tags=["Prompts"])

# Rate limiter
limiter = Limiter(key_func=get_remote_address)


@router.get("/prompts", response_model=PromptsResponse)
@limiter.limit("20/minute")
async def get_prompts(
    request: Request,
    user: User = Depends(get_current_user_required) if JWT_ENABLED else None
):
    """
    Hent alle tilgængelige system prompts
    
    Returnerer en liste af prompts med navn, filnavn og tilknyttet collection.
    """
    prompts = chat_service.load_system_prompts()
    return PromptsResponse(
        count=len(prompts),
        prompts=prompts
    )