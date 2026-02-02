"""
Collections Router - Endpoints for Chroma vector collections
"""
from fastapi import APIRouter, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from backend.models import CollectionsResponse
from backend.services import chat_service

# Opret router
router = APIRouter(prefix="", tags=["Collections"])

# Rate limiter
limiter = Limiter(key_func=get_remote_address)


@router.get("/collections", response_model=CollectionsResponse)
@limiter.limit("20/minute")
async def get_collections(request: Request):
    """
    Hent alle tilgængelige Chroma vector collections
    
    Returnerer en liste af collection navne der kan bruges til RAG.
    """
    collections = chat_service.list_collections()
    return CollectionsResponse(
        count=len(collections),
        collections=collections
    )
