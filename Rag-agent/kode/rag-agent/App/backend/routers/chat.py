"""
Chat Router - Endpoints for chat funktionalitet
===============================================
Async endpoints med JWT authentication, CSRF protection og audit logging.
"""
import uuid
import time
from fastapi import APIRouter, HTTPException, Request, Depends
from slowapi import Limiter
from slowapi.util import get_remote_address
from typing import Optional

from backend.models import ChatRAGRequest, ChatRAGResponse, HistoryResponse, ResetResponse
from backend.services import chat_service, audit_logger, User
from backend.services.csrf_service import verify_csrf_token
from backend.config import MAX_OUTPUT_TOKENS, logger, JWT_ENABLED
from backend.routers.auth import get_current_user_optional, get_client_ip

# Opret router
router = APIRouter(prefix="", tags=["Chat"])

# Rate limiter
limiter = Limiter(key_func=get_remote_address)


@router.post("/chat", response_model=ChatRAGResponse)
@limiter.limit("10/minute")
async def chat(
    request: Request, 
    chat_request: ChatRAGRequest,
    current_user: Optional[User] = Depends(get_current_user_optional),
    _csrf: bool = Depends(verify_csrf_token),  # CSRF protection
):
    """
    Send en besked til AI med RAG.
    
    - **message**: Brugerens besked (valideres og saniteres automatisk)
    - **session_id**: Valgfri session ID (oprettes automatisk for ny samtale)
    - **prompt_key**: Påkrævet for ny samtale - vælger system prompt
    
    Hvis JWT er aktiveret, kræves authentication.
    Returnerer AI's svar med kilder og token-forbrug.
    """
    start_time = time.time()
    client_ip = get_client_ip(request)
    user_id = current_user.user_id if current_user else None
    
    # Check JWT krav hvis aktiveret
    if JWT_ENABLED and not current_user:
        audit_logger.log_request(
            user_id=None,
            ip_address=client_ip,
            method="POST",
            endpoint="/chat",
            response_status=401,
            response_time_ms=(time.time() - start_time) * 1000,
            error="Authentication required"
        )
        raise HTTPException(
            status_code=401,
            detail="Authentication påkrævet",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Opret ny session hvis ikke angivet
    if not chat_request.session_id:
        chat_request.session_id = str(uuid.uuid4())
        
        if not chat_request.prompt_key:
            logger.warning("Chat request uden prompt_key for ny session")
            
            audit_logger.log_request(
                user_id=user_id,
                ip_address=client_ip,
                method="POST",
                endpoint="/chat",
                request_body={"message": chat_request.message[:100]},
                response_status=400,
                response_time_ms=(time.time() - start_time) * 1000,
                error="prompt_key required"
            )
            
            raise HTTPException(
                status_code=400, 
                detail="prompt_key er påkrævet for ny samtale"
            )
        
        prompt_name = await chat_service.create_conversation(
            chat_request.session_id, 
            chat_request.prompt_key
        )
        
        if not prompt_name:
            raise HTTPException(
                status_code=400,
                detail=f"Ugyldig prompt_key: {chat_request.prompt_key}"
            )
        
        logger.info(f"Ny samtale: session={chat_request.session_id[:8]}..., user={user_id or 'anonymous'}")
    
    try:
        result = await chat_service.send_message(
            chat_request.session_id, 
            chat_request.message,
            max_output_tokens=MAX_OUTPUT_TOKENS
        )
        
        response_time_ms = (time.time() - start_time) * 1000
        
        # Audit log
        audit_logger.log_request(
            user_id=user_id,
            ip_address=client_ip,
            method="POST",
            endpoint="/chat",
            request_body={
                "message": chat_request.message[:100] + "..." if len(chat_request.message) > 100 else chat_request.message,
                "session_id": chat_request.session_id[:8] + "...",
                "prompt_key": chat_request.prompt_key,
            },
            response_status=200,
            response_time_ms=response_time_ms,
            token_usage=result.get("tokens"),
        )
        
        logger.debug(
            f"Chat response: session={chat_request.session_id[:8]}..., "
            f"tokens={result['tokens']['input']}+{result['tokens']['output']}, "
            f"time={response_time_ms:.0f}ms"
        )
        
        return ChatRAGResponse(
            session_id=chat_request.session_id,
            response=result["response"],
            tokens=result["tokens"],
            rag_context=result.get("rag_context"),
            sources_used=result.get("sources_used", 0),
            sources_metadata=result.get("sources_metadata", [])
        )
        
    except ValueError as e:
        response_time_ms = (time.time() - start_time) * 1000
        
        audit_logger.log_request(
            user_id=user_id,
            ip_address=client_ip,
            method="POST",
            endpoint="/chat",
            response_status=400,
            response_time_ms=response_time_ms,
            error=str(e)
        )
        
        logger.warning(f"Chat ValueError: {e}")
        raise HTTPException(status_code=400, detail=str(e))
        
    except Exception as e:
        response_time_ms = (time.time() - start_time) * 1000
        
        audit_logger.log_request(
            user_id=user_id,
            ip_address=client_ip,
            method="POST",
            endpoint="/chat",
            response_status=500,
            response_time_ms=response_time_ms,
            error=str(e)
        )
        
        logger.error(f"Chat fejl: {e}", exc_info=True)
        raise HTTPException(
            status_code=500, 
            detail="Der opstod en fejl ved behandling af din besked"
        )


@router.get("/history/{session_id}", response_model=HistoryResponse)
@limiter.limit("30/minute")
async def get_history(
    request: Request, 
    session_id: str,
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """
    Hent samtalehistorik for en session.
    
    - **session_id**: Session ID at hente historik for
    """
    start_time = time.time()
    client_ip = get_client_ip(request)
    user_id = current_user.user_id if current_user else None
    
    # Check JWT krav hvis aktiveret
    if JWT_ENABLED and not current_user:
        raise HTTPException(
            status_code=401,
            detail="Authentication påkrævet",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    history = chat_service.get_history(session_id)
    
    response_time_ms = (time.time() - start_time) * 1000
    
    if not history:
        audit_logger.log_request(
            user_id=user_id,
            ip_address=client_ip,
            method="GET",
            endpoint=f"/history/{session_id[:8]}...",
            response_status=404,
            response_time_ms=response_time_ms,
        )
        
        logger.debug(f"Historik ikke fundet: {session_id[:8]}...")
        raise HTTPException(
            status_code=404, 
            detail="Samtale ikke fundet"
        )
    
    audit_logger.log_request(
        user_id=user_id,
        ip_address=client_ip,
        method="GET",
        endpoint=f"/history/{session_id[:8]}...",
        response_status=200,
        response_time_ms=response_time_ms,
        extra={"message_count": len(history)}
    )
    
    return HistoryResponse(
        session_id=session_id,
        messages=history
    )


@router.post("/reset/{session_id}", response_model=ResetResponse)
@limiter.limit("10/minute")
async def reset_conversation(
    request: Request, 
    session_id: str, 
    prompt_key: str,
    current_user: Optional[User] = Depends(get_current_user_optional),
    _csrf: bool = Depends(verify_csrf_token),  # CSRF protection
):
    """
    Nulstil en samtale med en ny prompt.
    
    - **session_id**: Session ID at nulstille
    - **prompt_key**: Ny prompt key at bruge
    """
    start_time = time.time()
    client_ip = get_client_ip(request)
    user_id = current_user.user_id if current_user else None
    
    # Check JWT krav hvis aktiveret
    if JWT_ENABLED and not current_user:
        raise HTTPException(
            status_code=401,
            detail="Authentication påkrævet",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    name = await chat_service.reset_conversation(session_id, prompt_key)
    
    response_time_ms = (time.time() - start_time) * 1000
    
    if not name:
        audit_logger.log_request(
            user_id=user_id,
            ip_address=client_ip,
            method="POST",
            endpoint=f"/reset/{session_id[:8]}...",
            response_status=404,
            response_time_ms=response_time_ms,
            error=f"Prompt not found: {prompt_key}"
        )
        
        logger.warning(f"Reset med ugyldig prompt: {prompt_key}")
        raise HTTPException(
            status_code=404, 
            detail=f"Prompt ikke fundet: {prompt_key}"
        )
    
    audit_logger.log_request(
        user_id=user_id,
        ip_address=client_ip,
        method="POST",
        endpoint=f"/reset/{session_id[:8]}...",
        response_status=200,
        response_time_ms=response_time_ms,
        extra={"new_prompt": prompt_key}
    )
    
    logger.info(f"Samtale nulstillet: {session_id[:8]}... -> {name}")
    
    return ResetResponse(
        message=f"Samtale nulstillet med prompt: {name}",
        session_id=session_id
    )
