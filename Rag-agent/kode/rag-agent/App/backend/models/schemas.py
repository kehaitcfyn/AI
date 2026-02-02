"""
Pydantic modeller for API requests og responses
===============================================
Inkluderer input validering og sanitering for sikkerhed.
"""
import re
from pydantic import BaseModel, field_validator
from typing import Optional, List

from backend.config import MAX_INPUT_TOKENS


# ============================================================
# Suspekte patterns for prompt injection detection
# ============================================================
SUSPICIOUS_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)",
    r"disregard\s+(all\s+)?(previous|prior|above)",
    r"forget\s+(all\s+)?(previous|prior|above)",
    r"new\s+instructions?\s*:",
    r"system\s*:\s*",
    r"<\s*/?script",
    r"<\s*/?iframe",
    r"javascript\s*:",
    r"data\s*:\s*text/html",
    r"on\w+\s*=",  # onclick, onerror, etc.
    r"\[\s*INST\s*\]",  # LLM instruction tags
    r"\[\s*/?\s*SYS(TEM)?\s*\]",
    r"```\s*(system|assistant)\s*\n",
]

# Kompiler patterns for bedre performance
COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_PATTERNS]


def sanitize_input(text: str) -> str:
    """
    Saniterer brugerinput for potentielt skadeligt indhold.
    
    Args:
        text: Rå brugerinput
        
    Returns:
        Saniteret tekst
    """
    # Trim whitespace
    text = text.strip()
    
    # Fjern null bytes og andre kontrolkarakterer (behold newlines og tabs)
    text = ''.join(char for char in text if char.isprintable() or char in '\n\t')
    
    # Normaliser multiple whitespace
    text = re.sub(r'[ \t]+', ' ', text)
    text = re.sub(r'\n{3,}', '\n\n', text)
    
    return text


def check_for_injection(text: str) -> Optional[str]:
    """
    Checker for potentielle prompt injection forsøg.
    
    Args:
        text: Tekst at checke
        
    Returns:
        None hvis OK, ellers en besked om hvad der blev fundet
    """
    text_lower = text.lower()
    
    for pattern in COMPILED_PATTERNS:
        if pattern.search(text_lower):
            return f"Besked indeholder potentielt skadeligt indhold"
    
    return None


# ============================================================
# Source Metadata Model
# ============================================================
class SourceMetadata(BaseModel):
    """Metadata for en kilde brugt i RAG"""
    rank: int
    collection: str
    document: str
    page: str | int
    sourceUrl: Optional[str] = None
    relevance_score: Optional[float] = None
    chunk_preview: str


# ============================================================
# Request Models
# ============================================================
class ChatRAGRequest(BaseModel):
    """Request model for chat endpoint med validering og sanitering"""
    message: str
    session_id: Optional[str] = None
    prompt_key: Optional[str] = None
    
    @field_validator('message')
    @classmethod
    def validate_and_sanitize_message(cls, v: str) -> str:
        """Valider og saniter beskeden"""
        # Sanitér input
        v = sanitize_input(v)
        
        # Check for tom besked
        if not v:
            raise ValueError("Besked kan ikke være tom")
        
        # Check længde (simpel estimering: ~4 karakterer per token)
        estimated_tokens = len(v) // 4
        if estimated_tokens > MAX_INPUT_TOKENS:
            raise ValueError(
                f"Besked er for lang. Estimeret {estimated_tokens} tokens, "
                f"max {MAX_INPUT_TOKENS} tokens tilladt (~{MAX_INPUT_TOKENS * 4} tegn)"
            )
        
        # Check for injection forsøg
        injection_warning = check_for_injection(v)
        if injection_warning:
            raise ValueError(injection_warning)
        
        return v
    
    @field_validator('session_id')
    @classmethod
    def validate_session_id(cls, v: Optional[str]) -> Optional[str]:
        """Valider session_id format"""
        if v is None:
            return v
        
        # Sanitér
        v = v.strip()
        
        # Check format (UUID-lignende)
        if not re.match(r'^[a-zA-Z0-9\-]{8,64}$', v):
            raise ValueError("Ugyldigt session_id format")
        
        return v
    
    @field_validator('prompt_key')
    @classmethod
    def validate_prompt_key(cls, v: Optional[str]) -> Optional[str]:
        """Valider prompt_key format"""
        if v is None:
            return v
        
        # Sanitér
        v = v.strip()
        
        # Check format (simpelt alfanumerisk)
        if not re.match(r'^[a-zA-Z0-9_\-]{1,50}$', v):
            raise ValueError("Ugyldigt prompt_key format")
        
        return v


# ============================================================
# Response Models
# ============================================================
class ChatRAGResponse(BaseModel):
    """Response model for chat endpoint"""
    session_id: str
    response: str
    tokens: dict
    rag_context: Optional[str] = None
    sources_used: int
    sources_metadata: Optional[List[SourceMetadata]] = None


class HealthResponse(BaseModel):
    """Response model for health endpoint"""
    status: str
    service: str
    checks: Optional[dict] = None


class PromptsResponse(BaseModel):
    """Response model for prompts endpoint"""
    count: int
    prompts: dict


class CollectionsResponse(BaseModel):
    """Response model for collections endpoint"""
    count: int
    collections: List[str]


class HistoryResponse(BaseModel):
    """Response model for history endpoint"""
    session_id: str
    messages: List[dict]


class ResetResponse(BaseModel):
    """Response model for reset endpoint"""
    message: str
    session_id: str
