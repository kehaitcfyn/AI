"""
Chat RAG Service - Håndterer samtaler med RAG (Retrieval Augmented Generation)
==============================================================================
VERSION 2 - Med forbedret ChromaDB håndtering:
- Isolerede embeddings per collection (undgår data-blanding)
- Bedre fejlhåndtering og logging
- Collection health check
- Graceful degradation ved Chroma fejl
"""
import os
import asyncio
import hashlib
from datetime import datetime, timedelta
from collections import OrderedDict
from openai import AsyncOpenAI
from typing import Dict, List, Optional, Tuple, Any
from langchain_chroma import Chroma
from langchain_openai import OpenAIEmbeddings
from functools import lru_cache
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from openai import APIError, APIConnectionError, RateLimitError

from backend.config import (
    logger,
    PROMPT_DIR,
    CHROMA_BASE_DIR,
    TOP_K,
    OPENAI_MODEL,
    OPENAI_TEMPERATURE,
    MAX_SESSIONS,
    SESSION_TIMEOUT_HOURS,
    get_token_cost,
)


# ============================================================
# Session Data Structure
# ============================================================
class SessionData:
    """Container for session data"""
    def __init__(self, messages: List[dict], collection: str):
        self.messages = messages
        self.collection = collection
        self.last_activity = datetime.now()
        self.created_at = datetime.now()
    
    def touch(self):
        """Opdater last_activity timestamp"""
        self.last_activity = datetime.now()
    
    def is_expired(self, timeout_hours: int) -> bool:
        """Check om session er udløbet"""
        return datetime.now() - self.last_activity > timedelta(hours=timeout_hours)


# ============================================================
# Chat RAG Service
# ============================================================
class ChatRAGService:
    """
    Service til at håndtere chat med RAG-funktionalitet.
    
    VERSION 2 Features:
    - Isolerede embeddings per collection
    - Bedre fejlhåndtering for ChromaDB
    - Collection health checks
    - Graceful degradation
    """
    
    def __init__(self):
        self.client = AsyncOpenAI()
        self.sessions: OrderedDict[str, SessionData] = OrderedDict()
        
        # ÆNDRET: Separeret cache for vectordb og embeddings
        self._vectordb_cache: Dict[str, Chroma] = {}
        self._embeddings_cache: Dict[str, OpenAIEmbeddings] = {}
        
        self._cleanup_lock = asyncio.Lock()
        
        # Log startup info
        logger.info(f"ChatRAGService initialiseret")
        logger.info(f"  CHROMA_BASE_DIR: {CHROMA_BASE_DIR}")
        logger.info(f"  PROMPT_DIR: {PROMPT_DIR}")
        logger.info(f"  TOP_K: {TOP_K}")
        
        # Verificér at Chroma dir eksisterer
        if os.path.exists(CHROMA_BASE_DIR):
            collections = self.list_collections()
            logger.info(f"  Tilgængelige collections: {collections}")
        else:
            logger.warning(f"  CHROMA_BASE_DIR findes ikke: {CHROMA_BASE_DIR}")
    
    # ============================================================
    # Session Management
    # ============================================================
    async def _cleanup_expired_sessions(self):
        """Fjern udløbne sessions og hold under max limit"""
        async with self._cleanup_lock:
            now = datetime.now()
            expired_count = 0
            
            # Find og fjern udløbne sessions
            expired_sessions = [
                sid for sid, session in self.sessions.items()
                if session.is_expired(SESSION_TIMEOUT_HOURS)
            ]
            
            for sid in expired_sessions:
                del self.sessions[sid]
                expired_count += 1
            
            # Hvis stadig over max, fjern de ældste
            evicted_count = 0
            while len(self.sessions) > MAX_SESSIONS:
                self.sessions.popitem(last=False)
                evicted_count += 1
            
            if expired_count > 0 or evicted_count > 0:
                logger.info(
                    f"Session cleanup: {expired_count} udløbet, "
                    f"{evicted_count} evicted, {len(self.sessions)} aktive"
                )
    
    def get_session_stats(self) -> dict:
        """Returner session statistik"""
        return {
            "active_sessions": len(self.sessions),
            "max_sessions": MAX_SESSIONS,
            "timeout_hours": SESSION_TIMEOUT_HOURS,
            "cached_collections": list(self._vectordb_cache.keys()),
        }
    
    # ============================================================
    # Prompt Management
    # ============================================================
    def load_system_prompts(self) -> Dict[str, dict]:
        """Indlæser alle system prompts fra prompts-mappen"""
        prompts = {}
        
        if not os.path.exists(PROMPT_DIR):
            os.makedirs(PROMPT_DIR)
            logger.warning(f"Prompt directory oprettet: {PROMPT_DIR}")
            return prompts
        
        files = [f for f in os.listdir(PROMPT_DIR) if f.endswith(".txt")]
        
        for file in sorted(files):
            key = file.split("_")[0]
            filename_without_ext = file.replace(".txt", "")
            parts = filename_without_ext.split("_", 1)
            collection_name = parts[1] if len(parts) > 1 else filename_without_ext
            
            filepath = os.path.join(PROMPT_DIR, file)
            
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    prompts[key] = {
                        "name": file.replace(".txt", "").replace("_", " ").title(),
                        "filename": file,
                        "content": f.read().strip(),
                        "collection": collection_name
                    }
                    logger.debug(f"Loaded prompt: {key} -> {collection_name}")
            except Exception as e:
                logger.error(f"Kunne ikke indlæse {file}: {e}")
        
        logger.info(f"Indlæst {len(prompts)} system prompts")
        return prompts
    
    # ============================================================
    # ChromaDB Management - FORBEDRET
    # ============================================================
    def list_collections(self) -> List[str]:
        """Lister alle tilgængelige Chroma collections"""
        if not os.path.exists(CHROMA_BASE_DIR):
            logger.warning(f"CHROMA_BASE_DIR findes ikke: {CHROMA_BASE_DIR}")
            return []
        return [
            d for d in os.listdir(CHROMA_BASE_DIR) 
            if os.path.isdir(os.path.join(CHROMA_BASE_DIR, d))
        ]
    
    def check_collection_health(self, collection_name: str) -> dict:
        """
        Tjek health status for en collection.
        
        Returns:
            dict med status info
        """
        collection_path = os.path.join(CHROMA_BASE_DIR, collection_name)
        
        result = {
            "collection": collection_name,
            "path": collection_path,
            "exists": False,
            "accessible": False,
            "chunk_count": 0,
            "error": None
        }
        
        if not os.path.exists(collection_path):
            result["error"] = "Path does not exist"
            return result
        
        result["exists"] = True
        
        # List filer i collection
        try:
            files = os.listdir(collection_path)
            result["files"] = files
        except Exception as e:
            result["error"] = f"Cannot list directory: {e}"
            return result
        
        # Prøv at åbne collection
        try:
            # Opret ny embeddings instans til test
            test_embeddings = OpenAIEmbeddings(
                request_timeout=30,
                max_retries=2
            )
            
            vectordb = Chroma(
                persist_directory=collection_path,
                embedding_function=test_embeddings,
                collection_name=collection_name
            )
            
            # Hent antal chunks
            all_docs = vectordb.get(include=[])
            result["chunk_count"] = len(all_docs.get("ids", []))
            result["accessible"] = True
            
        except Exception as e:
            result["error"] = f"Cannot access collection: {str(e)}"
            logger.error(f"Collection health check failed for {collection_name}: {e}")
        
        return result
    
    def _get_embeddings(self, collection_name: str) -> OpenAIEmbeddings:
        """
        Hent eller opret embeddings instans for en collection.
        HVER collection får sin egen instans for at undgå problemer.
        """
        if collection_name not in self._embeddings_cache:
            logger.debug(f"Opretter ny embeddings instans for: {collection_name}")
            self._embeddings_cache[collection_name] = OpenAIEmbeddings(
                request_timeout=60,
                max_retries=3
            )
        return self._embeddings_cache[collection_name]
    
    def _get_vectordb(self, collection_name: str, force_new: bool = False) -> Optional[Chroma]:
        """
        Hent eller opret cached ChromaDB connection.
        
        FORBEDRET:
        - Hver collection får sin egen embeddings instans
        - Bedre fejlhåndtering
        - force_new parameter til at tvinge ny connection
        
        Args:
            collection_name: Navn på collection
            force_new: Tving oprettelse af ny connection
            
        Returns:
            Chroma instance eller None hvis ikke fundet
        """
        # Fjern fra cache hvis force_new
        if force_new and collection_name in self._vectordb_cache:
            logger.info(f"Fjerner cached connection for: {collection_name}")
            del self._vectordb_cache[collection_name]
            if collection_name in self._embeddings_cache:
                del self._embeddings_cache[collection_name]
        
        if collection_name not in self._vectordb_cache:
            collection_path = os.path.join(CHROMA_BASE_DIR, collection_name)
            
            # Tjek at path eksisterer
            if not os.path.exists(collection_path):
                logger.warning(f"Collection path ikke fundet: {collection_path}")
                return None
            
            # Tjek at der er filer i mappen
            try:
                files = os.listdir(collection_path)
                if not files:
                    logger.warning(f"Collection mappe er tom: {collection_path}")
                    return None
                logger.debug(f"Collection {collection_name} indeholder: {files}")
            except Exception as e:
                logger.error(f"Kan ikke læse collection mappe: {e}")
                return None
            
            try:
                # Hent isoleret embeddings instans
                embeddings = self._get_embeddings(collection_name)
                
                # Opret Chroma connection
                self._vectordb_cache[collection_name] = Chroma(
                    persist_directory=collection_path,
                    embedding_function=embeddings,
                    collection_name=collection_name
                )
                
                # Verificér at collection er tilgængelig
                test_result = self._vectordb_cache[collection_name].get(include=[], limit=1)
                logger.info(f"ChromaDB connection oprettet: {collection_name}")
                
            except Exception as e:
                logger.error(f"Fejl ved oprettelse af ChromaDB connection for {collection_name}: {e}", exc_info=True)
                
                # Ryd op ved fejl
                if collection_name in self._vectordb_cache:
                    del self._vectordb_cache[collection_name]
                if collection_name in self._embeddings_cache:
                    del self._embeddings_cache[collection_name]
                    
                return None
        
        return self._vectordb_cache.get(collection_name)
    
    def clear_collection_cache(self, collection_name: str = None):
        """
        Ryd collection cache.
        
        Args:
            collection_name: Specifik collection at rydde, eller None for alle
        """
        if collection_name:
            if collection_name in self._vectordb_cache:
                del self._vectordb_cache[collection_name]
            if collection_name in self._embeddings_cache:
                del self._embeddings_cache[collection_name]
            logger.info(f"Cache ryddet for: {collection_name}")
        else:
            self._vectordb_cache.clear()
            self._embeddings_cache.clear()
            logger.info("Al collection cache ryddet")
    
    def _get_query_hash(self, query: str, collection: str) -> str:
        """Generer hash for query caching"""
        return hashlib.md5(f"{query}:{collection}".encode()).hexdigest()
    
    def get_rag_context(
        self, 
        user_query: str, 
        collection_name: str
    ) -> Tuple[str, int, List[dict]]:
        """
        Henter RAG-kontekst fra Chroma collection med metadata.
        
        FORBEDRET:
        - Bedre fejlhåndtering
        - Retry ved fejl med ny connection
        - Graceful degradation
        
        Args:
            user_query: Brugerens spørgsmål
            collection_name: Navn på collection at søge i
            
        Returns:
            Tuple med (context_string, antal_kilder, sources_metadata)
        """
        # Første forsøg
        vectordb = self._get_vectordb(collection_name)
        
        if vectordb is None:
            logger.warning(f"Collection ikke tilgængelig: {collection_name}")
            return "", 0, []
        
        # Forsøg query med retry
        for attempt in range(2):
            try:
                # Hent dokumenter med metadata
                results = vectordb.similarity_search_with_score(user_query, k=TOP_K)
                
                if not results:
                    logger.info(f"Ingen dokumenter fundet i collection: {collection_name}")
                    return "", 0, []
                
                context_parts = []
                sources_metadata = []
                
                for idx, (doc, score) in enumerate(results, 1):
                    metadata = doc.metadata
                    source_name = metadata.get("source", "Ukendt kilde")
                    page = metadata.get("page", metadata.get("page_number", "N/A"))
                    
                    # Verificér at data kommer fra korrekt collection
                    doc_collection = metadata.get("collection", "unknown")
                    if doc_collection != collection_name:
                        logger.warning(
                            f"Data mismatch! Forventet {collection_name}, "
                            f"fik {doc_collection} fra {source_name}"
                        )
                    
                    context_parts.append(doc.page_content)
                    
                    sources_metadata.append({
                        "rank": idx,
                        "collection": collection_name,
                        "document": source_name,
                        "page": page,
                        "sourceUrl": metadata.get("sourceUrl", ""),
                        "relevance_score": round(1 - score, 4) if score else None,
                        "chunk_preview": (
                            doc.page_content[:150] + "..." 
                            if len(doc.page_content) > 150 
                            else doc.page_content
                        )
                    })
                
                context = "\n\n".join(context_parts)
                logger.info(f"RAG: {len(results)} dokumenter fundet i {collection_name}")
                
                return context, len(results), sources_metadata
                
            except Exception as e:
                logger.error(f"Fejl ved RAG query (forsøg {attempt + 1}): {e}", exc_info=True)
                
                if attempt == 0:
                    # Første fejl - prøv med ny connection
                    logger.info(f"Prøver med ny connection til {collection_name}...")
                    vectordb = self._get_vectordb(collection_name, force_new=True)
                    
                    if vectordb is None:
                        logger.error(f"Kunne ikke genoprette connection til {collection_name}")
                        return "", 0, []
                else:
                    # Anden fejl - giv op
                    logger.error(f"RAG query fejlede efter retry for {collection_name}")
                    return "", 0, []
        
        return "", 0, []
    
    # ============================================================
    # Conversation Management
    # ============================================================
    async def create_conversation(
        self, 
        session_id: str, 
        prompt_key: str
    ) -> Optional[str]:
        """
        Opretter en ny samtale med valgt prompt.
        
        Args:
            session_id: Unik session identifier
            prompt_key: Nøgle til system prompt
            
        Returns:
            Prompt navn eller None hvis fejl
        """
        # Cleanup gamle sessions
        await self._cleanup_expired_sessions()
        
        prompts = self.load_system_prompts()
        if prompt_key not in prompts:
            logger.warning(f"Prompt ikke fundet: {prompt_key}")
            return None
        
        system_prompt = prompts[prompt_key]["content"]
        collection_name = prompts[prompt_key]["collection"]
        
        # Verificér at collection er tilgængelig
        vectordb = self._get_vectordb(collection_name)
        if vectordb is None:
            logger.warning(f"Collection {collection_name} ikke tilgængelig for prompt {prompt_key}")
            # Fortsæt alligevel - chat kan fungere uden RAG
        
        # Opret session data
        session = SessionData(
            messages=[{"role": "system", "content": system_prompt}],
            collection=collection_name
        )
        
        self.sessions[session_id] = session
        
        logger.info(f"Samtale oprettet: session={session_id[:8]}..., collection={collection_name}")
        
        return prompts[prompt_key]["name"]
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type((APIError, APIConnectionError, RateLimitError)),
        before_sleep=lambda retry_state: logger.warning(
            f"OpenAI API fejl, retry {retry_state.attempt_number}/3..."
        )
    )
    async def _call_openai(
        self, 
        messages: List[dict], 
        max_tokens: int
    ) -> Any:
        """
        Kald OpenAI API med retry logic.
        
        Args:
            messages: Chat messages
            max_tokens: Max output tokens
            
        Returns:
            OpenAI completion response
        """
        return await self.client.chat.completions.create(
            model=OPENAI_MODEL,
            temperature=OPENAI_TEMPERATURE,
            messages=messages,
            max_tokens=max_tokens
        )
    
    async def send_message(
        self, 
        session_id: str, 
        message: str, 
        max_output_tokens: int = 300
    ) -> dict:
        """
        Sender en besked og får svar fra AI med RAG.
        
        Args:
            session_id: Samtale ID
            message: Brugerens besked
            max_output_tokens: Maksimalt antal output tokens
            
        Returns:
            dict med response, tokens, rag_context, sources_used, sources_metadata
            
        Raises:
            ValueError: Hvis samtale ikke findes
        """
        if session_id not in self.sessions:
            raise ValueError("Samtale ikke fundet")
        
        session = self.sessions[session_id]
        session.touch()  # Opdater aktivitet
        
        # Hent RAG-kontekst
        rag_context = ""
        sources_used = 0
        sources_metadata = []
        
        if session.collection:
            try:
                rag_context, sources_used, sources_metadata = self.get_rag_context(
                    message, session.collection
                )
            except Exception as e:
                logger.error(f"RAG context fejl (fortsætter uden): {e}")
                # Fortsæt uden RAG - bedre end at fejle helt
        
        # Tilføj brugerens besked
        session.messages.append({
            "role": "user",
            "content": message
        })
        
        # Byg messages med RAG-kontekst
        messages = session.messages.copy()
        if rag_context:
            messages.insert(-1, {
                "role": "system",
                "content": f"Kontekst fra dokumenter:\n{rag_context}"
            })
        
        try:
            # Kald OpenAI API (async med retry)
            response = await self._call_openai(messages, max_output_tokens)
            
            ai_message = response.choices[0].message.content
            finish_reason = response.choices[0].finish_reason
            
            # Advar hvis svaret blev afbrudt pga. token-grænse
            if finish_reason == "length":
                logger.warning(f"Svar afbrudt - nåede max_tokens ({max_output_tokens})")
                ai_message += "\n\n[Svaret blev afkortet pga. token-begrænsning]"
            
            # Gem AI's svar
            session.messages.append({
                "role": "assistant",
                "content": ai_message
            })
            
            # Beregn tokens og pris
            usage = response.usage
            input_tokens = usage.prompt_tokens
            output_tokens = usage.completion_tokens
            
            # Brug config-baseret pricing
            costs = get_token_cost(OPENAI_MODEL, input_tokens, output_tokens)
            
            return {
                "response": ai_message,
                "rag_context": rag_context if rag_context else None,
                "sources_used": sources_used,
                "sources_metadata": sources_metadata,
                "tokens": {
                    "input": input_tokens,
                    "output": output_tokens,
                    "max_output": max_output_tokens,
                    "finish_reason": finish_reason,
                    **costs
                }
            }
            
        except Exception as e:
            # Fjern den fejlede besked
            session.messages.pop()
            logger.error(f"Fejl ved send_message: {e}", exc_info=True)
            raise
    
    async def reset_conversation(
        self, 
        session_id: str, 
        prompt_key: str
    ) -> Optional[str]:
        """Nulstiller en samtale"""
        return await self.create_conversation(session_id, prompt_key)
    
    def get_history(self, session_id: str) -> List[dict]:
        """Henter samtalehistorik"""
        session = self.sessions.get(session_id)
        if session:
            session.touch()
            return session.messages
        return []


# ============================================================
# Singleton Instance
# ============================================================
chat_service = ChatRAGService()
