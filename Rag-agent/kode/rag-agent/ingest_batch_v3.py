###Embeddings
### Når du ikke angiver en specifik model, bruger OpenAIEmbeddings() som standard text-embedding-ada-002
# =============================================================================
# VERSION 5 - ISOLEREDE FORBINDELSER PER COLLECTION
# =============================================================================
# VIGTIGE ÆNDRINGER fra v4:
# - HVER collection får sin egen ISOLEREDE Chroma client
# - Eksplicit lukning af forbindelser mellem collections
# - Ny embedding-instans for hver collection
# - Tilføjet collection verification efter ingest
# - Bedre separation af data mellem collections
# =============================================================================

import os
import hashlib
import time
import gc  # Garbage collector til at rydde op
from datetime import datetime
from dotenv import load_dotenv
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_chroma import Chroma
from langchain_openai import OpenAIEmbeddings
from langchain_core.documents import Document
import warnings

# Document loaders
try:
    from langchain_community.document_loaders import (
        PyPDFLoader,
        Docx2txtLoader,
        UnstructuredMarkdownLoader,
        TextLoader
    )
    LOADERS_AVAILABLE = True
except ImportError as e:
    print(f"⚠️  Advarsel: Kunne ikke importere document loaders: {e}")
    print(f"   Installer med: pip install langchain-community pypdf docx2txt unstructured markdown")
    LOADERS_AVAILABLE = False

# Ignorer deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Indlæs miljøvariabler
load_dotenv()

# --- Konfiguration ---
DOCS_BASE_DIR = "documents"
CHROMA_BASE_DIR = "chroma_collections"
PROMPT_DIR = "prompts"
CHUNK_SIZE = 500
CHUNK_OVERLAP = 50
SERVER_BASE_URL = "https://server.dk/files/"

# =============================================================================
# TIMEOUT OG RETRY KONFIGURATION
# =============================================================================
MAX_RETRIES = 3
RETRY_BASE_DELAY = 5
DELAY_BETWEEN_DOCUMENTS = 1
DELAY_BETWEEN_COLLECTIONS = 5      # ØGET: Mere tid mellem collections
BATCH_SIZE = 10
BATCH_DELAY = 10
EMBEDDING_TIMEOUT = 60

# Ekskluder specifikke collections fra ingest
EXCLUDED_COLLECTIONS = [
    "retsinfo",
]


# =============================================================================
# COLLECTION MANAGER - ISOLERER FORBINDELSER
# =============================================================================
class CollectionManager:
    """
    Manager klasse der sikrer at hver collection har sin egen isolerede forbindelse.
    Dette forhindrer data-blanding mellem collections.
    """
    
    def __init__(self, collection_name: str):
        self.collection_name = collection_name
        self.persist_directory = os.path.join(CHROMA_BASE_DIR, collection_name)
        self._vectordb = None
        self._embedding_function = None
        
    def __enter__(self):
        """Context manager entry - opret ny isoleret forbindelse."""
        print(f"   🔌 Opretter isoleret forbindelse til: {self.collection_name}")
        
        # Opret ALTID ny embedding instans for hver collection
        self._embedding_function = OpenAIEmbeddings(
            request_timeout=EMBEDDING_TIMEOUT,
            max_retries=MAX_RETRIES
        )
        
        # Opret mappe hvis den ikke findes
        os.makedirs(self.persist_directory, exist_ok=True)
        
        # Opret ny Chroma forbindelse
        self._vectordb = Chroma(
            persist_directory=self.persist_directory,
            embedding_function=self._embedding_function,
            collection_name=self.collection_name
        )
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - luk og ryd op."""
        print(f"   🔒 Lukker forbindelse til: {self.collection_name}")
        
        # Eksplicit ryd op
        self._vectordb = None
        self._embedding_function = None
        
        # Force garbage collection for at frigøre ressourcer
        gc.collect()
        
        # Vent lidt for at sikre alt er lukket
        time.sleep(1)
        
        return False  # Don't suppress exceptions
    
    @property
    def vectordb(self) -> Chroma:
        """Returnér den aktive vectordb."""
        if self._vectordb is None:
            raise RuntimeError("CollectionManager skal bruges som context manager (with statement)")
        return self._vectordb
    
    def verify_collection(self) -> dict:
        """Verificér at data er gemt korrekt i denne collection."""
        try:
            all_docs = self._vectordb.get(include=["metadatas"])
            
            # Tæl dokumenter per collection metadata
            collection_counts = {}
            for metadata in all_docs.get("metadatas", []):
                col = metadata.get("collection", "unknown")
                collection_counts[col] = collection_counts.get(col, 0) + 1
            
            return {
                "total_chunks": len(all_docs.get("ids", [])),
                "collection_distribution": collection_counts
            }
        except Exception as e:
            return {"error": str(e)}


# =============================================================================
# RETRY DECORATOR
# =============================================================================
def retry_with_backoff(max_retries=MAX_RETRIES, base_delay=RETRY_BASE_DELAY):
    """Decorator der tilføjer retry-logik med eksponentiel backoff."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_retries - 1:
                        wait_time = base_delay * (2 ** attempt)
                        print(f"      ⚠️  Forsøg {attempt + 1}/{max_retries} fejlede: {str(e)[:100]}")
                        print(f"      ⏳ Venter {wait_time} sekunder...")
                        time.sleep(wait_time)
                    else:
                        print(f"      ❌ Alle {max_retries} forsøg fejlede")
            raise last_exception
        return wrapper
    return decorator


# =============================================================================
# RATE LIMITER
# =============================================================================
class RateLimiter:
    def __init__(self, delay_between_calls=1.0):
        self.delay = delay_between_calls
        self.last_call_time = 0
    
    def wait(self):
        elapsed = time.time() - self.last_call_time
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self.last_call_time = time.time()

rate_limiter = RateLimiter(delay_between_calls=DELAY_BETWEEN_DOCUMENTS)


# =============================================================================
# HJÆLPEFUNKTIONER
# =============================================================================
def file_hash(path: str) -> str:
    """Beregn SHA256 hash af fil"""
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    return sha.hexdigest()


def get_file_metadata(path: str) -> dict:
    """Hent detaljeret fil metadata"""
    stat = os.stat(path)
    file_ext = os.path.splitext(path)[1].lower()
    
    return {
        "file_size": stat.st_size,
        "file_extension": file_ext,
        "file_type": get_file_type(file_ext),
        "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
        "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
    }


def get_file_type(extension: str) -> str:
    """Klassificer filtype"""
    type_mapping = {
        '.txt': 'text', '.md': 'markdown', '.pdf': 'pdf',
        '.docx': 'word', '.doc': 'word', '.xlsx': 'excel',
        '.csv': 'csv', '.json': 'json', '.xml': 'xml',
        '.html': 'html', '.py': 'code', '.js': 'code', '.java': 'code',
    }
    return type_mapping.get(extension, 'unknown')


def sync_folders_with_prompts():
    """Synkroniser mapper med prompt-filer."""
    print("\n" + "═" * 60)
    print("🔄 SYNKRONISERER MAPPER MED PROMPT-FILER")
    print("═" * 60)
    
    if not os.path.exists(PROMPT_DIR):
        print(f"⚠️  Prompt-mappe '{PROMPT_DIR}' findes ikke")
        return []
    
    prompt_files = [f for f in os.listdir(PROMPT_DIR) if f.endswith(".txt")]
    
    if not prompt_files:
        print(f"⚠️  Ingen prompt-filer fundet i '{PROMPT_DIR}'")
        return []
    
    collections_from_prompts = []
    
    for prompt_file in sorted(prompt_files):
        filename_without_ext = prompt_file.replace(".txt", "")
        parts = filename_without_ext.split("_", 1)
        
        if len(parts) < 2:
            continue
        
        collection_name = parts[1]
        collections_from_prompts.append(collection_name)
        
        collection_path = os.path.join(DOCS_BASE_DIR, collection_name)
        
        if not os.path.exists(collection_path):
            os.makedirs(collection_path)
            print(f"   📁 OPRETTET: {collection_name}/")
        else:
            print(f"   ✅ EXISTS:   {collection_name}/")
    
    print(f"\n📋 {len(collections_from_prompts)} collections synkroniseret")
    print("═" * 60 + "\n")
    
    return collections_from_prompts


@retry_with_backoff()
def load_document(path: str) -> tuple:
    """Load document baseret på filtype."""
    file_ext = os.path.splitext(path)[1].lower()
    extra_metadata = {}
    
    if not LOADERS_AVAILABLE:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read(), {}
    
    try:
        if file_ext == '.pdf':
            loader = PyPDFLoader(path)
            pages = loader.load()
            
            text_parts = []
            page_mapping = {}
            
            for page_num, page in enumerate(pages, 1):
                page_text = page.page_content
                page_start = len('\n\n'.join(text_parts))
                page_mapping[page_start] = page_num
                text_parts.append(f"[Side {page_num}]\n{page_text}")
            
            text = '\n\n'.join(text_parts)
            extra_metadata['total_pages'] = len(pages)
            extra_metadata['page_mapping'] = page_mapping
            print(f"      📕 PDF loaded ({len(pages)} sider)")
            
        elif file_ext in ['.docx', '.doc']:
            loader = Docx2txtLoader(path)
            docs = loader.load()
            text = '\n\n'.join([doc.page_content for doc in docs])
            print(f"      📘 Word dokument loaded")
            
        elif file_ext == '.md':
            loader = UnstructuredMarkdownLoader(path)
            docs = loader.load()
            text = '\n\n'.join([doc.page_content for doc in docs])
            print(f"      📗 Markdown loaded")
            
        elif file_ext == '.txt':
            loader = TextLoader(path, encoding='utf-8')
            docs = loader.load()
            text = '\n\n'.join([doc.page_content for doc in docs])
            print(f"      📄 Text fil loaded")
            
        else:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        
        return text, extra_metadata
        
    except Exception as e:
        print(f"      ❌ Fejl ved loading: {e}")
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read(), {}


def get_page_number_for_chunk(chunk_index: int, chunk_size: int, page_mapping: dict = None) -> int:
    """Bestem sidenummer for en chunk."""
    if page_mapping:
        start_char = chunk_index * (chunk_size - CHUNK_OVERLAP)
        closest_page = 1
        for page_start, page_num in sorted(page_mapping.items()):
            if page_start <= start_char:
                closest_page = page_num
            else:
                break
        return closest_page
    else:
        chars_per_page = 2500
        start_char = chunk_index * (chunk_size - CHUNK_OVERLAP)
        return (start_char // chars_per_page) + 1


def split_document(text: str):
    """Split document i chunks"""
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE,
        chunk_overlap=CHUNK_OVERLAP,
        length_function=len,
        separators=["\n\n", "\n", ". ", " ", ""]
    )
    return splitter.create_documents([text])


def calculate_chunk_position(chunk_index: int, total_chunks: int) -> str:
    """Beregn position i dokumentet"""
    if total_chunks <= 1:
        return "complete"
    position_ratio = chunk_index / (total_chunks - 1)
    if position_ratio < 0.2:
        return "start"
    elif position_ratio > 0.8:
        return "end"
    return "middle"


def extract_keywords(text: str, max_keywords: int = 5) -> list:
    """Simpel keyword extraction"""
    stop_words = {
        'og', 'i', 'at', 'er', 'en', 'et', 'til', 'af', 'for', 'på', 
        'med', 'som', 'der', 'den', 'det', 'de', 'om', 'har', 'ikke',
        'kan', 'vil', 'var', 'ved', 'også', 'blev', 'være', 'fra',
        'efter', 'eller', 'skal', 'side'
    }
    
    words = text.lower().split()
    word_freq = {}
    
    for word in words:
        clean_word = ''.join(c for c in word if c.isalnum())
        if len(clean_word) >= 3 and clean_word not in stop_words:
            word_freq[clean_word] = word_freq.get(clean_word, 0) + 1
    
    sorted_words = sorted(word_freq.items(), key=lambda x: x[1], reverse=True)
    return [word for word, _ in sorted_words[:max_keywords]]


# =============================================================================
# HOVEDFUNKTIONER MED ISOLEREDE FORBINDELSER
# =============================================================================

def cleanup_deleted_documents(manager: CollectionManager, existing_files: list) -> int:
    """
    Fjerner dokumenter fra databasen som ikke længere findes i filsystemet.
    BRUGER NU CollectionManager for isoleret forbindelse.
    """
    try:
        all_docs = manager.vectordb.get(include=["metadatas"])
        
        if not all_docs["metadatas"]:
            return 0
        
        docs_in_db = set()
        for metadata in all_docs["metadatas"]:
            if "document" in metadata:
                docs_in_db.add(metadata["document"])
        
        files_set = set(existing_files)
        docs_to_delete = docs_in_db - files_set
        
        deleted_count = 0
        for doc_name in docs_to_delete:
            document_id = doc_name.replace(".", "_")
            rate_limiter.wait()
            
            try:
                manager.vectordb.delete(where={"document_id": document_id})
                print(f"   🗑️  SLETTET fra database: {doc_name}")
                deleted_count += 1
            except Exception as e:
                print(f"   ⚠️  Kunne ikke slette {doc_name}: {e}")
        
        return deleted_count
        
    except Exception as e:
        print(f"   ⚠️  Fejl ved oprydning: {e}")
        return 0


def ingest_document(manager: CollectionManager, doc_path: str, doc_number: int = 0, total_docs: int = 0) -> int:
    """
    Ingest et enkelt dokument.
    BRUGER NU CollectionManager for isoleret forbindelse.
    """
    collection_name = manager.collection_name
    doc_name = os.path.basename(doc_path)
    progress_str = f"[{doc_number}/{total_docs}] " if total_docs > 0 else ""
    
    try:
        sha256 = file_hash(doc_path)
        file_meta = get_file_metadata(doc_path)
    except Exception as e:
        print(f"   ❌ {progress_str}Kunne ikke læse fil metadata for {doc_name}: {e}")
        return 0

    print(f"   📄 {progress_str}{doc_name}")

    rate_limiter.wait()

    document_id = doc_name.replace(".", "_")
    
    # Check om dokument allerede findes
    try:
        existing = manager.vectordb.get(where={"document_id": document_id}, include=["metadatas"])
    except Exception as e:
        print(f"      ⚠️  Fejl ved check af eksisterende dokument: {e}")
        existing = {"metadatas": []}
    
    if existing["metadatas"]:
        if existing["metadatas"][0].get("sha256") == sha256:
            print(f"      ✅ [SKIP] Uændret")
            return 0
        else:
            print(f"      🔄 [UPDATE] Fil ændret - genindlæser...")
            try:
                rate_limiter.wait()
                manager.vectordb.delete(where={"document_id": document_id})
            except Exception as e:
                print(f"      ⚠️  Fejl ved sletning: {e}")

    # Load dokument
    try:
        text, extra_metadata = load_document(doc_path)
    except Exception as e:
        print(f"      ❌ Kunne ikke indlæse dokument: {e}")
        return 0
    
    if not text or len(text.strip()) == 0:
        print(f"      ⚠️  Tomt dokument - springer over")
        return 0
    
    # Split
    docs = split_document(text)
    total_chunks = len(docs)
    ingested_at = datetime.now().isoformat()
    
    print(f"      📊 Chunks: {total_chunks}")

    # Metadata - VIGTIGT: Sæt collection_name eksplicit
    for idx, doc in enumerate(docs):
        chunk_text = doc.page_content
        
        doc.metadata["document"] = doc_name
        doc.metadata["source"] = doc_name
        doc.metadata["sourceUrl"] = SERVER_BASE_URL + doc_name
        doc.metadata["document_id"] = document_id
        doc.metadata["collection"] = collection_name  # EKSPLICIT COLLECTION
        doc.metadata["sha256"] = sha256
        doc.metadata["ingested_at"] = ingested_at
        doc.metadata["file_modified_at"] = file_meta["modified_at"]
        doc.metadata["file_size"] = file_meta["file_size"]
        doc.metadata["file_extension"] = file_meta["file_extension"]
        doc.metadata["file_type"] = file_meta["file_type"]
        doc.metadata["chunk_index"] = idx
        doc.metadata["chunk_number"] = idx + 1
        doc.metadata["total_chunks"] = total_chunks
        
        page_mapping = extra_metadata.get('page_mapping')
        doc.metadata["page"] = get_page_number_for_chunk(idx, CHUNK_SIZE, page_mapping)
        
        if 'total_pages' in extra_metadata:
            doc.metadata["total_pages"] = extra_metadata['total_pages']
        
        doc.metadata["position"] = calculate_chunk_position(idx, total_chunks)
        doc.metadata["chunk_length"] = len(chunk_text)
        doc.metadata["word_count"] = len(chunk_text.split())
        
        keywords = extract_keywords(chunk_text)
        doc.metadata["keywords"] = ",".join(keywords)
        doc.metadata["has_numbers"] = any(char.isdigit() for char in chunk_text)
        doc.metadata["is_complete_sentence"] = chunk_text.strip().endswith(('.', '!', '?'))
        
        words = chunk_text.split()
        doc.metadata["avg_word_length"] = sum(len(w) for w in words) / max(len(words), 1)
        
        first_line = chunk_text.split('\n')[0][:100]
        doc.metadata["preview"] = first_line

    # Gem dokumenter
    @retry_with_backoff()
    def add_documents_with_retry():
        rate_limiter.wait()
        manager.vectordb.add_documents(docs)
    
    try:
        add_documents_with_retry()
    except Exception as e:
        print(f"      ❌ Kunne ikke gemme dokument: {e}")
        return 0
    
    status = "UPDATE" if existing["metadatas"] else "INGEST"
    print(f"      ✅ [{status}] Gemt til collection: {collection_name}")
    
    return total_chunks


def process_collection(collection_name: str, collection_path: str) -> dict:
    """
    Processér alle dokumenter i en collection.
    BRUGER NU CollectionManager for isoleret forbindelse.
    """
    stats = {
        "processed": 0,
        "skipped": 0,
        "deleted": 0,
        "chunks": 0,
        "errors": 0,
        "verification": None
    }
    
    files_in_collection = [
        f for f in os.listdir(collection_path) 
        if os.path.isfile(os.path.join(collection_path, f))
        and not f.startswith('.')
        and os.path.splitext(f)[1].lower() in ['.pdf', '.docx', '.doc', '.md', '.txt']
    ]
    
    # BRUG CONTEXT MANAGER FOR ISOLERET FORBINDELSE
    with CollectionManager(collection_name) as manager:
        
        if not files_in_collection:
            print(f"   ⚠️  Ingen understøttede filer fundet")
            deleted = cleanup_deleted_documents(manager, [])
            if deleted > 0:
                print(f"   🧹 Oprydning: {deleted} forældede dokumenter fjernet")
                stats["deleted"] = deleted
            return stats
        
        total_files = len(files_in_collection)
        print(f"   📋 Filer fundet: {total_files}\n")
        
        # Oprydning
        deleted = cleanup_deleted_documents(manager, files_in_collection)
        if deleted > 0:
            print(f"   🧹 Oprydning: {deleted} forældede dokumenter fjernet\n")
            stats["deleted"] = deleted
        
        # Process filer
        for idx, file in enumerate(sorted(files_in_collection), 1):
            doc_path = os.path.join(collection_path, file)
            
            try:
                chunks = ingest_document(manager, doc_path, idx, total_files)
                
                if chunks > 0:
                    stats["processed"] += 1
                    stats["chunks"] += chunks
                else:
                    stats["skipped"] += 1
            except Exception as e:
                print(f"      ❌ Uventet fejl ved {file}: {e}")
                stats["errors"] += 1
            
            # Batch pause
            if idx % BATCH_SIZE == 0 and idx < total_files:
                print(f"\n   ⏸️  Batch pause ({BATCH_DELAY}s)...")
                time.sleep(BATCH_DELAY)
                print(f"   ▶️  Fortsætter...\n")
        
        # VERIFICÉR at data er gemt korrekt
        print(f"\n   🔍 Verificerer collection...")
        verification = manager.verify_collection()
        stats["verification"] = verification
        
        if "error" not in verification:
            print(f"   ✅ Chunks i collection: {verification['total_chunks']}")
            
            # Tjek for data-blanding
            dist = verification.get("collection_distribution", {})
            if len(dist) > 1:
                print(f"   ⚠️  ADVARSEL: Fundet data fra flere collections!")
                for col, count in dist.items():
                    print(f"      - {col}: {count} chunks")
            elif collection_name in dist:
                print(f"   ✅ Alle chunks tilhører korrekt collection")
        else:
            print(f"   ⚠️  Kunne ikke verificere: {verification['error']}")
    
    # Context manager lukker forbindelsen her
    return stats


# =============================================================================
# MAIN
# =============================================================================
if __name__ == "__main__":
    start_time = time.time()
    
    print("╔══════════════════════════════════════════════════════════╗")
    print("║       🚀 BATCH DOCUMENT INGESTION PIPELINE v5 🚀          ║")
    print("║       (Isolerede forbindelser per collection)             ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"\n📂 Dokument mappe:  {DOCS_BASE_DIR}")
    print(f"💾 Database mappe:  {CHROMA_BASE_DIR}")
    print(f"📝 Prompt mappe:    {PROMPT_DIR}")
    print(f"📏 Chunk størrelse: {CHUNK_SIZE} chars (overlap: {CHUNK_OVERLAP})")
    print(f"🔗 Server URL:      {SERVER_BASE_URL}")
    print(f"\n⚙️  Retry config:   {MAX_RETRIES} forsøg, {RETRY_BASE_DELAY}s base delay")
    print(f"⏱️  Rate limiting:  {DELAY_BETWEEN_DOCUMENTS}s mellem dokumenter")
    print(f"📦 Batch size:      {BATCH_SIZE} dokumenter, {BATCH_DELAY}s pause")
    print(f"🔌 Collection pause: {DELAY_BETWEEN_COLLECTIONS}s mellem collections")
    print(f"\n🎯 Understøttede formater: PDF, DOCX, MD, TXT")
    
    # Opret documents mappe hvis den ikke findes
    if not os.path.exists(DOCS_BASE_DIR):
        os.makedirs(DOCS_BASE_DIR)
        print(f"\n📁 Oprettet mappe: {DOCS_BASE_DIR}")
    
    # Synkroniser mapper
    collections_from_prompts = sync_folders_with_prompts()
    
    # Start ingest
    print("═" * 60)
    print("📥 STARTER DOKUMENT INGEST")
    print("═" * 60)
    
    total_stats = {
        "collections": 0,
        "processed": 0,
        "skipped": 0,
        "deleted": 0,
        "chunks": 0,
        "errors": 0
    }
    empty_collections = []
    verification_warnings = []
    
    collection_dirs = sorted([
        d for d in os.listdir(DOCS_BASE_DIR) 
        if os.path.isdir(os.path.join(DOCS_BASE_DIR, d))
    ])
    
    total_collections = len([c for c in collection_dirs if c not in EXCLUDED_COLLECTIONS])
    
    for col_idx, collection_name in enumerate(collection_dirs, 1):
        collection_path = os.path.join(DOCS_BASE_DIR, collection_name)
        
        if not os.path.isdir(collection_path):
            continue
        
        if collection_name in EXCLUDED_COLLECTIONS:
            print(f"\n⏭️  Springer over: {collection_name} (ekskluderet)")
            continue
            
        total_stats["collections"] += 1
        
        print(f"\n╔{'═'*58}╗")
        print(f"║ 📚 Collection [{col_idx}/{total_collections}]: {collection_name:<30} ║")
        print(f"╚{'═'*58}╝")
        
        # Process collection med isoleret forbindelse
        stats = process_collection(collection_name, collection_path)
        
        # Opdater totaler
        total_stats["processed"] += stats["processed"]
        total_stats["skipped"] += stats["skipped"]
        total_stats["deleted"] += stats["deleted"]
        total_stats["chunks"] += stats["chunks"]
        total_stats["errors"] += stats.get("errors", 0)
        
        # Check for verification warnings
        if stats.get("verification"):
            dist = stats["verification"].get("collection_distribution", {})
            if len(dist) > 1:
                verification_warnings.append({
                    "collection": collection_name,
                    "distribution": dist
                })
        
        if stats["processed"] == 0 and stats["skipped"] == 0:
            empty_collections.append(collection_name)
        
        # VIGTIG PAUSE mellem collections
        if col_idx < total_collections:
            print(f"\n   ⏳ Pause mellem collections ({DELAY_BETWEEN_COLLECTIONS}s)...")
            print(f"   🧹 Frigør ressourcer...")
            gc.collect()  # Force garbage collection
            time.sleep(DELAY_BETWEEN_COLLECTIONS)
    
    # Beregn tid
    elapsed_time = time.time() - start_time
    minutes = int(elapsed_time // 60)
    seconds = int(elapsed_time % 60)
    
    print("\n" + "═" * 60)
    print("╔══════════════════════════════════════════════════════════╗")
    print("║                   ✅ INGEST FÆRDIG                         ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"\n📊 Statistik:")
    print(f"   • Collections behandlet:    {total_stats['collections']}")
    print(f"   • Dokumenter processeret:   {total_stats['processed']}")
    print(f"   • Dokumenter sprunget over: {total_stats['skipped']}")
    print(f"   • Dokumenter slettet fra DB: {total_stats['deleted']}")
    print(f"   • Total chunks oprettet:    {total_stats['chunks']}")
    if total_stats["errors"] > 0:
        print(f"   • ⚠️  Fejl:                  {total_stats['errors']}")
    print(f"\n⏱️  Tid brugt: {minutes}m {seconds}s")
    
    # Vis verification warnings
    if verification_warnings:
        print(f"\n⚠️  ADVARSEL: Data-blanding fundet i følgende collections:")
        for warn in verification_warnings:
            print(f"   • {warn['collection']}: {warn['distribution']}")
        print(f"   Overvej at slette og genindeksere disse collections.")
    
    if empty_collections:
        print(f"\n⚠️  Tomme collections:")
        for col in empty_collections:
            print(f"   • documents/{col}/")
    
    print("\n" + "═" * 60 + "\n")