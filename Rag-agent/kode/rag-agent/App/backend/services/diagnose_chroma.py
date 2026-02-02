#!/usr/bin/env python3
"""
Chroma Collection Diagnosticering
==================================
Kør dette script for at tjekke status på dine Chroma collections.

Brug:
    python diagnose_chroma.py
    
    # Eller med specifik path:
    python diagnose_chroma.py /app/chroma_collections
"""

import os
import sys
from datetime import datetime

# Prøv at importere dependencies
try:
    from langchain_chroma import Chroma
    from langchain_openai import OpenAIEmbeddings
    from dotenv import load_dotenv
    load_dotenv()
except ImportError as e:
    print(f"❌ Manglende dependencies: {e}")
    print("   Installer med: pip install langchain-chroma langchain-openai python-dotenv")
    sys.exit(1)


def diagnose_collection(collection_name: str, collection_path: str) -> dict:
    """Diagnosticér en enkelt collection."""
    result = {
        "name": collection_name,
        "path": collection_path,
        "status": "unknown",
        "chunks": 0,
        "documents": set(),
        "collections_in_metadata": set(),
        "errors": [],
        "warnings": []
    }
    
    # Tjek at path eksisterer
    if not os.path.exists(collection_path):
        result["status"] = "missing"
        result["errors"].append(f"Path findes ikke: {collection_path}")
        return result
    
    # List filer
    try:
        files = os.listdir(collection_path)
        result["files"] = files
        
        if not files:
            result["status"] = "empty"
            result["errors"].append("Mappe er tom")
            return result
            
    except Exception as e:
        result["status"] = "error"
        result["errors"].append(f"Kan ikke læse mappe: {e}")
        return result
    
    # Prøv at åbne collection
    try:
        embeddings = OpenAIEmbeddings(request_timeout=30, max_retries=2)
        
        vectordb = Chroma(
            persist_directory=collection_path,
            embedding_function=embeddings,
            collection_name=collection_name
        )
        
        # Hent alle dokumenter
        all_docs = vectordb.get(include=["metadatas"])
        
        result["chunks"] = len(all_docs.get("ids", []))
        
        # Analyser metadata
        for metadata in all_docs.get("metadatas", []):
            if metadata:
                # Dokumenter
                doc_name = metadata.get("document", metadata.get("source", "unknown"))
                result["documents"].add(doc_name)
                
                # Collection i metadata
                meta_collection = metadata.get("collection", "not_set")
                result["collections_in_metadata"].add(meta_collection)
        
        # Konverter sets til lists for output
        result["documents"] = list(result["documents"])
        result["collections_in_metadata"] = list(result["collections_in_metadata"])
        
        # Tjek for data-blanding
        if len(result["collections_in_metadata"]) > 1:
            result["warnings"].append(
                f"DATA BLANDING! Fundet data fra: {result['collections_in_metadata']}"
            )
        elif result["collections_in_metadata"] and collection_name not in result["collections_in_metadata"]:
            result["warnings"].append(
                f"Collection mismatch! Forventet '{collection_name}', "
                f"fandt '{result['collections_in_metadata']}'"
            )
        
        # Test query
        if result["chunks"] > 0:
            try:
                test_results = vectordb.similarity_search_with_score("test query", k=1)
                result["query_test"] = "passed"
            except Exception as e:
                result["query_test"] = f"failed: {e}"
                result["errors"].append(f"Query test fejlede: {e}")
        
        result["status"] = "ok" if not result["errors"] else "warning"
        
    except Exception as e:
        result["status"] = "error"
        result["errors"].append(f"Kunne ikke åbne collection: {e}")
    
    return result


def main():
    print("=" * 70)
    print("🔍 CHROMA COLLECTION DIAGNOSTICERING")
    print("=" * 70)
    print(f"Tidspunkt: {datetime.now().isoformat()}")
    print()
    
    # Bestem base dir
    if len(sys.argv) > 1:
        chroma_base_dir = sys.argv[1]
    else:
        # Prøv almindelige paths
        possible_paths = [
            "chroma_collections",
            "/app/chroma_collections",
            "./chroma_collections",
        ]
        chroma_base_dir = None
        for path in possible_paths:
            if os.path.exists(path):
                chroma_base_dir = path
                break
        
        if not chroma_base_dir:
            print("❌ Kunne ikke finde chroma_collections mappe!")
            print(f"   Prøvede: {possible_paths}")
            print("\n   Brug: python diagnose_chroma.py /path/to/chroma_collections")
            sys.exit(1)
    
    print(f"📂 Base directory: {chroma_base_dir}")
    print(f"   Absolut path: {os.path.abspath(chroma_base_dir)}")
    print()
    
    # Find collections
    if not os.path.exists(chroma_base_dir):
        print(f"❌ Directory findes ikke: {chroma_base_dir}")
        sys.exit(1)
    
    collections = [
        d for d in os.listdir(chroma_base_dir)
        if os.path.isdir(os.path.join(chroma_base_dir, d))
    ]
    
    if not collections:
        print("⚠️  Ingen collections fundet!")
        sys.exit(0)
    
    print(f"📚 Fundet {len(collections)} collections")
    print("-" * 70)
    
    # Diagnosticér hver collection
    total_chunks = 0
    issues_found = 0
    
    for collection_name in sorted(collections):
        collection_path = os.path.join(chroma_base_dir, collection_name)
        
        print(f"\n📁 {collection_name}")
        print(f"   Path: {collection_path}")
        
        result = diagnose_collection(collection_name, collection_path)
        
        # Status
        status_icons = {
            "ok": "✅",
            "warning": "⚠️",
            "error": "❌",
            "empty": "📭",
            "missing": "🚫"
        }
        status_icon = status_icons.get(result["status"], "❓")
        print(f"   Status: {status_icon} {result['status'].upper()}")
        
        # Chunks
        print(f"   Chunks: {result['chunks']}")
        total_chunks += result["chunks"]
        
        # Dokumenter
        if result.get("documents"):
            print(f"   Dokumenter: {len(result['documents'])}")
            for doc in result["documents"][:5]:  # Vis max 5
                print(f"      - {doc}")
            if len(result["documents"]) > 5:
                print(f"      ... og {len(result['documents']) - 5} flere")
        
        # Collection i metadata
        if result.get("collections_in_metadata"):
            print(f"   Collections i metadata: {result['collections_in_metadata']}")
        
        # Query test
        if "query_test" in result:
            if result["query_test"] == "passed":
                print(f"   Query test: ✅ OK")
            else:
                print(f"   Query test: ❌ {result['query_test']}")
        
        # Warnings
        for warning in result.get("warnings", []):
            print(f"   ⚠️  {warning}")
            issues_found += 1
        
        # Errors
        for error in result.get("errors", []):
            print(f"   ❌ {error}")
            issues_found += 1
    
    # Summary
    print("\n" + "=" * 70)
    print("📊 SAMMENFATNING")
    print("=" * 70)
    print(f"   Collections: {len(collections)}")
    print(f"   Total chunks: {total_chunks}")
    print(f"   Issues fundet: {issues_found}")
    
    if issues_found > 0:
        print("\n⚠️  Der blev fundet problemer!")
        print("   Overvej at genindeksere problematiske collections:")
        print("   1. Slet collection mappen")
        print("   2. Kør ingest scriptet igen")
    else:
        print("\n✅ Alle collections ser OK ud!")


if __name__ == "__main__":
    main()
