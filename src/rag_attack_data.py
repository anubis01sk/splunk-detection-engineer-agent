#!/usr/bin/env python3
"""
Attack Data RAG System
======================

ChromaDB-based RAG system for Splunk Attack Data repository.
Enables semantic search for finding relevant attack datasets for testing detections.

Source: https://github.com/splunk/attack_data

Usage:
    from src.rag_attack_data import AttackDataRAG
    
    rag = AttackDataRAG()
    
    # Find datasets for credential theft
    results = rag.search("credential dumping LSASS")
    
    # Find datasets by MITRE technique
    results = rag.search_by_mitre("T1003")
    
    # Get context for agent
    context = rag.get_context_for_agent("lateral movement RDP")

CLI:
    python -m src.rag_attack_data stats              Show RAG statistics
    python -m src.rag_attack_data query "<text>"     Search attack datasets
    python -m src.rag_attack_data ingest             Ingest from data/splunk_attack_data.jsonl
    python -m src.rag_attack_data mitre <technique>  Search by MITRE ID

Dependencies:
    pip install chromadb sentence-transformers
"""

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List

# Disable ChromaDB telemetry before import
os.environ["ANONYMIZED_TELEMETRY"] = "False"

import chromadb
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer

# Suppress ChromaDB telemetry errors
logging.getLogger("chromadb.telemetry.product.posthog").setLevel(logging.CRITICAL)


# =============================================================================
# CONFIGURATION
# =============================================================================

DEFAULT_DB_PATH = Path(__file__).parent.parent / "vector_dbs" / "attack_data"
DEFAULT_DATA_FILE = Path(__file__).parent.parent / "data" / "splunk_attack_data.jsonl"
DEFAULT_COLLECTION_NAME = "attack_data"
DEFAULT_EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"


# =============================================================================
# DATA MODELS
# =============================================================================

@dataclass
class AttackDataResult:
    """Result from Attack Data RAG search."""
    id: str
    name: str
    content: str
    mitre_id: str
    attack_technique: str
    data_source: str
    file_path: str
    score: float
    tags: list[str] = None
    
    def __str__(self):
        mitre = f" ({self.mitre_id})" if self.mitre_id else ""
        return f"[{self.score:.2f}] {self.name}{mitre}: {self.content[:100]}..."


# =============================================================================
# ATTACK DATA RAG CLASS
# =============================================================================

class AttackDataRAG:
    """
    RAG system for Splunk Attack Data.
    
    Provides semantic search over attack datasets to help
    find relevant test data for detection validation.
    """
    
    def __init__(
        self,
        db_path: Path = DEFAULT_DB_PATH,
        collection_name: str = DEFAULT_COLLECTION_NAME,
        embedding_model: str = DEFAULT_EMBEDDING_MODEL,
    ):
        """
        Initialize Attack Data RAG system.
        
        Args:
            db_path: Path to ChromaDB database
            collection_name: Name of the collection
            embedding_model: Sentence transformer model name
        """
        self.db_path = Path(db_path)
        self.collection_name = collection_name
        
        # Initialize ChromaDB
        self.client = chromadb.PersistentClient(
            path=str(self.db_path),
            settings=Settings(anonymized_telemetry=False),
        )
        
        # Get or create collection
        self.collection = self.client.get_or_create_collection(
            name=collection_name,
            metadata={"description": "Splunk Attack Data datasets for detection testing"},
        )
        
        # Load embedding model (lazy)
        self._model = None
        self._model_name = embedding_model
    
    @property
    def model(self) -> SentenceTransformer:
        """Lazy-load embedding model."""
        if self._model is None:
            print(f"[*] Loading embedding model: {self._model_name}")
            self._model = SentenceTransformer(self._model_name)
            print(f"[+] Embedding model loaded")
        return self._model
    
    def ingest(self, jsonl_path: Path = DEFAULT_DATA_FILE, batch_size: int = 100) -> int:
        """
        Ingest attack data chunks from JSON Lines file.
        
        Args:
            jsonl_path: Path to the JSONL file
            batch_size: Number of documents per batch
            
        Returns:
            Number of documents ingested
        """
        jsonl_path = Path(jsonl_path)
        
        if not jsonl_path.exists():
            raise FileNotFoundError(
                f"Data file not found: {jsonl_path}\n"
                "Run 'python -m src.fetcher_attack_data' to download attack data."
            )
        
        # Read chunks
        chunks = []
        with open(jsonl_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    chunks.append(json.loads(line))
        
        if not chunks:
            print("No chunks found in file")
            return 0
        
        print(f"[*] Ingesting {len(chunks)} attack data chunks...")
        
        # Clear existing data
        existing = self.collection.count()
        if existing > 0:
            print(f"[*] Clearing {existing} existing documents...")
            # Delete all by querying all IDs
            all_ids = self.collection.get()["ids"]
            if all_ids:
                self.collection.delete(ids=all_ids)
        
        # Deduplicate IDs by adding index suffix
        seen_ids: dict[str, int] = {}
        for chunk in chunks:
            original_id = chunk["id"]
            if original_id in seen_ids:
                seen_ids[original_id] += 1
                chunk["id"] = f"{original_id}_{seen_ids[original_id]}"
            else:
                seen_ids[original_id] = 0
        
        # Batch ingest
        for i in range(0, len(chunks), batch_size):
            batch = chunks[i:i+batch_size]
            
            ids = [chunk["id"] for chunk in batch]
            documents = [chunk["content"] for chunk in batch]
            metadatas = [
                {
                    "name": chunk.get("name", ""),
                    "mitre_id": chunk.get("mitre_id", ""),
                    "attack_technique": chunk.get("attack_technique", ""),
                    "data_source": chunk.get("data_source", ""),
                    "file_path": chunk.get("file_path", ""),
                    "tags": ",".join(chunk.get("tags", [])),
                }
                for chunk in batch
            ]
            
            # Generate embeddings
            embeddings = self.model.encode(documents, show_progress_bar=False).tolist()
            
            # Add to collection
            self.collection.add(
                ids=ids,
                documents=documents,
                metadatas=metadatas,
                embeddings=embeddings,
            )
            
            print(f"    Ingested {min(i + batch_size, len(chunks))}/{len(chunks)}")
        
        print(f"[+] Successfully ingested {len(chunks)} attack data chunks")
        return len(chunks)
    
    def search(
        self,
        query: str,
        top_k: int = 5,
        mitre_id: Optional[str] = None,
        data_source: Optional[str] = None,
    ) -> list[AttackDataResult]:
        """
        Search for relevant attack datasets.
        
        Args:
            query: Search query
            top_k: Number of results to return
            mitre_id: Filter by MITRE ATT&CK ID (optional)
            data_source: Filter by data source (optional)
            
        Returns:
            List of AttackDataResult objects
        """
        # Build where clause
        where = None
        if mitre_id:
            where = {"mitre_id": mitre_id}
        elif data_source:
            where = {"data_source": data_source}
        
        # Generate query embedding
        query_embedding = self.model.encode([query])[0].tolist()
        
        # Search with error handling for HNSW issues
        try:
            results = self.collection.query(
                query_embeddings=[query_embedding],
                n_results=min(top_k, self.collection.count()),  # Don't exceed collection size
                where=where,
                include=["documents", "metadatas", "distances"],
            )
        except RuntimeError as e:
            if "ef or M is too small" in str(e):
                print("[!] HNSW index error - try resetting the database:")
                print("    rm -rf vector_dbs/attack_data")
                print("    python -m src.rag_attack_data ingest data/splunk_attack_data.jsonl")
                return []
            raise
        
        # Convert to AttackDataResult objects
        attack_results = []
        
        if results["ids"] and results["ids"][0]:
            for i, doc_id in enumerate(results["ids"][0]):
                metadata = results["metadatas"][0][i] if results["metadatas"] else {}
                distance = results["distances"][0][i] if results["distances"] else 0
                
                # Convert distance to similarity score (0-1)
                score = 1 / (1 + distance)
                
                tags = metadata.get("tags", "").split(",") if metadata.get("tags") else []
                
                attack_results.append(AttackDataResult(
                    id=doc_id,
                    name=metadata.get("name", ""),
                    content=results["documents"][0][i] if results["documents"] else "",
                    mitre_id=metadata.get("mitre_id", ""),
                    attack_technique=metadata.get("attack_technique", ""),
                    data_source=metadata.get("data_source", ""),
                    file_path=metadata.get("file_path", ""),
                    score=score,
                    tags=tags if tags != [""] else None,
                ))
        
        return attack_results
    
    def search_by_mitre(self, mitre_id: str, top_k: int = 10) -> list[AttackDataResult]:
        """
        Search for attack datasets by MITRE ATT&CK technique ID.
        
        Args:
            mitre_id: MITRE technique ID (e.g., "T1003", "T1059.001")
            top_k: Number of results to return
            
        Returns:
            List of AttackDataResult objects
        """
        # Normalize MITRE ID
        mitre_id = mitre_id.upper().strip()
        
        # Search with MITRE ID as query and filter
        return self.search(
            query=f"MITRE ATT&CK {mitre_id}",
            top_k=top_k,
            mitre_id=mitre_id,
        )
    
    def get_context_for_agent(self, query: str, top_k: int = 3) -> str:
        """
        Get formatted context string for LLM agent.
        
        Args:
            query: User query or detection requirement
            top_k: Number of results to include
            
        Returns:
            Formatted context string with attack data recommendations
        """
        results = self.search(query, top_k=top_k)
        
        if not results:
            return ""
        
        context_parts = ["## Relevant Attack Datasets for Testing\n"]
        
        for i, result in enumerate(results, 1):
            context_parts.append(f"### {i}. {result.name}")
            if result.mitre_id:
                context_parts.append(f"MITRE: {result.mitre_id} - {result.attack_technique}")
            context_parts.append(f"Data Source: {result.data_source}")
            context_parts.append(f"File: {result.file_path}")
            context_parts.append("")
        
        return "\n".join(context_parts)
    
    def get_stats(self) -> dict:
        """Get RAG statistics."""
        count = self.collection.count()
        
        # Get unique values
        mitre_ids = set()
        data_sources = set()
        
        if count > 0:
            results = self.collection.get(
                limit=count,
                include=["metadatas"],
            )
            if results["metadatas"]:
                for m in results["metadatas"]:
                    if m.get("mitre_id"):
                        mitre_ids.add(m["mitre_id"])
                    if m.get("data_source"):
                        data_sources.add(m["data_source"])
        
        return {
            "total_documents": count,
            "unique_mitre_techniques": len(mitre_ids),
            "unique_data_sources": len(data_sources),
            "db_path": str(self.db_path),
            "collection_name": self.collection_name,
        }
    
    def list_mitre_techniques(self) -> list[str]:
        """List all MITRE ATT&CK techniques in the database."""
        count = self.collection.count()
        if count == 0:
            return []
        
        results = self.collection.get(
            limit=count,
            include=["metadatas"],
        )
        
        techniques = set()
        if results["metadatas"]:
            for m in results["metadatas"]:
                if m.get("mitre_id"):
                    techniques.add(m["mitre_id"])
        
        return sorted(techniques)
    
    def list_data_sources(self) -> list[str]:
        """List all data sources in the database."""
        count = self.collection.count()
        if count == 0:
            return []
        
        results = self.collection.get(
            limit=count,
            include=["metadatas"],
        )
        
        sources = set()
        if results["metadatas"]:
            for m in results["metadatas"]:
                if m.get("data_source"):
                    sources.add(m["data_source"])
        
        return sorted(sources)


# =============================================================================
# CLI
# =============================================================================

def main():
    """CLI entry point."""
    import sys
    
    if len(sys.argv) < 2:
        print("""
Attack Data RAG System
======================

Source: https://github.com/splunk/attack_data

Commands:
    python -m src.rag_attack_data stats              Show RAG statistics
    python -m src.rag_attack_data query "<text>"     Search attack datasets
    python -m src.rag_attack_data ingest             Ingest from data/splunk_attack_data.jsonl
    python -m src.rag_attack_data mitre <technique>  Search by MITRE ID
    python -m src.rag_attack_data techniques         List MITRE techniques
    python -m src.rag_attack_data sources            List data sources

Examples:
    python -m src.rag_attack_data query "credential dumping"
    python -m src.rag_attack_data mitre T1003
""")
        sys.exit(0)
    
    command = sys.argv[1].lower()
    rag = AttackDataRAG()
    
    if command == "stats":
        stats = rag.get_stats()
        print("\nAttack Data RAG Statistics")
        print("=" * 40)
        print(f"Total Documents: {stats['total_documents']}")
        print(f"MITRE Techniques: {stats['unique_mitre_techniques']}")
        print(f"Data Sources: {stats['unique_data_sources']}")
        print(f"Database Path: {stats['db_path']}")
        print("=" * 40)
    
    elif command == "ingest":
        rag.ingest()
    
    elif command in ("query", "search"):  # Accept both for compatibility
        if len(sys.argv) < 3:
            print("Error: query text required")
            print('Usage: python -m src.rag_attack_data query "<text>"')
            sys.exit(1)
        
        query = sys.argv[2]
        results = rag.search(query)
        
        print(f"\nSearch Results for: {query}\n")
        print("-" * 60)
        
        for i, result in enumerate(results, 1):
            print(f"\n{i}. [{result.score:.2f}] {result.name}")
            if result.mitre_id:
                print(f"   MITRE: {result.mitre_id} - {result.attack_technique}")
            print(f"   Source: {result.data_source}")
            print(f"   File: {result.file_path}")
    
    elif command == "mitre":
        if len(sys.argv) < 3:
            print("Error: MITRE technique ID required")
            print('Usage: python -m src.rag_attack_data mitre <technique>')
            sys.exit(1)
        
        mitre_id = sys.argv[2]
        results = rag.search_by_mitre(mitre_id)
        
        print(f"\nDatasets for MITRE {mitre_id}:\n")
        print("-" * 60)
        
        if results:
            for i, result in enumerate(results, 1):
                print(f"\n{i}. {result.name}")
                print(f"   Technique: {result.attack_technique}")
                print(f"   Source: {result.data_source}")
                print(f"   File: {result.file_path}")
        else:
            print(f"No datasets found for {mitre_id}")
    
    elif command == "techniques":
        techniques = rag.list_mitre_techniques()
        print(f"\nMITRE Techniques ({len(techniques)}):")
        for t in techniques:
            print(f"  - {t}")
    
    elif command == "sources":
        sources = rag.list_data_sources()
        print(f"\nData Sources ({len(sources)}):")
        for s in sources:
            print(f"  - {s}")
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
