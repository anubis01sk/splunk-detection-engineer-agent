#!/usr/bin/env python3
"""
Splunk Detection Rules RAG System
==================================

ChromaDB-based RAG system for Splunk security detection rules.
Provides semantic search, MITRE ATT&CK lookup, and context retrieval
for the Splunk SPL Agent.

Prerequisites:
    1. Parse detections first:
       python -m src.fetcher_detections parse ./security_content/detections
    
    2. Ingest into ChromaDB (uses default data file):
       python -m src.rag_detections ingest

Usage:
    from src.rag_detections import DetectionRAG
    
    rag = DetectionRAG()
    
    # Semantic search
    results = rag.search("detect credential dumping from LSASS")
    
    # Search by MITRE ATT&CK technique
    results = rag.search_by_mitre("T1003.001")
    
    # Search by data source
    results = rag.search_by_data_source("Sysmon EventID 1")
    
    # Get context for LLM
    context = rag.get_context_for_agent("ransomware file encryption detection")

Dependencies:
    pip install chromadb sentence-transformers

Author: Claude (Anthropic)
"""

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import logging

# Disable ChromaDB telemetry before import
os.environ["ANONYMIZED_TELEMETRY"] = "False"

import chromadb
from chromadb.config import Settings

# Module-level logger - configuration is done by entry points (cli.py, server.py)
logger = logging.getLogger(__name__)

# Suppress ChromaDB telemetry errors
logging.getLogger("chromadb.telemetry.product.posthog").setLevel(logging.CRITICAL)


# =============================================================================
# CONFIGURATION
# =============================================================================

# Path relative to project root (parent of src/)
DEFAULT_DB_PATH = str(Path(__file__).parent.parent / "vector_dbs" / "detections")
DEFAULT_DATA_FILE = Path(__file__).parent.parent / "data" / "splunk_spl_detections.jsonl"
DEFAULT_COLLECTION_NAME = "splunk_detections"
DEFAULT_EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"


@dataclass
class DetectionResult:
    """A single detection search result."""
    id: str
    name: str
    description: str
    search: str
    score: float
    type: str = ""
    category: str = ""
    mitre_attack_id: list[str] = None
    analytic_story: list[str] = None
    data_source: list[str] = None
    security_domain: str = ""
    how_to_implement: str = ""
    known_false_positives: str = ""
    
    def __post_init__(self):
        self.mitre_attack_id = self.mitre_attack_id or []
        self.analytic_story = self.analytic_story or []
        self.data_source = self.data_source or []


# =============================================================================
# DETECTION RAG CLASS
# =============================================================================

class DetectionRAG:
    """
    RAG system for Splunk security detection rules.
    
    Provides semantic search, metadata filtering, and context retrieval
    for detection rules stored in ChromaDB.
    """
    
    def __init__(
        self,
        db_path: str = DEFAULT_DB_PATH,
        collection_name: str = DEFAULT_COLLECTION_NAME,
        embedding_model: str = DEFAULT_EMBEDDING_MODEL,
    ):
        """
        Initialize the Detection RAG system.
        
        Args:
            db_path: Path to ChromaDB persistent storage
            collection_name: Name of the collection
            embedding_model: Sentence transformer model for embeddings
        """
        self.db_path = db_path
        self.collection_name = collection_name
        self.embedding_model = embedding_model
        
        # Initialize ChromaDB client
        self._client = chromadb.PersistentClient(
            path=db_path,
            settings=Settings(anonymized_telemetry=False),
        )
        
        # Get or create collection with embedding function
        try:
            from chromadb.utils import embedding_functions
            print(f"[*] Loading embedding model: {embedding_model}")
            self._embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
                model_name=embedding_model
            )
            print("[+] Embedding model loaded")
        except Exception as e:
            logger.warning(f"Could not load embedding function: {e}")
            self._embedding_fn = None
        
        self._collection = None
    
    def _get_collection(self):
        """Get or create the collection."""
        if self._collection is None:
            self._collection = self._client.get_or_create_collection(
                name=self.collection_name,
                embedding_function=self._embedding_fn,
                metadata={"description": "Splunk security detection rules"}
            )
        return self._collection
    
    # =========================================================================
    # INGESTION
    # =========================================================================
    
    def ingest(self, jsonl_path: Path = DEFAULT_DATA_FILE, batch_size: int = 100) -> int:
        """
        Ingest detections from a JSONL file into ChromaDB.
        
        Args:
            jsonl_path: Path to the JSONL file from fetcher_detections.py
                        Defaults to data/splunk_spl_detections.jsonl
            batch_size: Number of documents per batch
            
        Returns:
            Number of documents ingested
        """
        collection = self._get_collection()
        
        # Load detections from JSONL
        print(f"[*] Loading detections from {jsonl_path}...")
        detections = []
        with open(jsonl_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    detections.append(json.loads(line))
        
        print(f"[+] Loaded {len(detections)} detections")
        
        # Check for existing documents and clear if needed
        existing_count = collection.count()
        if existing_count > 0:
            print(f"[*] Collection already contains {existing_count} documents")
            print("[*] Clearing existing documents...")
            existing_ids = collection.get()["ids"]
            if existing_ids:
                collection.delete(ids=existing_ids)
            print("[+] Collection cleared")
        
        # Prepare documents for ingestion
        ids = []
        documents = []
        metadatas = []
        
        for detection in detections:
            # Create embedding text (what we search against)
            embedding_text = self._create_embedding_text(detection)
            
            # Create metadata for filtering
            metadata = {
                "name": detection.get("name", ""),
                "type": detection.get("type", ""),
                "status": detection.get("status", ""),
                "category": detection.get("category", ""),
                "security_domain": detection.get("security_domain", ""),
                "asset_type": detection.get("asset_type", ""),
                "author": detection.get("author", ""),
                # Store lists as comma-separated strings for filtering
                "mitre_attack_id": ",".join(detection.get("mitre_attack_id", [])),
                "analytic_story": ",".join(detection.get("analytic_story", [])),
                "data_source": ",".join(detection.get("data_source", [])),
                # Store full detection as JSON for retrieval
                "full_detection": json.dumps(detection),
            }
            
            ids.append(detection["id"])
            documents.append(embedding_text)
            metadatas.append(metadata)
        
        # Ingest in batches
        total_ingested = 0
        start_time = time.time()
        
        print(f"[*] Ingesting {len(ids)} detections in batches of {batch_size}...")
        
        for i in range(0, len(ids), batch_size):
            batch_ids = ids[i:i + batch_size]
            batch_docs = documents[i:i + batch_size]
            batch_meta = metadatas[i:i + batch_size]
            
            collection.add(
                ids=batch_ids,
                documents=batch_docs,
                metadatas=batch_meta,
            )
            
            total_ingested += len(batch_ids)
            print(f"    Progress: {total_ingested}/{len(ids)} detections")
        
        elapsed = time.time() - start_time
        print(f"\n[+] Ingestion complete")
        print(f"    Total: {total_ingested} detections")
        print(f"    Duration: {elapsed:.1f}s")
        
        return total_ingested
    
    def _create_embedding_text(self, detection: dict) -> str:
        """Create text representation for embedding."""
        parts = [
            f"Detection: {detection.get('name', '')}",
            f"Description: {detection.get('description', '')}",
            f"SPL Search: {detection.get('search', '')}",
        ]
        
        if detection.get("data_source"):
            parts.append(f"Data Sources: {', '.join(detection['data_source'])}")
        
        if detection.get("mitre_attack_id"):
            parts.append(f"MITRE ATT&CK: {', '.join(detection['mitre_attack_id'])}")
        
        if detection.get("analytic_story"):
            parts.append(f"Analytic Stories: {', '.join(detection['analytic_story'])}")
        
        if detection.get("how_to_implement"):
            parts.append(f"Implementation: {detection['how_to_implement']}")
        
        return "\n\n".join(parts)
    
    def reset(self) -> bool:
        """
        Reset the collection (delete all documents).
        
        Returns:
            True if successful
        """
        try:
            self._client.delete_collection(self.collection_name)
            self._collection = None
            logger.info(f"Collection '{self.collection_name}' deleted")
            return True
        except Exception as e:
            logger.error(f"Error resetting collection: {e}")
            return False
    
    # =========================================================================
    # SEARCH METHODS
    # =========================================================================
    
    def search(
        self,
        query: str,
        top_k: int = 5,
        filter_type: Optional[str] = None,
        filter_category: Optional[str] = None,
        filter_status: str = "production",
    ) -> list[DetectionResult]:
        """
        Semantic search for detections.
        
        Args:
            query: Natural language search query
            top_k: Number of results to return
            filter_type: Filter by detection type (TTP, Hunting, Anomaly)
            filter_category: Filter by category (endpoint, network, cloud, etc.)
            filter_status: Filter by status (production, experimental, deprecated)
            
        Returns:
            List of DetectionResult objects
        """
        collection = self._get_collection()
        
        # Build where clause for filtering
        where = {}
        if filter_type:
            where["type"] = filter_type
        if filter_category:
            where["category"] = filter_category
        if filter_status:
            where["status"] = filter_status
        
        # Execute search
        results = collection.query(
            query_texts=[query],
            n_results=top_k,
            where=where if where else None,
            include=["documents", "metadatas", "distances"],
        )
        
        return self._parse_results(results)
    
    def search_by_mitre(
        self,
        technique_id: str,
        top_k: int = 10,
    ) -> list[DetectionResult]:
        """
        Search for detections by MITRE ATT&CK technique ID.
        
        Args:
            technique_id: MITRE ATT&CK technique ID (e.g., T1003.001)
            top_k: Number of results to return
            
        Returns:
            List of DetectionResult objects
        """
        collection = self._get_collection()
        
        # Use $contains for partial matching in comma-separated list
        results = collection.query(
            query_texts=[f"MITRE ATT&CK technique {technique_id}"],
            n_results=top_k,
            where={"mitre_attack_id": {"$contains": technique_id}},
            include=["documents", "metadatas", "distances"],
        )
        
        return self._parse_results(results)
    
    def search_by_data_source(
        self,
        data_source: str,
        top_k: int = 10,
    ) -> list[DetectionResult]:
        """
        Search for detections by data source.
        
        Args:
            data_source: Data source name (e.g., "Sysmon EventID 1")
            top_k: Number of results to return
            
        Returns:
            List of DetectionResult objects
        """
        collection = self._get_collection()
        
        # Semantic search with data source context
        results = collection.query(
            query_texts=[f"Detection using data source {data_source}"],
            n_results=top_k * 2,  # Get more results to filter
            include=["documents", "metadatas", "distances"],
        )
        
        # Filter results that actually contain the data source
        parsed = self._parse_results(results)
        filtered = [
            r for r in parsed
            if any(data_source.lower() in ds.lower() for ds in r.data_source)
        ]
        
        return filtered[:top_k]
    
    def search_by_analytic_story(
        self,
        story: str,
        top_k: int = 10,
    ) -> list[DetectionResult]:
        """
        Search for detections by analytic story.
        
        Args:
            story: Analytic story name (e.g., "Ransomware")
            top_k: Number of results to return
            
        Returns:
            List of DetectionResult objects
        """
        collection = self._get_collection()
        
        results = collection.query(
            query_texts=[f"Analytic story {story} detection"],
            n_results=top_k,
            where={"analytic_story": {"$contains": story}},
            include=["documents", "metadatas", "distances"],
        )
        
        return self._parse_results(results)
    
    def get_by_id(self, detection_id: str) -> Optional[DetectionResult]:
        """
        Get a specific detection by ID.
        
        Args:
            detection_id: Detection UUID
            
        Returns:
            DetectionResult or None if not found
        """
        collection = self._get_collection()
        
        try:
            result = collection.get(
                ids=[detection_id],
                include=["documents", "metadatas"],
            )
            
            if result["ids"]:
                metadata = result["metadatas"][0]
                full_detection = json.loads(metadata.get("full_detection", "{}"))
                
                return DetectionResult(
                    id=detection_id,
                    name=full_detection.get("name", ""),
                    description=full_detection.get("description", ""),
                    search=full_detection.get("search", ""),
                    score=1.0,
                    type=full_detection.get("type", ""),
                    category=full_detection.get("category", ""),
                    mitre_attack_id=full_detection.get("mitre_attack_id", []),
                    analytic_story=full_detection.get("analytic_story", []),
                    data_source=full_detection.get("data_source", []),
                    security_domain=full_detection.get("security_domain", ""),
                    how_to_implement=full_detection.get("how_to_implement", ""),
                    known_false_positives=full_detection.get("known_false_positives", ""),
                )
            return None
        except Exception:
            return None
    
    def _parse_results(self, results: dict) -> list[DetectionResult]:
        """Parse ChromaDB results into DetectionResult objects."""
        parsed = []
        
        if not results["ids"] or not results["ids"][0]:
            return parsed
        
        for i, doc_id in enumerate(results["ids"][0]):
            metadata = results["metadatas"][0][i]
            distance = results["distances"][0][i] if results.get("distances") else 0
            
            # Parse full detection from metadata
            full_detection = json.loads(metadata.get("full_detection", "{}"))
            
            # Convert distance to similarity score (ChromaDB uses L2 distance by default)
            # Lower distance = higher similarity
            score = 1 / (1 + distance)
            
            parsed.append(DetectionResult(
                id=doc_id,
                name=full_detection.get("name", metadata.get("name", "")),
                description=full_detection.get("description", ""),
                search=full_detection.get("search", ""),
                score=score,
                type=full_detection.get("type", metadata.get("type", "")),
                category=full_detection.get("category", metadata.get("category", "")),
                mitre_attack_id=full_detection.get("mitre_attack_id", []),
                analytic_story=full_detection.get("analytic_story", []),
                data_source=full_detection.get("data_source", []),
                security_domain=full_detection.get("security_domain", ""),
                how_to_implement=full_detection.get("how_to_implement", ""),
                known_false_positives=full_detection.get("known_false_positives", ""),
            ))
        
        return parsed
    
    # =========================================================================
    # CONTEXT GENERATION FOR AGENT
    # =========================================================================
    
    def get_context_for_agent(
        self,
        query: str,
        top_k: int = 3,
        include_implementation: bool = True,
    ) -> str:
        """
        Get formatted context for the LLM agent.
        
        Args:
            query: User's query or detection request
            top_k: Number of relevant detections to include
            include_implementation: Whether to include implementation details
            
        Returns:
            Formatted string context for the agent
        """
        results = self.search(query, top_k=top_k, filter_status=None)
        
        if not results:
            return "No relevant detection rules found in the knowledge base."
        
        context_parts = [
            "=== RELEVANT SPLUNK DETECTION RULES ===",
            f"Found {len(results)} relevant detections:\n",
        ]
        
        for i, r in enumerate(results, 1):
            parts = [
                f"--- Detection {i}: {r.name} ---",
                f"ID: {r.id}",
                f"Type: {r.type} | Category: {r.category}",
                f"Description: {r.description}",
                f"\nSPL Search:\n```spl\n{r.search}\n```",
            ]
            
            if r.mitre_attack_id:
                parts.append(f"\nMITRE ATT&CK: {', '.join(r.mitre_attack_id)}")
            
            if r.data_source:
                parts.append(f"Data Sources: {', '.join(r.data_source)}")
            
            if include_implementation and r.how_to_implement:
                parts.append(f"\nImplementation Notes:\n{r.how_to_implement}")
            
            if r.known_false_positives:
                parts.append(f"\nKnown False Positives: {r.known_false_positives}")
            
            context_parts.append("\n".join(parts))
        
        context_parts.append("\n=== END DETECTION RULES ===")
        
        return "\n\n".join(context_parts)
    
    # =========================================================================
    # STATISTICS
    # =========================================================================
    
    def get_stats(self) -> dict:
        """Get statistics about the detection database."""
        collection = self._get_collection()
        
        count = collection.count()
        
        return {
            "total_documents": count,  # Standard key for consistency with other RAGs
            "total_detections": count,  # Legacy key for backward compatibility
            "collection_name": self.collection_name,
            "db_path": self.db_path,
            "embedding_model": self.embedding_model,
        }


# =============================================================================
# CLI INTERFACE
# =============================================================================

def main():
    """CLI entry point."""
    import sys
    
    if len(sys.argv) < 2:
        print("""
Splunk Detection Rules RAG System
==================================

Usage:
    python -m src.rag_detections ingest [jsonl_file]      Ingest detections into ChromaDB
                                                          (defaults to data/splunk_spl_detections.jsonl)
    python -m src.rag_detections query "<text>"           Semantic search
    python -m src.rag_detections mitre <technique_id>     Search by MITRE ATT&CK ID
    python -m src.rag_detections story "<story_name>"     Search by analytic story
    python -m src.rag_detections context "<query>"        Get LLM context
    python -m src.rag_detections stats                    Show database statistics
    python -m src.rag_detections reset                    Clear all data
    python -m src.rag_detections interactive              Interactive query mode

Examples:
    python -m src.rag_detections ingest
    python -m src.rag_detections ingest data/splunk_spl_detections.jsonl
    python -m src.rag_detections query "detect credential dumping"
    python -m src.rag_detections mitre T1003.001
    python -m src.rag_detections story Ransomware
    python -m src.rag_detections context "detect lateral movement"
""")
        sys.exit(0)
    
    command = sys.argv[1].lower()
    rag = DetectionRAG()
    
    if command == "ingest":
        jsonl_file = sys.argv[2] if len(sys.argv) >= 3 else DEFAULT_DATA_FILE
        print(f"[*] Using data file: {jsonl_file}")
        count = rag.ingest(jsonl_file)
        print(f"\nIngested {count} detections into ChromaDB")
    
    elif command == "query":
        if len(sys.argv) < 3:
            print("Error: query text required")
            print('Usage: python -m src.rag_detections query "<text>"')
            sys.exit(1)
        
        query = sys.argv[2]
        print(f"\nSearching for: {query}\n")
        
        results = rag.search(query, top_k=5, filter_status=None)
        
        if not results:
            print("No results found")
            sys.exit(0)
        
        for i, r in enumerate(results, 1):
            print(f"{i}. [{r.score:.3f}] {r.name}")
            print(f"   Type: {r.type} | Category: {r.category}")
            print(f"   MITRE: {', '.join(r.mitre_attack_id) if r.mitre_attack_id else 'N/A'}")
            print(f"   {r.description[:150]}...")
            print()
    
    elif command == "mitre":
        if len(sys.argv) < 3:
            print("Error: MITRE technique ID required")
            print("Usage: python -m src.rag_detections mitre <technique_id>")
            sys.exit(1)
        
        technique_id = sys.argv[2]
        print(f"\nSearching for MITRE ATT&CK technique: {technique_id}\n")
        
        results = rag.search_by_mitre(technique_id)
        
        if not results:
            print("No results found")
            sys.exit(0)
        
        for i, r in enumerate(results, 1):
            print(f"{i}. {r.name}")
            print(f"   Type: {r.type} | Category: {r.category}")
            print(f"   MITRE: {', '.join(r.mitre_attack_id)}")
            print()
    
    elif command == "story":
        if len(sys.argv) < 3:
            print("Error: analytic story name required")
            print('Usage: python -m src.rag_detections story "<story_name>"')
            sys.exit(1)
        
        story = sys.argv[2]
        print(f"\nSearching for analytic story: {story}\n")
        
        results = rag.search_by_analytic_story(story)
        
        if not results:
            print("No results found")
            sys.exit(0)
        
        for i, r in enumerate(results, 1):
            print(f"{i}. {r.name}")
            print(f"   Stories: {', '.join(r.analytic_story)}")
            print(f"   Type: {r.type}")
            print()
    
    elif command == "context":
        if len(sys.argv) < 3:
            print("Error: query text required")
            print('Usage: python -m src.rag_detections context "<query>"')
            sys.exit(1)
        
        query = sys.argv[2]
        context = rag.get_context_for_agent(query)
        print(context)
    
    elif command == "stats":
        stats = rag.get_stats()
        print("\nDetection RAG Statistics:")
        print(f"  Total detections: {stats['total_detections']}")
        print(f"  Collection: {stats['collection_name']}")
        print(f"  Database path: {stats['db_path']}")
        print(f"  Embedding model: {stats['embedding_model']}")
    
    elif command == "reset":
        confirm = input("Are you sure you want to delete all detection data? (yes/no): ")
        if confirm.lower() == "yes":
            rag.reset()
            print("Detection database reset successfully")
        else:
            print("Reset cancelled")
    
    elif command == "interactive":
        print("\nInteractive Detection Search")
        print("Type 'quit' to exit, 'help' for commands\n")
        
        while True:
            try:
                query = input("Query> ").strip()
                
                if not query:
                    continue
                
                if query.lower() == "quit":
                    break
                
                if query.lower() == "help":
                    print("\nCommands:")
                    print("  <text>           - Semantic search")
                    print("  mitre:<id>       - Search by MITRE ID (e.g., mitre:T1003)")
                    print("  story:<name>     - Search by story (e.g., story:Ransomware)")
                    print("  id:<uuid>        - Get detection by ID")
                    print("  quit             - Exit")
                    print()
                    continue
                
                if query.startswith("mitre:"):
                    technique = query[6:].strip()
                    results = rag.search_by_mitre(technique)
                elif query.startswith("story:"):
                    story = query[6:].strip()
                    results = rag.search_by_analytic_story(story)
                elif query.startswith("id:"):
                    detection_id = query[3:].strip()
                    result = rag.get_by_id(detection_id)
                    if result:
                        print(f"\n{result.name}")
                        print(f"Type: {result.type} | Category: {result.category}")
                        print(f"MITRE: {', '.join(result.mitre_attack_id)}")
                        print(f"\n{result.description}")
                        print(f"\nSPL:\n{result.search}")
                    else:
                        print("Detection not found")
                    continue
                else:
                    results = rag.search(query, top_k=5, filter_status=None)
                
                if not results:
                    print("No results found\n")
                    continue
                
                print()
                for i, r in enumerate(results, 1):
                    print(f"{i}. [{r.score:.3f}] {r.name}")
                    print(f"   {r.type} | {r.category} | MITRE: {', '.join(r.mitre_attack_id) or 'N/A'}")
                print()
                
            except KeyboardInterrupt:
                print("\n")
                break
            except Exception as e:
                print(f"Error: {e}\n")
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
