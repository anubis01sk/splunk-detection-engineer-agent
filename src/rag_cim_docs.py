#!/usr/bin/env python3
"""
CIM Data Models RAG System
==========================

ChromaDB-based RAG system for Splunk Common Information Model (CIM) field definitions.
Enables semantic search for finding relevant CIM fields for detection engineering.

Usage:
    from src.rag_cim_docs import CIMRAG
    
    rag = CIMRAG()
    
    # Find fields for authentication events
    results = rag.search("authentication login user credentials")
    
    # Find fields for network traffic
    results = rag.search("network connections source destination IP")
    
    # Get context for agent
    context = rag.get_context_for_agent("find fields for process execution")

CLI:
    python -m src.rag_cim_docs stats              Show RAG statistics
    python -m src.rag_cim_docs search "<query>"   Search CIM fields
    python -m src.rag_cim_docs ingest             Ingest from data/splunk_cim_docs.jsonl

Dependencies:
    pip install chromadb sentence-transformers
"""

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

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

DEFAULT_DB_PATH = Path(__file__).parent.parent / "vector_dbs" / "cim"
DEFAULT_DATA_FILE = Path(__file__).parent.parent / "data" / "splunk_cim_docs.jsonl"
DEFAULT_COLLECTION_NAME = "cim_docs"
DEFAULT_EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"


# =============================================================================
# DATA MODELS
# =============================================================================

@dataclass
class CIMResult:
    """Result from CIM RAG search."""
    id: str
    data_model: str
    display_name: str
    content: str
    score: float
    field_names: list[str] = None
    
    def __str__(self):
        fields = f" [{', '.join(self.field_names[:5])}...]" if self.field_names else ""
        return f"[{self.score:.2f}] {self.display_name}{fields}: {self.content[:100]}..."


# =============================================================================
# CIM RAG CLASS
# =============================================================================

class CIMRAG:
    """
    RAG system for Splunk CIM field definitions.
    
    Provides semantic search over CIM data model fields to help
    agents and users find the right fields for their queries.
    """
    
    def __init__(
        self,
        db_path: Path = DEFAULT_DB_PATH,
        collection_name: str = DEFAULT_COLLECTION_NAME,
        embedding_model: str = DEFAULT_EMBEDDING_MODEL,
    ):
        """
        Initialize CIM RAG system.
        
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
            metadata={"description": "Splunk CIM data model field definitions"},
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
        Ingest CIM chunks from JSON Lines file.
        
        Args:
            jsonl_path: Path to the JSONL file
            batch_size: Number of documents per batch
            
        Returns:
            Number of documents ingested
        """
        if not jsonl_path.exists():
            raise FileNotFoundError(
                f"Data file not found: {jsonl_path}\n"
                "Run 'python -m src.fetcher_cim_docs' to download CIM data."
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
        
        print(f"[*] Ingesting {len(chunks)} CIM chunks...")
        
        # Clear existing data
        existing = self.collection.count()
        if existing > 0:
            print(f"[*] Clearing {existing} existing documents...")
            self.collection.delete(where={"data_model": {"$ne": ""}})
        
        # Batch ingest
        for i in range(0, len(chunks), batch_size):
            batch = chunks[i:i+batch_size]
            
            ids = [chunk["id"] for chunk in batch]
            documents = [chunk["content"] for chunk in batch]
            metadatas = [
                {
                    "data_model": chunk.get("data_model", ""),
                    "display_name": chunk.get("display_name", ""),
                    "type": chunk.get("type", ""),
                    "version": chunk.get("version", ""),
                    "url": chunk.get("url", ""),
                    "field_names": ",".join(chunk.get("field_names", [])),
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
        
        print(f"[+] Successfully ingested {len(chunks)} CIM chunks")
        return len(chunks)
    
    def search(
        self,
        query: str,
        top_k: int = 5,
        data_model: Optional[str] = None,
    ) -> list[CIMResult]:
        """
        Search for relevant CIM fields.
        
        Args:
            query: Search query
            top_k: Number of results to return
            data_model: Filter by specific data model (optional)
            
        Returns:
            List of CIMResult objects
        """
        # Build where clause
        where = None
        if data_model:
            where = {"data_model": data_model}
        
        # Generate query embedding
        query_embedding = self.model.encode([query])[0].tolist()
        
        # Search
        results = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=top_k,
            where=where,
            include=["documents", "metadatas", "distances"],
        )
        
        # Convert to CIMResult objects
        cim_results = []
        
        if results["ids"] and results["ids"][0]:
            for i, doc_id in enumerate(results["ids"][0]):
                metadata = results["metadatas"][0][i] if results["metadatas"] else {}
                distance = results["distances"][0][i] if results["distances"] else 0
                
                # Convert distance to similarity score (0-1)
                score = 1 / (1 + distance)
                
                field_names = metadata.get("field_names", "").split(",") if metadata.get("field_names") else []
                
                cim_results.append(CIMResult(
                    id=doc_id,
                    data_model=metadata.get("data_model", ""),
                    display_name=metadata.get("display_name", ""),
                    content=results["documents"][0][i] if results["documents"] else "",
                    score=score,
                    field_names=field_names if field_names != [""] else None,
                ))
        
        return cim_results
    
    def get_context_for_agent(self, query: str, top_k: int = 3) -> str:
        """
        Get formatted context string for LLM agent.
        
        Args:
            query: User query or detection requirement
            top_k: Number of results to include
            
        Returns:
            Formatted context string with CIM field recommendations
        """
        import re
        
        results = self.search(query, top_k=top_k)
        
        if not results:
            return ""
        
        context_parts = ["## Splunk CIM (Common Information Model) Fields\n"]
        context_parts.append("Use these CIM-compliant field names for cross-sourcetype compatibility:\n")
        
        for i, result in enumerate(results, 1):
            context_parts.append(f"### {i}. CIM Data Model: {result.data_model}")
            
            # Extract actual field names from content using multiple patterns
            content = result.content
            extracted_fields = set()
            
            # Pattern 1: Extract fields from Expression patterns like "if(isnull(dest)"
            expr_matches = re.findall(r'isnull\((\w+)\)', content)
            extracted_fields.update(f for f in expr_matches if len(f) > 1)
            
            # Pattern 2: Extract fields from OR comparisons like "user OR user=\"\""
            or_matches = re.findall(r'\b(\w+)\s+OR\s+\1\s*=', content)
            extracted_fields.update(f for f in or_matches if len(f) > 1)
            
            # Pattern 3: Extract common CIM field names mentioned in the text
            # Comprehensive list of standard CIM fields
            cim_field_patterns = [
                # Process fields
                'process', 'process_name', 'process_path', 'process_id', 'process_guid', 
                'process_exec', 'process_current_directory', 'process_integrity_level',
                'parent_process', 'parent_process_name', 'parent_process_path', 
                'parent_process_id', 'parent_process_guid', 'parent_process_exec',
                'original_file_name', 'process_hash',
                # User/Identity fields
                'user', 'user_id', 'user_name', 'user_type', 'user_category', 'user_bunit',
                'src_user', 'dest_user', 'user_role', 'user_email',
                # Network/Endpoint fields
                'dest', 'dest_ip', 'dest_host', 'dest_port', 'dest_mac', 'dest_zone',
                'src', 'src_ip', 'src_host', 'src_port', 'src_mac', 'src_zone',
                'dvc', 'dvc_ip', 'dvc_host', 'dvc_zone',
                'transport', 'protocol', 'direction',
                # Action/Status fields
                'action', 'status', 'result', 'reason', 'category', 'severity', 'priority',
                'signature', 'signature_id', 'app', 'vendor', 'product', 'vendor_product',
                # File fields
                'file_name', 'file_path', 'file_size', 'file_hash', 'file_modify_time',
                'file_create_time', 'file_access_time', 'file_acl',
                # Registry fields (Windows)
                'registry_path', 'registry_key_name', 'registry_value_name', 
                'registry_value_data', 'registry_value_type', 'registry_hive',
                # Authentication fields
                'authentication_method', 'authentication_service', 'auth',
                # Web/HTTP fields
                'http_method', 'http_user_agent', 'http_referrer', 'http_content_type',
                'url', 'uri', 'uri_path', 'uri_query', 'url_domain',
                'bytes', 'bytes_in', 'bytes_out', 'duration',
                # Time fields
                'start_time', 'end_time', '_time',
                # Command/Script fields  
                'command', 'command_line', 'os', 'os_version',
                # Service fields
                'service', 'service_name', 'service_path', 'service_id',
            ]
            
            content_lower = content.lower()
            for field in cim_field_patterns:
                if field in content_lower:
                    extracted_fields.add(field)
            
            # Pattern 4: Extract fields that follow common description patterns
            # "The <field_name> is/contains/specifies..."
            desc_matches = re.findall(r'The\s+([a-z_]+)\s+(?:is|of|that|contains|specifies)', content, re.IGNORECASE)
            for match in desc_matches:
                clean = match.lower().replace(' ', '_')
                if len(clean) > 2 and clean not in ('field', 'value', 'event', 'data', 'type'):
                    extracted_fields.add(clean)
            
            if extracted_fields:
                # Sort and display fields by category
                sorted_fields = sorted(extracted_fields)
                context_parts.append(f"**CIM Fields Available:** {', '.join(sorted_fields)}")
            
            # Include a brief summary of the data model (first 400 chars)
            brief_content = content[:400].replace('\n\n', ' ').replace('\n', ' ')
            context_parts.append(f"**Overview:** {brief_content}...")
            context_parts.append("")
        
        context_parts.append("**Important:** When using these CIM fields, ensure your data is CIM-compliant or use field aliases.")
        
        return "\n".join(context_parts)
    
    def get_stats(self) -> dict:
        """Get RAG statistics."""
        count = self.collection.count()
        
        # Get unique data models
        data_models = set()
        if count > 0:
            results = self.collection.get(
                limit=count,
                include=["metadatas"],
            )
            if results["metadatas"]:
                data_models = set(
                    m.get("data_model", "")
                    for m in results["metadatas"]
                    if m.get("data_model")
                )
        
        return {
            "total_documents": count,
            "unique_data_models": len(data_models),
            "data_models": sorted(data_models),
            "db_path": str(self.db_path),
            "collection_name": self.collection_name,
        }
    
    def list_data_models(self) -> list[str]:
        """List all available CIM data models."""
        stats = self.get_stats()
        return stats["data_models"]
    
    def get_fields_for_model(self, data_model: str, top_k: int = 50) -> list[str]:
        """
        Get all field names for a specific data model.
        
        Args:
            data_model: Name of the data model (e.g., "authentication")
            top_k: Maximum number of chunks to search
            
        Returns:
            List of field names
        """
        results = self.collection.get(
            where={"data_model": data_model},
            limit=top_k,
            include=["metadatas"],
        )
        
        fields = set()
        if results["metadatas"]:
            for metadata in results["metadatas"]:
                field_str = metadata.get("field_names", "")
                if field_str:
                    fields.update(f.strip() for f in field_str.split(",") if f.strip())
        
        return sorted(fields)


# =============================================================================
# CLI
# =============================================================================

def main():
    """CLI entry point."""
    import sys
    
    if len(sys.argv) < 2:
        print("""
CIM Data Models RAG System
==========================

Commands:
    python -m src.rag_cim_docs stats              Show RAG statistics
    python -m src.rag_cim_docs search "<query>"   Search CIM fields
    python -m src.rag_cim_docs ingest             Ingest from data/splunk_cim_docs.jsonl
    python -m src.rag_cim_docs models             List available data models
    python -m src.rag_cim_docs fields <model>     Show fields for a data model

Examples:
    python -m src.rag_cim_docs search "authentication login"
    python -m src.rag_cim_docs fields authentication
""")
        sys.exit(0)
    
    command = sys.argv[1].lower()
    rag = CIMRAG()
    
    if command == "stats":
        stats = rag.get_stats()
        print("\nCIM RAG Statistics")
        print("=" * 40)
        print(f"Total Documents: {stats['total_documents']}")
        print(f"Data Models: {stats['unique_data_models']}")
        print(f"Database Path: {stats['db_path']}")
        print("=" * 40)
    
    elif command == "ingest":
        rag.ingest()
    
    elif command in ("search", "query"):
        if len(sys.argv) < 3:
            print("Error: query required")
            print('Usage: python -m src.rag_cim_docs query "<query>"')
            sys.exit(1)
        
        import re
        query = sys.argv[2]
        results = rag.search(query)
        
        print(f"\nCIM Data Model Search: {query}\n")
        print("-" * 60)
        
        # Comprehensive list of standard CIM fields to look for
        cim_field_patterns = [
            'process', 'process_name', 'process_path', 'process_id', 'process_guid', 
            'process_exec', 'parent_process', 'parent_process_name', 'parent_process_path',
            'parent_process_id', 'parent_process_guid', 'original_file_name',
            'user', 'user_id', 'user_name', 'user_type', 'src_user', 'dest_user',
            'dest', 'dest_ip', 'dest_host', 'dest_port', 'dest_mac', 'dest_zone',
            'src', 'src_ip', 'src_host', 'src_port', 'src_mac', 'src_zone',
            'dvc', 'dvc_ip', 'dvc_host', 'transport', 'protocol', 'direction',
            'action', 'status', 'result', 'reason', 'category', 'severity', 'priority',
            'signature', 'signature_id', 'app', 'vendor', 'product', 'vendor_product',
            'file_name', 'file_path', 'file_size', 'file_hash',
            'registry_path', 'registry_key_name', 'registry_value_name', 'registry_value_data',
            'authentication_method', 'auth', 'http_method', 'http_user_agent',
            'url', 'uri', 'uri_path', 'uri_query', 'bytes', 'bytes_in', 'bytes_out',
            'command', 'command_line', 'service', 'service_name', 'service_path',
        ]
        
        for i, result in enumerate(results, 1):
            print(f"\n{i}. [{result.score:.2f}] Data Model: {result.data_model}")
            
            # Extract actual CIM field names from content
            content = result.content
            content_lower = content.lower()
            extracted_fields = set()
            
            # Extract from Expression patterns like "isnull(dest)"
            expr_matches = re.findall(r'isnull\((\w+)\)', content)
            extracted_fields.update(f for f in expr_matches if len(f) > 1)
            
            # Extract from OR patterns like "user OR user=\"\""
            or_matches = re.findall(r'\b(\w+)\s+OR\s+\1\s*=', content)
            extracted_fields.update(f for f in or_matches if len(f) > 1)
            
            # Check for standard CIM field names in the text
            for field in cim_field_patterns:
                if field in content_lower:
                    extracted_fields.add(field)
            
            if extracted_fields:
                # Sort and show top 15 fields
                sorted_fields = sorted(extracted_fields)[:15]
                print(f"   CIM Fields: {', '.join(sorted_fields)}")
            
            # Show brief content
            brief = content[:300].replace('\n', ' ')
            print(f"   Content: {brief}...")
    
    elif command == "models":
        models = rag.list_data_models()
        print(f"\nAvailable CIM Data Models ({len(models)}):")
        for model in models:
            print(f"  - {model}")
    
    elif command == "fields":
        if len(sys.argv) < 3:
            print("Error: data model name required")
            print('Usage: python -m src.rag_cim_docs fields <model>')
            sys.exit(1)
        
        model = sys.argv[2]
        fields = rag.get_fields_for_model(model)
        
        if fields:
            print(f"\nFields for {model} ({len(fields)}):")
            for field in fields:
                print(f"  - {field}")
        else:
            print(f"No fields found for data model: {model}")
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
