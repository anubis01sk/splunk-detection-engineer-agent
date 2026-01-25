#!/usr/bin/env python3
"""
Splunk Documentation RAG Ingestion and Query System
====================================================

Loads SPL documentation chunks into ChromaDB with BGE-small-en-v1.5 embeddings
for retrieval-augmented generation. Provides a query interface for agents
building Splunk searches.

Features:
- ChromaDB persistent vector storage (no server required)
- BGE-small-en-v1.5 embeddings optimized for CPU
- Metadata filtering by manual, command, and section
- Hybrid search combining semantic similarity with keyword matching

Usage:
    # Ingest documentation (uses default data file)
    python -m src.rag_spl_docs ingest
    
    # Query the database
    python -m src.rag_spl_docs query "How do I calculate average by host?"
    
    # Interactive mode
    python -m src.rag_spl_docs interactive
    
    # Show database statistics
    python -m src.rag_spl_docs stats

Dependencies:
    pip install chromadb sentence-transformers

Author: Claude (Anthropic)
"""

import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# Disable ChromaDB telemetry before import
os.environ["ANONYMIZED_TELEMETRY"] = "False"

import chromadb
from chromadb.config import Settings
from chromadb.utils import embedding_functions

# Suppress ChromaDB telemetry errors
import logging
logging.getLogger("chromadb.telemetry.product.posthog").setLevel(logging.CRITICAL)


# =============================================================================
# CONFIGURATION
# =============================================================================

# Path relative to project root (parent of src/)
DEFAULT_DB_PATH = str(Path(__file__).parent.parent / "vector_dbs" / "spl_docs")
DEFAULT_DATA_FILE = Path(__file__).parent.parent / "data" / "splunk_spl_docs.jsonl"
DEFAULT_COLLECTION_NAME = "spl_documentation"
EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"
DEFAULT_TOP_K = 5
BATCH_SIZE = 100


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class QueryResult:
    """Represents a single search result."""
    content: str
    title: str
    section_heading: str
    url: str
    manual: str
    similarity: float
    code_examples: list[dict]
    tables: list[dict]

    def to_context_string(self) -> str:
        """Format result for LLM context injection."""
        lines = []
        header = f"[{self.manual}] {self.title}"
        if self.section_heading:
            header += f" > {self.section_heading}"
        lines.append(header)
        lines.append("-" * len(header))
        if self.content:
            lines.append(self.content)
        if self.code_examples:
            lines.append("\nCode Examples:")
            for example in self.code_examples:
                code = example.get("code", "")
                lines.append(f"```spl\n{code}\n```")
        if self.tables:
            lines.append("\nReference Tables:")
            for table in self.tables:
                headers = table.get("headers", [])
                if headers:
                    lines.append("| " + " | ".join(headers) + " |")
                    lines.append("| " + " | ".join(["---"] * len(headers)) + " |")
                for row in table.get("rows", [])[:5]:
                    lines.append("| " + " | ".join(str(cell) for cell in row) + " |")
        lines.append(f"\nSource: {self.url}")
        return "\n".join(lines)


@dataclass
class IngestStats:
    """Statistics from ingestion process."""
    total_chunks: int = 0
    successful: int = 0
    failed: int = 0
    duration_seconds: float = 0.0


# =============================================================================
# SPLUNK RAG SYSTEM
# =============================================================================

class SplunkRAG:
    """ChromaDB-based RAG system for Splunk documentation."""

    def __init__(
        self,
        db_path: str = DEFAULT_DB_PATH,
        collection_name: str = DEFAULT_COLLECTION_NAME,
    ):
        self.db_path = db_path
        self.collection_name = collection_name
        self._client: Optional[chromadb.PersistentClient] = None
        self._collection = None
        self._embedding_fn = None

    def _get_client(self) -> chromadb.PersistentClient:
        """Lazy initialization of ChromaDB client."""
        if self._client is None:
            Path(self.db_path).mkdir(parents=True, exist_ok=True)
            self._client = chromadb.PersistentClient(
                path=self.db_path,
                settings=Settings(anonymized_telemetry=False),
            )
        return self._client

    def _get_embedding_fn(self):
        """Lazy initialization of embedding function."""
        if self._embedding_fn is None:
            print(f"[*] Loading embedding model: {EMBEDDING_MODEL}")
            self._embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
                model_name=EMBEDDING_MODEL,
                device="cpu",
            )
            print("[+] Embedding model loaded")
        return self._embedding_fn

    def _get_collection(self):
        """Get or create the document collection."""
        if self._collection is None:
            client = self._get_client()
            embedding_fn = self._get_embedding_fn()
            self._collection = client.get_or_create_collection(
                name=self.collection_name,
                embedding_function=embedding_fn,
                metadata={"hnsw:space": "cosine"},
            )
        return self._collection

    def ingest_jsonl(self, jsonl_path: Path = DEFAULT_DATA_FILE) -> IngestStats:
        """
        Ingest chunks from a JSON Lines file into ChromaDB.
        
        Args:
            jsonl_path: Path to the splunk_spl_docs.jsonl file.
                        Defaults to data/splunk_spl_docs.jsonl
            
        Returns:
            IngestStats with ingestion results.
        """
        stats = IngestStats()
        start_time = time.time()
        path = Path(jsonl_path)
        if not path.exists():
            raise FileNotFoundError(f"JSONL file not found: {jsonl_path}")
        print(f"[*] Reading chunks from: {jsonl_path}")
        chunks = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        chunk = json.loads(line)
                        chunks.append(chunk)
                    except json.JSONDecodeError as e:
                        print(f"[!] Skipping malformed line: {e}")
                        stats.failed += 1
        stats.total_chunks = len(chunks)
        print(f"[*] Loaded {stats.total_chunks} chunks")
        if not chunks:
            print("[!] No chunks to ingest")
            return stats
        collection = self._get_collection()
        existing_count = collection.count()
        if existing_count > 0:
            print(f"[*] Collection already contains {existing_count} documents")
            print("[*] Clearing existing documents...")
            existing_ids = collection.get()["ids"]
            if existing_ids:
                collection.delete(ids=existing_ids)
            print("[+] Collection cleared")
        print(f"[*] Ingesting {len(chunks)} chunks in batches of {BATCH_SIZE}...")
        for i in range(0, len(chunks), BATCH_SIZE):
            batch = chunks[i:i + BATCH_SIZE]
            ids = []
            documents = []
            metadatas = []
            for chunk in batch:
                chunk_id = chunk.get("id", "")
                if not chunk_id:
                    stats.failed += 1
                    continue
                content = chunk.get("content", "")
                metadata = chunk.get("metadata", {})
                code_examples = chunk.get("code_examples", [])
                tables = chunk.get("tables", [])
                doc_text = content
                if code_examples:
                    code_str = " ".join(ex.get("code", "") for ex in code_examples)
                    doc_text = f"{content} {code_str}"
                meta = {
                    "title": metadata.get("title", ""),
                    "section_heading": metadata.get("section_heading", ""),
                    "section_id": metadata.get("section_id", ""),
                    "url": metadata.get("url", ""),
                    "breadcrumb": metadata.get("breadcrumb", ""),
                    "manual": metadata.get("manual", ""),
                    "chunk_index": chunk.get("chunk_index", 0),
                    "total_chunks": chunk.get("total_chunks", 1),
                    "code_examples_json": json.dumps(code_examples),
                    "tables_json": json.dumps(tables),
                }
                ids.append(chunk_id)
                documents.append(doc_text)
                metadatas.append(meta)
            if ids:
                try:
                    collection.add(ids=ids, documents=documents, metadatas=metadatas)
                    stats.successful += len(ids)
                except Exception as e:
                    print(f"[!] Batch ingestion error: {e}")
                    stats.failed += len(ids)
            progress = min(i + BATCH_SIZE, len(chunks))
            print(f"    Progress: {progress}/{len(chunks)} chunks")
        stats.duration_seconds = time.time() - start_time
        print(f"\n[+] Ingestion complete")
        print(f"    Successful: {stats.successful}")
        print(f"    Failed: {stats.failed}")
        print(f"    Duration: {stats.duration_seconds:.1f}s")
        return stats

    def query(
        self,
        query_text: str,
        top_k: int = DEFAULT_TOP_K,
        manual_filter: Optional[str] = None,
        include_code: bool = True,
    ) -> list[QueryResult]:
        """
        Query the documentation for relevant chunks.
        
        Args:
            query_text: Natural language query about SPL.
            top_k: Number of results to return.
            manual_filter: Optional filter by manual name ("search-manual" or "spl-search-reference").
            include_code: Whether to parse and include code examples in results.
            
        Returns:
            List of QueryResult objects ranked by relevance.
        """
        collection = self._get_collection()
        where_filter = None
        if manual_filter:
            where_filter = {"manual": {"$eq": manual_filter}}
        results = collection.query(
            query_texts=[query_text],
            n_results=top_k,
            where=where_filter,
            include=["documents", "metadatas", "distances"],
        )
        query_results = []
        if results and results["ids"] and results["ids"][0]:
            for i, doc_id in enumerate(results["ids"][0]):
                metadata = results["metadatas"][0][i] if results["metadatas"] else {}
                distance = results["distances"][0][i] if results["distances"] else 0.0
                similarity = 1.0 - distance
                code_examples = []
                tables = []
                if include_code:
                    code_json = metadata.get("code_examples_json", "[]")
                    tables_json = metadata.get("tables_json", "[]")
                    try:
                        code_examples = json.loads(code_json)
                        tables = json.loads(tables_json)
                    except json.JSONDecodeError:
                        pass
                content = results["documents"][0][i] if results["documents"] else ""
                query_results.append(QueryResult(
                    content=content,
                    title=metadata.get("title", ""),
                    section_heading=metadata.get("section_heading", ""),
                    url=metadata.get("url", ""),
                    manual=metadata.get("manual", ""),
                    similarity=similarity,
                    code_examples=code_examples,
                    tables=tables,
                ))
        return query_results

    def get_context_for_agent(
        self,
        query_text: str,
        top_k: int = DEFAULT_TOP_K,
        manual_filter: Optional[str] = None,
    ) -> str:
        """
        Get formatted context string for LLM agent injection.
        
        Args:
            query_text: The user's question about SPL.
            top_k: Number of documentation chunks to retrieve.
            manual_filter: Optional manual filter.
            
        Returns:
            Formatted string ready for LLM context.
        """
        results = self.query(query_text, top_k=top_k, manual_filter=manual_filter)
        if not results:
            return "No relevant SPL documentation found for this query."
        context_parts = [
            "=== RELEVANT SPLUNK SPL DOCUMENTATION ===\n"
        ]
        for i, result in enumerate(results, 1):
            context_parts.append(f"\n--- Result {i} (Relevance: {result.similarity:.2f}) ---\n")
            context_parts.append(result.to_context_string())
            context_parts.append("\n")
        context_parts.append("\n=== END DOCUMENTATION ===")
        return "\n".join(context_parts)

    def get_stats(self) -> dict:
        """Get collection statistics."""
        collection = self._get_collection()
        count = collection.count()
        sample = collection.peek(limit=5) if count > 0 else {}
        manuals = set()
        if sample and "metadatas" in sample:
            for meta in sample["metadatas"]:
                manual = meta.get("manual", "")
                if manual:
                    manuals.add(manual)
        return {
            "total_documents": count,
            "collection_name": self.collection_name,
            "db_path": self.db_path,
            "embedding_model": EMBEDDING_MODEL,
            "sample_manuals": list(manuals),
        }


# =============================================================================
# CLI INTERFACE
# =============================================================================

def print_usage():
    """Print CLI usage instructions."""
    print("""
Splunk Documentation RAG System
===============================

Usage:
    python -m src.rag_spl_docs <command> [arguments]

Commands:
    ingest [jsonl_file]     Ingest documentation chunks into ChromaDB
                            (defaults to data/splunk_spl_docs.jsonl)
    query <text>            Query the documentation
    interactive             Start interactive query mode
    stats                   Show database statistics
    context <text>          Get formatted context for LLM agent

Options:
    --db-path <path>        ChromaDB storage path (default: ./spl_vector_db)
    --top-k <n>             Number of results to return (default: 5)
    --manual <name>         Filter by manual (search-manual or spl-search-reference)

Examples:
    python -m src.rag_spl_docs ingest
    python -m src.rag_spl_docs ingest data/splunk_spl_docs.jsonl
    python -m src.rag_spl_docs query "How do I use the stats command?"
    python -m src.rag_spl_docs query "calculate average" --top-k 10
    python -m src.rag_spl_docs context "filter events by source type"
    python -m src.rag_spl_docs interactive
""")


def parse_args(args: list[str]) -> dict:
    """Parse command line arguments."""
    parsed = {
        "command": None,
        "argument": None,
        "db_path": DEFAULT_DB_PATH,
        "top_k": DEFAULT_TOP_K,
        "manual": None,
    }
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--db-path" and i + 1 < len(args):
            parsed["db_path"] = args[i + 1]
            i += 2
        elif arg == "--top-k" and i + 1 < len(args):
            parsed["top_k"] = int(args[i + 1])
            i += 2
        elif arg == "--manual" and i + 1 < len(args):
            parsed["manual"] = args[i + 1]
            i += 2
        elif not arg.startswith("--"):
            if parsed["command"] is None:
                parsed["command"] = arg
            elif parsed["argument"] is None:
                parsed["argument"] = arg
            i += 1
        else:
            i += 1
    return parsed


def run_interactive(rag: SplunkRAG, top_k: int, manual_filter: Optional[str]):
    """Run interactive query mode."""
    print("\n" + "=" * 60)
    print("SPLUNK SPL DOCUMENTATION QUERY")
    print("=" * 60)
    print("Type your question about SPL and press Enter.")
    print("Commands: 'quit' to exit, 'stats' for database info")
    print("=" * 60 + "\n")
    while True:
        try:
            query = input("Query> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break
        if not query:
            continue
        if query.lower() in ("quit", "exit", "q"):
            print("Goodbye!")
            break
        if query.lower() == "stats":
            stats = rag.get_stats()
            print(f"\nDatabase Statistics:")
            print(f"  Documents: {stats['total_documents']}")
            print(f"  Collection: {stats['collection_name']}")
            print(f"  Path: {stats['db_path']}")
            print()
            continue
        print("\nSearching...\n")
        results = rag.query(query, top_k=top_k, manual_filter=manual_filter)
        if not results:
            print("No relevant documentation found.\n")
            continue
        for i, result in enumerate(results, 1):
            print(f"--- Result {i} (Similarity: {result.similarity:.3f}) ---")
            print(f"Title: {result.title}")
            if result.section_heading:
                print(f"Section: {result.section_heading}")
            print(f"Manual: {result.manual}")
            print(f"URL: {result.url}")
            print()
            content_preview = result.content[:500]
            if len(result.content) > 500:
                content_preview += "..."
            print(content_preview)
            if result.code_examples:
                print("\nCode Examples:")
                for ex in result.code_examples[:2]:
                    print(f"  ```\n  {ex.get('code', '')}\n  ```")
            print()
        print("-" * 60 + "\n")


def main():
    """CLI entry point."""
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(0)
    args = parse_args(sys.argv[1:])
    command = args["command"]
    if not command:
        print_usage()
        sys.exit(1)
    rag = SplunkRAG(db_path=args["db_path"])
    if command == "ingest":
        jsonl_path = args["argument"] if args["argument"] else DEFAULT_DATA_FILE
        print(f"[*] Using data file: {jsonl_path}")
        stats = rag.ingest_jsonl(jsonl_path)
        print(f"\nIngestion Summary:")
        print(f"  Total chunks: {stats.total_chunks}")
        print(f"  Successful: {stats.successful}")
        print(f"  Failed: {stats.failed}")
        print(f"  Duration: {stats.duration_seconds:.1f}s")
    elif command == "query":
        if not args["argument"]:
            print("Error: Please provide a query")
            print("Usage: python -m src.rag_spl_docs query <text>")
            sys.exit(1)
        results = rag.query(
            args["argument"],
            top_k=args["top_k"],
            manual_filter=args["manual"],
        )
        if not results:
            print("No relevant documentation found.")
            sys.exit(0)
        for i, result in enumerate(results, 1):
            print(f"\n--- Result {i} (Similarity: {result.similarity:.3f}) ---")
            print(f"Title: {result.title}")
            if result.section_heading:
                print(f"Section: {result.section_heading}")
            print(f"Manual: {result.manual}")
            print(f"URL: {result.url}")
            print(f"\n{result.content[:500]}...")
            if result.code_examples:
                print("\nCode Examples:")
                for ex in result.code_examples[:2]:
                    print(f"```\n{ex.get('code', '')}\n```")
    elif command == "context":
        if not args["argument"]:
            print("Error: Please provide a query")
            sys.exit(1)
        context = rag.get_context_for_agent(
            args["argument"],
            top_k=args["top_k"],
            manual_filter=args["manual"],
        )
        print(context)
    elif command == "interactive":
        run_interactive(rag, args["top_k"], args["manual"])
    elif command == "stats":
        stats = rag.get_stats()
        print("\nDatabase Statistics")
        print("=" * 40)
        print(f"Total documents: {stats['total_documents']}")
        print(f"Collection name: {stats['collection_name']}")
        print(f"Database path: {stats['db_path']}")
        print(f"Embedding model: {stats['embedding_model']}")
        if stats['sample_manuals']:
            print(f"Manuals indexed: {', '.join(stats['sample_manuals'])}")
    else:
        print(f"Unknown command: {command}")
        print_usage()
        sys.exit(1)


if __name__ == "__main__":
    main()
