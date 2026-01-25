#!/usr/bin/env python3
"""
Example: Generate SPL Query from Natural Language
==================================================

This example demonstrates how to use the Splunk Detection Engineer Agent
to generate SPL queries from natural language descriptions.

Usage:
    python examples/natural_language_query.py

Requirements:
    - Valid config/config.yaml with LLM API key
    - (Optional) Splunk connection for query validation
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.agent import SplunkAgent, QueryStatus


def main():
    """Demonstrate natural language query generation."""
    print("=" * 60)
    print("Splunk Detection Engineer Agent - Natural Language Example")
    print("=" * 60)
    print()
    
    # Initialize the agent
    print("Initializing agent...")
    agent = SplunkAgent()
    
    # Check status
    status = agent.get_status()
    print(f"LLM Provider: {status['llm_provider']}")
    print(f"Splunk Connected: {status['splunk_connected']}")
    print(f"Documentation: {status['doc_rag_documents']} documents")
    print(f"Detections: {status['detection_rag_documents']} rules")
    print()
    
    # Example queries to demonstrate
    example_queries = [
        "Detect brute force login attempts on Windows systems",
        "Find PowerShell commands that download files from the internet",
        "Alert on suspicious process creation from Office applications",
    ]
    
    # Process the first example
    query = example_queries[0]
    print(f"Query: {query}")
    print("-" * 60)
    print()
    
    # Generate the SPL query
    result = agent.run(query)
    
    # Display results
    print("Generated SPL Query:")
    print("-" * 40)
    print(result.spl_query)
    print()
    
    print("Explanation:")
    print("-" * 40)
    print(result.explanation[:500] + "..." if len(result.explanation) > 500 else result.explanation)
    print()
    
    print("Metadata:")
    print("-" * 40)
    print(f"  Status: {result.status.value}")
    print(f"  Input Type: {result.input_type.value}")
    print(f"  Iterations: {result.iterations}")
    print(f"  Total Time: {result.total_time:.2f}s")
    print(f"  Validated: {result.validated}")
    if result.result_count > 0:
        print(f"  Results: {result.result_count}")
    print()
    
    if result.warnings:
        print("Warnings:")
        for w in result.warnings:
            print(f"  - {w}")
        print()
    
    print("=" * 60)
    print("Other example queries you can try:")
    for i, q in enumerate(example_queries[1:], 2):
        print(f"  {i}. {q}")


if __name__ == "__main__":
    main()
