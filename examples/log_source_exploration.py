#!/usr/bin/env python3
"""
Example: Log Source Exploration
===============================

This example demonstrates how to use the Splunk Detection Engineer Agent
to explore a specific data source and get query suggestions.

Usage:
    python examples/log_source_exploration.py

Requirements:
    - Valid config/config.yaml with LLM API key
    - Splunk connection for field discovery (optional but recommended)
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.agent import SplunkAgent, QueryStatus


def main():
    """Demonstrate log source exploration."""
    print("=" * 60)
    print("Splunk Detection Engineer Agent - Log Source Exploration")
    print("=" * 60)
    print()
    
    # Initialize the agent
    print("Initializing agent...")
    agent = SplunkAgent()
    
    # Check status
    status = agent.get_status()
    print(f"LLM Provider: {status['llm_provider']}")
    print(f"Splunk Connected: {status['splunk_connected']}")
    print()
    
    # Example log source specifications
    log_sources = [
        "index=windows sourcetype=WinEventLog:Security",
        "index=sysmon sourcetype=xmlwineventlog",
        "index=firewall sourcetype=cisco:asa",
    ]
    
    # Process the first example
    log_source = log_sources[0]
    print(f"Log Source: {log_source}")
    print("-" * 60)
    print()
    
    # Generate query suggestions
    result = agent.run(log_source)
    
    # Display results
    print("Suggested SPL Query:")
    print("-" * 40)
    print(result.spl_query)
    print()
    
    print("Explanation:")
    print("-" * 40)
    print(result.explanation[:500] + "..." if len(result.explanation) > 500 else result.explanation)
    print()
    
    # Show discovered fields if available
    if result.fields_discovered:
        print("Discovered Fields:")
        print("-" * 40)
        for field in result.fields_discovered[:15]:
            print(f"  - {field}")
        if len(result.fields_discovered) > 15:
            print(f"  ... and {len(result.fields_discovered) - 15} more")
        print()
    
    print("Metadata:")
    print("-" * 40)
    print(f"  Status: {result.status.value}")
    print(f"  Input Type: {result.input_type.value}")
    print(f"  Total Time: {result.total_time:.2f}s")
    print()
    
    print("=" * 60)
    print("Other log sources you can explore:")
    for i, ls in enumerate(log_sources[1:], 2):
        print(f"  {i}. {ls}")


if __name__ == "__main__":
    main()
