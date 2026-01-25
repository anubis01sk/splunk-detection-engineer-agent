#!/usr/bin/env python3
"""
Example: IOC Report Processing
==============================

This example demonstrates how to use the Splunk Detection Engineer Agent
to process threat intelligence reports and generate hunting queries.

Usage:
    python examples/ioc_report_processing.py

Requirements:
    - Valid config/config.yaml with LLM API key
    - Playwright browser installed (for URL fetching)
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.agent import SplunkAgent, QueryStatus
from src.input_processor import InputProcessor, InputType


def main():
    """Demonstrate IOC report processing."""
    print("=" * 60)
    print("Splunk Detection Engineer Agent - IOC Report Processing")
    print("=" * 60)
    print()
    
    # First, demonstrate the input processor directly
    print("Step 1: Input Processing")
    print("-" * 40)
    
    processor = InputProcessor()
    
    # Example: Process a sample text with IOCs
    sample_text = """
    The threat actor was observed using the following indicators:
    
    IP Addresses:
    - 192.168.1.100 (C2 server)
    - 10.0.0.50 (internal pivot)
    
    Domains:
    - malware-c2.evil.com
    - data-exfil.badactor.net
    
    File Hashes (SHA256):
    - a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
    
    MITRE ATT&CK Techniques:
    - T1059.001 (PowerShell)
    - T1003.001 (LSASS Memory)
    """
    
    # Note: For actual URL processing, use a real threat report URL
    # result = processor.process("https://example.com/threat-report.pdf")
    
    # For this demo, we'll show what the processor extracts
    print("Sample threat intelligence text:")
    print(sample_text[:200] + "...")
    print()
    
    # Initialize the agent for query generation
    print("Step 2: Initialize Agent")
    print("-" * 40)
    
    agent = SplunkAgent()
    status = agent.get_status()
    print(f"LLM Provider: {status['llm_provider']}")
    print(f"Detection Rules: {status['detection_rag_documents']} available")
    print()
    
    # Generate IOC hunting queries
    print("Step 3: Generate IOC Hunting Queries")
    print("-" * 40)
    
    # For demo, we'll use natural language that mentions IOCs
    ioc_query = """
    Generate a Splunk query to hunt for:
    - Connections to IP 192.168.1.100 or domain malware-c2.evil.com
    - PowerShell execution (T1059.001)
    - Potential credential dumping (T1003.001)
    """
    
    result = agent.run(ioc_query)
    
    print("Generated Hunting Query:")
    print("-" * 40)
    print(result.spl_query)
    print()
    
    print("Explanation:")
    print("-" * 40)
    print(result.explanation[:600] + "..." if len(result.explanation) > 600 else result.explanation)
    print()
    
    print("Metadata:")
    print("-" * 40)
    print(f"  Status: {result.status.value}")
    print(f"  Iterations: {result.iterations}")
    print(f"  Total Time: {result.total_time:.2f}s")
    print()
    
    if result.warnings:
        print("Warnings:")
        for w in result.warnings:
            print(f"  - {w}")
        print()
    
    print("=" * 60)
    print("Tips for IOC Report Processing:")
    print("  1. Use URLs to threat intelligence reports")
    print("  2. PDF files are also supported")
    print("  3. The agent extracts IPs, domains, hashes, CVEs, and MITRE TTPs")
    print("  4. Always review and adapt generated queries to your environment")


if __name__ == "__main__":
    main()
