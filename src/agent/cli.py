"""
Agent CLI Interface
===================

Command-line interface for the Splunk Agent.
"""

import sys

from src.agent.orchestrator import SplunkAgent
from src.agent.reasoning import ReasoningStep


def print_reasoning_step(step: ReasoningStep):
    """Print a reasoning step in real-time."""
    status_icons = {
        "pending": "⏳",
        "in_progress": "🔄",
        "complete": "✓",
        "error": "✗",
    }
    icon = status_icons.get(step.status, "•")
    print(f"  {icon} {step.title}")


def main():
    """CLI entry point."""
    if len(sys.argv) < 2:
        print("""
Splunk SPL Agent - Query Generator
===================================

Usage:
    python -m src.agent run "<input>"         Generate SPL query
    python -m src.agent run --reason "<in>"   Generate with reasoning trace
    python -m src.agent status                Show component status
    python -m src.agent interactive           Interactive mode

Options:
    --reason, -r      Show chain-of-thought reasoning process

Input Types:
    Natural Language:  "Detect brute force login attempts"
    Log Source:        "index=windows sourcetype=WinEventLog:Security"
    IOC Report:        "https://example.com/report.pdf" or "/path/to/report.pdf"

Examples:
    python -m src.agent run "Detect credential dumping from LSASS"
    python -m src.agent run --reason "Create a detection for T1003"
    python -m src.agent interactive
""")
        sys.exit(0)
    
    command = sys.argv[1].lower()
    
    if command == "status":
        print("\nInitializing Splunk Agent...")
        agent = SplunkAgent()
        
        print("\nTesting connections...")
        status = agent.get_status(test_llm=True)
        
        print("\nSplunk SPL Agent Status")
        print("=" * 40)
        
        # LLM Status
        llm_status = "Not configured"
        if status['llm_provider']:
            if status['llm_connected']:
                llm_status = f"{status['llm_provider']} ✓ Connected"
            elif status['llm_error']:
                llm_status = f"{status['llm_provider']} ✗ Error: {status['llm_error'][:50]}"
            else:
                llm_status = f"{status['llm_provider']} (not tested)"
        print(f"AI Provider: {llm_status}")
        
        # Splunk Status
        print(f"Splunk: {'✓ Connected' if status['splunk_connected'] else '✗ Not connected'}")
        
        # RAG Status
        print("-" * 40)
        print("Knowledge Bases:")
        print(f"  SPL Documentation: {status['doc_rag_documents']} documents")
        print(f"  Detection Rules:   {status['detection_rag_documents']} detections")
        print(f"  CIM Data Models:   {status['cim_rag_chunks']} chunks")
        print(f"  Attack Data:       {status['attack_data_rag_datasets']} datasets")
        print("=" * 40)
    
    elif command == "run":
        if len(sys.argv) < 3:
            print("Error: input required")
            print('Usage: python -m src.agent run "<input>"')
            sys.exit(1)
        
        # Parse arguments
        show_reasoning = False
        user_input = None
        
        args = sys.argv[2:]
        i = 0
        while i < len(args):
            arg = args[i]
            if arg in ("--reason", "-r", "--reasoning"):
                show_reasoning = True
            elif not arg.startswith("-"):
                user_input = arg
            i += 1
        
        if not user_input:
            print("Error: input required")
            print('Usage: python -m src.agent run "<input>"')
            sys.exit(1)
        
        print("\nInitializing Splunk Agent...")
        agent = SplunkAgent()
        
        print(f"\nProcessing: {user_input[:80]}{'...' if len(user_input) > 80 else ''}\n")
        
        # Create callback for real-time reasoning display
        if show_reasoning:
            print("🔍 REASONING PROCESS")
            print("-" * 40)
            
            def reasoning_callback(step: ReasoningStep):
                if step.status == "in_progress":
                    print(f"  🔄 {step.title}...")
                elif step.status == "complete":
                    print(f"  ✓ {step.title}")
                elif step.status == "error":
                    print(f"  ✗ {step.title}: {step.details.get('error', 'Error')[:50]}")
            
            result = agent.run(user_input, show_reasoning=True, reasoning_callback=reasoning_callback)
            print("-" * 40)
            print()
        else:
            result = agent.run(user_input)
        
        # Show output with full reasoning if requested
        print(result.format_output(show_reasoning=show_reasoning))
    
    elif command == "interactive":
        print("\nSplunk SPL Agent - Interactive Mode")
        print("=" * 40)
        print("Commands:")
        print("  quit       - Exit")
        print("  status     - Show component status")
        print("  reason on  - Enable Chain of Thought display")
        print("  reason off - Disable Chain of Thought display")
        print()
        
        agent = SplunkAgent()
        print("Testing connections...")
        status = agent.get_status(test_llm=True)
        
        # AI Status
        if status['llm_connected']:
            print(f"AI: {status['llm_provider']} ✓")
        elif status['llm_provider']:
            print(f"AI: {status['llm_provider']} ✗ {status.get('llm_error', 'Connection failed')[:40]}")
        else:
            print("AI: Not configured")
        
        print(f"Splunk: {'✓ Connected' if status['splunk_connected'] else '✗ Not connected'}")
        print(f"RAG: {status['doc_rag_documents']} docs, {status['detection_rag_documents']} detections")
        print()
        
        show_reasoning = False
        
        while True:
            try:
                prompt = f"Agent{'[reason]' if show_reasoning else ''}> "
                user_input = input(prompt).strip()
                
                if not user_input:
                    continue
                
                if user_input.lower() == "quit":
                    break
                
                if user_input.lower() == "reason on":
                    show_reasoning = True
                    print("Chain of Thought enabled ✓\n")
                    continue
                
                if user_input.lower() == "reason off":
                    show_reasoning = False
                    print("Chain of Thought disabled\n")
                    continue
                
                if user_input.lower() == "status":
                    status = agent.get_status(test_llm=False)
                    print(f"\nAI: {status['llm_provider'] or 'Not configured'}")
                    print(f"Splunk: {'✓ Connected' if status['splunk_connected'] else '✗ Not connected'}")
                    print(f"RAG: {status['doc_rag_documents']} docs, {status['detection_rag_documents']} detections")
                    print(f"Reasoning: {'Enabled' if show_reasoning else 'Disabled'}\n")
                    continue
                
                print("\nProcessing...\n")
                
                if show_reasoning:
                    print("🔍 REASONING PROCESS")
                    print("-" * 40)
                    
                    def callback(step: ReasoningStep):
                        if step.status == "in_progress":
                            print(f"  🔄 {step.title}...")
                        elif step.status == "complete":
                            print(f"  ✓ {step.title}")
                    
                    result = agent.run(user_input, show_reasoning=True, reasoning_callback=callback)
                    print("-" * 40)
                    print()
                else:
                    result = agent.run(user_input)
                
                print(result.format_output(show_reasoning=show_reasoning))
                
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
