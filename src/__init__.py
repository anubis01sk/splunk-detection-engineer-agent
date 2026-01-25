"""
Splunk Detection Engineer Agent
===============================

An AI-powered agent for generating production-ready Splunk SPL queries from
natural language descriptions, log source specifications, or threat intelligence reports.

Main Components:
    - SplunkAgent: Main orchestrator for SPL query generation
    - LLMProvider: Multi-provider LLM interface (Groq, Mistral, Claude, etc.)
    - SplunkClient: REST API client for Splunk Enterprise
    - SplunkRAG: Documentation knowledge base
    - DetectionRAG: Security detection rules knowledge base
    - InputProcessor: Input classification and processing

Usage:
    from src.agent import SplunkAgent
    
    agent = SplunkAgent()
    result = agent.run("Detect brute force login attempts")
    print(result.spl_query)
"""

__version__ = "1.2.4"
__author__ = "Security Engineering Team"

__all__ = [
    # Version
    "__version__",
    # Core
    "SplunkAgent",
    "AgentResult",
    "AgentConfig",
    "QueryStatus",
    "LLMProvider",
    "get_provider",
    "LLMResponse",
    "SplunkClient",
    "SplunkConfig",
    "InputProcessor",
    "ProcessedInput",
    "InputType",
    "IOCType",
    # RAG
    "SplunkRAG",
    "QueryResult",
    "DetectionRAG",
    "DetectionResult",
]

# Lazy imports to avoid RuntimeWarning when running submodules with python -m
# This defers imports until attributes are actually accessed

_import_map = {
    # src.agent package
    "SplunkAgent": "src.agent",
    "AgentResult": "src.agent",
    "AgentConfig": "src.agent",
    "QueryStatus": "src.agent",
    # src.llm_provider
    "LLMProvider": "src.llm_provider",
    "get_provider": "src.llm_provider",
    "LLMResponse": "src.llm_provider",
    # src.splunk_client
    "SplunkClient": "src.splunk_client",
    "SplunkConfig": "src.splunk_client",
    # src.input_processor
    "InputProcessor": "src.input_processor",
    "ProcessedInput": "src.input_processor",
    "InputType": "src.input_processor",
    "IOCType": "src.input_processor",
    # src.rag_spl_docs
    "SplunkRAG": "src.rag_spl_docs",
    "QueryResult": "src.rag_spl_docs",
    # src.rag_detections
    "DetectionRAG": "src.rag_detections",
    "DetectionResult": "src.rag_detections",
}


def __getattr__(name: str):
    """Lazy import mechanism - only imports when the attribute is accessed."""
    if name in _import_map:
        module_path = _import_map[name]
        import importlib
        module = importlib.import_module(module_path)
        return getattr(module, name)
    raise AttributeError(f"module 'src' has no attribute '{name}'")


def __dir__():
    """List available attributes for tab completion and dir()."""
    return __all__
