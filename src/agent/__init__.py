"""
Splunk Agent Package
====================

AI-powered SPL query generation from natural language, log sources, or IOC reports.

Usage:
    from src.agent import SplunkAgent, AgentResult, AgentConfig, QueryStatus
    
    agent = SplunkAgent()
    result = agent.run("Detect brute force login attempts")
    print(result.spl_query)
    
    # With reasoning trace (Chain of Thought)
    result = agent.run("Detect T1003", show_reasoning=True)
    print(result.format_output(show_reasoning=True))
"""

from src.agent.config import AgentConfig, DEFAULT_CONFIG_PATH
from src.agent.models import AgentResult, QueryStatus
from src.agent.orchestrator import SplunkAgent
from src.agent.reasoning import ReasoningTrace, ReasoningStep, ReasoningStepType
from src.agent.grounding import GroundingResult, validate_query_grounding
from src.agent.cli import main

__all__ = [
    "SplunkAgent",
    "AgentResult",
    "AgentConfig",
    "QueryStatus",
    "ReasoningTrace",
    "ReasoningStep",
    "ReasoningStepType",
    "GroundingResult",
    "validate_query_grounding",
    "DEFAULT_CONFIG_PATH",
    "main",
]
