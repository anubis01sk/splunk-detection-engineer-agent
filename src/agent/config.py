"""
Agent Configuration
===================

Configuration classes and utilities for the Splunk Agent.
"""

from dataclasses import dataclass
from pathlib import Path

import yaml


DEFAULT_CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "config.yaml"


@dataclass
class AgentConfig:
    """Configuration for the Splunk Agent."""
    max_iterations: int = 5
    validation_time_range: str = "-24h"
    validation_max_results: int = 100
    context_top_k: int = 5
    enable_splunk_validation: bool = True
    enable_field_discovery: bool = True
    
    @classmethod
    def from_yaml(cls, path: Path = DEFAULT_CONFIG_PATH) -> "AgentConfig":
        """Load configuration from YAML file."""
        if not path.exists():
            return cls()
        
        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}
        
        agent_data = data.get("agent", {})
        
        return cls(
            max_iterations=agent_data.get("max_iterations", 5),
            validation_time_range=agent_data.get("validation_time_range", "-24h"),
            validation_max_results=agent_data.get("validation_max_results", 100),
            context_top_k=data.get("rag", {}).get("top_k", 5),
            enable_splunk_validation=agent_data.get("enable_splunk_validation", True),
            enable_field_discovery=agent_data.get("enable_field_discovery", True),
        )
