"""
Agent Data Models
=================

Output models and status enums for the Splunk Agent.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, TYPE_CHECKING

from src.input_processor import InputType

if TYPE_CHECKING:
    from src.agent.reasoning import ReasoningTrace
    from src.agent.grounding import GroundingResult


class QueryStatus(str, Enum):
    """Status of the generated query.
    
    Extends str for JSON serialization compatibility across API boundaries.
    """
    SUCCESS = "success"
    PARTIAL = "partial"  # Query generated but not fully validated
    FAILED = "failed"


@dataclass
class AgentResult:
    """Result from the Splunk Agent."""
    status: QueryStatus
    spl_query: str
    explanation: str
    
    # Metadata
    input_type: InputType = InputType.UNKNOWN
    iterations: int = 0
    total_time: float = 0.0
    
    # Validation results
    validated: bool = False
    result_count: int = 0
    fields_discovered: list[str] = field(default_factory=list)
    
    # Context used
    documentation_context: str = ""
    detection_context: str = ""
    cim_context: str = ""
    attack_data_context: str = ""
    
    # For IOC reports
    ioc_summary: str = ""
    
    # Warnings and errors
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    
    # Iteration history
    iteration_history: list[dict] = field(default_factory=list)
    
    # Reasoning trace for Chain of Thought display
    reasoning_trace: Optional["ReasoningTrace"] = None
    
    # Grounding validation result
    grounding_result: Optional["GroundingResult"] = None
    
    # Token usage for this run
    token_usage: dict = field(default_factory=lambda: {
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "request_count": 0,
    })
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        result = {
            "status": self.status.value,
            "spl_query": self.spl_query,
            "explanation": self.explanation,
            "input_type": self.input_type.value,
            "iterations": self.iterations,
            "total_time": self.total_time,
            "validated": self.validated,
            "result_count": self.result_count,
            "fields_discovered": self.fields_discovered,
            "ioc_summary": self.ioc_summary,
            "warnings": self.warnings,
            "errors": self.errors,
        }
        
        # Include reasoning trace if available
        if self.reasoning_trace:
            result["reasoning"] = self.reasoning_trace.to_dict()
            result["confidence_score"] = self.reasoning_trace.get_confidence_score()
        
        # Include grounding result if available
        if self.grounding_result:
            result["grounding"] = self.grounding_result.to_dict()
        
        # Include token usage
        result["token_usage"] = self.token_usage
        
        return result
    
    def format_output(self, show_reasoning: bool = False) -> str:
        """
        Format result for display.
        
        Args:
            show_reasoning: If True, include detailed reasoning trace
        """
        lines = [
            "=" * 70,
            "SPLUNK SPL AGENT - QUERY GENERATION RESULT",
            "=" * 70,
            "",
            f"Status: {self.status.value.upper()}",
            f"Input Type: {self.input_type.value}",
            f"Iterations: {self.iterations}",
            f"Total Time: {self.total_time:.2f}s",
        ]
        
        # Show token usage
        if self.token_usage and self.token_usage.get("total_tokens", 0) > 0:
            tokens = self.token_usage
            lines.append(f"Tokens: {tokens['total_tokens']:,} (in: {tokens['input_tokens']:,}, out: {tokens['output_tokens']:,})")
        
        # Show confidence score if reasoning is available
        if self.reasoning_trace:
            confidence = self.reasoning_trace.get_confidence_score()
            confidence_bar = "█" * int(confidence * 10) + "░" * (10 - int(confidence * 10))
            lines.append(f"Confidence: [{confidence_bar}] {confidence:.1%}")
        
        lines.extend([
            "",
            "--- GENERATED SPL QUERY ---",
            "",
            self.spl_query,
            "",
            "--- EXPLANATION ---",
            "",
            self.explanation,
        ])
        
        if self.validated:
            lines.extend([
                "",
                "--- VALIDATION ---",
                f"Validated: Yes",
                f"Result Count: {self.result_count}",
            ])
            if self.fields_discovered:
                lines.append(f"Fields: {', '.join(self.fields_discovered[:10])}")
        
        if self.ioc_summary:
            lines.extend([
                "",
                "--- IOC SUMMARY ---",
                self.ioc_summary,
            ])
        
        # Show reasoning trace if requested
        if show_reasoning and self.reasoning_trace:
            lines.append("")
            lines.append(self.reasoning_trace.format_cli())
        
        # Show grounding information
        if self.grounding_result:
            lines.extend([
                "",
                "--- GROUNDING ---",
            ])
            if self.grounding_result.is_grounded:
                lines.append(f"✅ Query is grounded ({self.grounding_result.grounding_score:.0%} confidence)")
            else:
                lines.append(f"⚠️ Query contains unverified fields ({self.grounding_result.grounding_score:.0%} confidence)")
            
            if self.grounding_result.sources_used:
                lines.append(f"   Sources: {', '.join(self.grounding_result.sources_used)}")
            
            if self.grounding_result.unknown_fields:
                lines.append("   Unknown fields:")
                for f in self.grounding_result.unknown_fields[:5]:
                    suggestion_str = f" (try: {', '.join(f.suggestions)})" if f.suggestions else ""
                    lines.append(f"     - {f.field_name}{suggestion_str}")
        
        if self.warnings:
            lines.extend([
                "",
                "--- WARNINGS ---",
            ])
            for w in self.warnings:
                lines.append(f"  - {w}")
        
        if self.errors:
            lines.extend([
                "",
                "--- ERRORS ---",
            ])
            for e in self.errors:
                lines.append(f"  - {e}")
        
        lines.append("")
        lines.append("=" * 70)
        
        return "\n".join(lines)
