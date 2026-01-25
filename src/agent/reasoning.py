"""
Reasoning Trace System
======================

Data structures and utilities for tracking the agent's reasoning process.
Shows step-by-step how the agent generates SPL queries, including:
- Input classification
- RAG retrievals and similarity scores
- Field selection rationale
- Query construction steps
- Validation results

This enables users to see WHY the agent made specific decisions.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional, Callable
import time


class ReasoningStepType(Enum):
    """Types of reasoning steps."""
    INPUT_CLASSIFICATION = "input_classification"
    RAG_RETRIEVAL = "rag_retrieval"
    CONTEXT_BUILDING = "context_building"
    QUERY_GENERATION = "query_generation"
    VALIDATION = "validation"
    REFINEMENT = "refinement"
    FIELD_SELECTION = "field_selection"
    COMPLETE = "complete"
    ERROR = "error"


@dataclass
class RAGResult:
    """Result from a RAG query."""
    source: str  # "spl_docs", "detections", "cim", "attack_data"
    query: str
    matches: int
    top_score: float
    top_results: list[dict] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "query": self.query,
            "matches": self.matches,
            "top_score": self.top_score,
            "top_results": self.top_results[:3],  # Limit for display
        }


@dataclass
class ReasoningStep:
    """A single step in the reasoning process."""
    step_type: ReasoningStepType
    title: str
    status: str = "pending"  # pending, in_progress, complete, error
    details: dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    duration_ms: float = 0
    
    def to_dict(self) -> dict:
        return {
            "step_type": self.step_type.value,
            "title": self.title,
            "status": self.status,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
            "duration_ms": self.duration_ms,
        }
    
    def format_cli(self) -> str:
        """Format step for CLI display."""
        status_icons = {
            "pending": "⏳",
            "in_progress": "🔄",
            "complete": "✓",
            "error": "✗",
        }
        icon = status_icons.get(self.status, "•")
        
        lines = [f"{icon} {self.title}"]
        
        # Add relevant details based on step type
        if self.step_type == ReasoningStepType.INPUT_CLASSIFICATION:
            if "input_type" in self.details:
                lines.append(f"   └─ Type: {self.details['input_type']}")
            if "confidence" in self.details:
                lines.append(f"   └─ Confidence: {self.details['confidence']:.2f}")
        
        elif self.step_type == ReasoningStepType.RAG_RETRIEVAL:
            for rag in self.details.get("rag_results", []):
                if isinstance(rag, dict):
                    score_str = f"(best: {rag['top_score']:.2f})" if rag.get('top_score') else ""
                    lines.append(f"   └─ {rag['source']}: {rag['matches']} matches {score_str}")
        
        elif self.step_type == ReasoningStepType.FIELD_SELECTION:
            if "cim_fields" in self.details:
                fields = self.details["cim_fields"][:5]
                lines.append(f"   └─ CIM Fields: {', '.join(fields)}")
            if "discovered_fields" in self.details:
                fields = self.details["discovered_fields"][:5]
                lines.append(f"   └─ Discovered: {', '.join(fields)}")
        
        elif self.step_type == ReasoningStepType.QUERY_GENERATION:
            if "template" in self.details:
                lines.append(f"   └─ Using template: {self.details['template']}")
            if "query_preview" in self.details:
                preview = self.details["query_preview"][:60]
                lines.append(f"   └─ Query: {preview}...")
        
        elif self.step_type == ReasoningStepType.VALIDATION:
            if "result_count" in self.details:
                lines.append(f"   └─ Results: {self.details['result_count']} events")
            if "validated" in self.details:
                status = "✓ Valid" if self.details["validated"] else "✗ Invalid"
                lines.append(f"   └─ Status: {status}")
            if "error" in self.details:
                lines.append(f"   └─ Error: {self.details['error'][:50]}...")
        
        elif self.step_type == ReasoningStepType.REFINEMENT:
            if "iteration" in self.details:
                lines.append(f"   └─ Iteration: {self.details['iteration']}")
            if "reason" in self.details:
                lines.append(f"   └─ Reason: {self.details['reason'][:50]}...")
        
        if self.duration_ms > 0:
            lines.append(f"   └─ Time: {self.duration_ms:.0f}ms")
        
        return "\n".join(lines)


class ReasoningTrace:
    """
    Collects and manages reasoning steps during query generation.
    
    Usage:
        trace = ReasoningTrace()
        
        with trace.step("Input Classification") as step:
            # Do classification
            step.details["input_type"] = "natural_language"
        
        # Get formatted output
        print(trace.format_cli())
    """
    
    def __init__(self, callback: Optional[Callable[[ReasoningStep], None]] = None):
        """
        Initialize reasoning trace.
        
        Args:
            callback: Optional function called when each step completes.
                     Useful for real-time streaming to UI.
        """
        self.steps: list[ReasoningStep] = []
        self.start_time = time.time()
        self.callback = callback
        self._current_step: Optional[ReasoningStep] = None
    
    def add_step(
        self,
        step_type: ReasoningStepType,
        title: str,
        details: dict = None,
    ) -> ReasoningStep:
        """Add a completed step."""
        step = ReasoningStep(
            step_type=step_type,
            title=title,
            status="complete",
            details=details or {},
        )
        self.steps.append(step)
        
        if self.callback:
            self.callback(step)
        
        return step
    
    def start_step(
        self,
        step_type: ReasoningStepType,
        title: str,
    ) -> ReasoningStep:
        """Start a new step (in progress)."""
        step = ReasoningStep(
            step_type=step_type,
            title=title,
            status="in_progress",
        )
        self._current_step = step
        self._step_start_time = time.time()
        self.steps.append(step)
        
        if self.callback:
            self.callback(step)
        
        return step
    
    def complete_step(self, details: dict = None, error: str = None):
        """Complete the current step."""
        if self._current_step:
            self._current_step.duration_ms = (time.time() - self._step_start_time) * 1000
            
            if error:
                self._current_step.status = "error"
                self._current_step.details["error"] = error
            else:
                self._current_step.status = "complete"
            
            if details:
                self._current_step.details.update(details)
            
            if self.callback:
                self.callback(self._current_step)
            
            self._current_step = None
    
    def format_cli(self) -> str:
        """Format all steps for CLI display."""
        if not self.steps:
            return ""
        
        lines = [
            "",
            "🔍 REASONING PROCESS",
            "─" * 50,
        ]
        
        for i, step in enumerate(self.steps, 1):
            lines.append(f"\nStep {i}: {step.format_cli()}")
        
        # Add total time
        total_time = time.time() - self.start_time
        lines.append("")
        lines.append(f"Total reasoning time: {total_time:.2f}s")
        lines.append("─" * 50)
        
        return "\n".join(lines)
    
    def to_dict(self) -> dict:
        """Convert trace to dictionary."""
        return {
            "steps": [step.to_dict() for step in self.steps],
            "total_time_ms": (time.time() - self.start_time) * 1000,
        }
    
    def get_confidence_score(self) -> float:
        """
        Calculate overall confidence based on RAG match scores.
        Higher scores = more confident the answer is grounded.
        """
        scores = []
        
        for step in self.steps:
            if step.step_type == ReasoningStepType.RAG_RETRIEVAL:
                for rag in step.details.get("rag_results", []):
                    if isinstance(rag, dict) and rag.get("top_score"):
                        scores.append(rag["top_score"])
        
        if not scores:
            return 0.5  # Default confidence
        
        return sum(scores) / len(scores)
