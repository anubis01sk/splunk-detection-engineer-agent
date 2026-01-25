"""
API Data Models
===============

Pydantic models for API request/response validation.
"""

from typing import Optional, List
from pydantic import BaseModel, Field

# Import QueryStatus from agent models to avoid duplicate enum definitions
from src.agent.models import QueryStatus


# =============================================================================
# REQUEST MODELS
# =============================================================================

class QueryRequest(BaseModel):
    """Request model for query generation."""
    input: str = Field(..., description="User input (natural language, log source, or IOC URL)")
    show_reasoning: bool = Field(default=False, description="Show Chain of Thought reasoning")
    options: Optional[dict] = Field(default=None, description="Optional parameters")
    
    class Config:
        json_schema_extra = {
            "example": {
                "input": "Detect brute force login attempts",
                "show_reasoning": True,
                "options": {}
            }
        }


class ConfigUpdateRequest(BaseModel):
    """Request model for configuration updates."""
    llm_provider: Optional[str] = Field(default=None, description="LLM provider name")
    llm_api_key: Optional[str] = Field(default=None, description="LLM API key")
    llm_model: Optional[str] = Field(default=None, description="LLM model name")
    splunk_host: Optional[str] = Field(default=None, description="Splunk host")
    splunk_port: Optional[int] = Field(default=None, description="Splunk port")
    splunk_token: Optional[str] = Field(default=None, description="Splunk auth token")
    splunk_username: Optional[str] = Field(default=None, description="Splunk username")
    splunk_password: Optional[str] = Field(default=None, description="Splunk password")
    splunk_verify_ssl: Optional[bool] = Field(default=None, description="Verify SSL")


class SearchRequest(BaseModel):
    """Request model for RAG search."""
    query: str = Field(..., description="Search query")
    top_k: int = Field(default=5, description="Number of results")
    rag_type: str = Field(default="all", description="RAG type: spl_docs, detections, cim, attack_data, all")


# =============================================================================
# RESPONSE MODELS
# =============================================================================

# QueryStatus is imported from src.agent.models to avoid duplicate definitions


class ReasoningStep(BaseModel):
    """Single step in reasoning trace."""
    step_type: str
    title: str
    status: str
    details: dict = {}
    timestamp: str = ""
    duration_ms: float = 0


class ReasoningTrace(BaseModel):
    """Full reasoning trace."""
    steps: List[ReasoningStep] = []
    total_time_ms: float = 0


class QueryResponse(BaseModel):
    """Response model for query generation."""
    status: QueryStatus
    spl_query: str
    explanation: str
    input_type: str
    iterations: int
    total_time: float
    validated: bool
    result_count: int
    fields_discovered: List[str] = []
    ioc_summary: str = ""
    warnings: List[str] = []
    errors: List[str] = []
    # Chain of Thought fields
    reasoning: Optional[dict] = Field(default=None, description="Reasoning trace for Chain of Thought")
    confidence_score: Optional[float] = Field(default=None, description="Confidence score based on RAG matches")
    # Grounding validation result
    grounding: Optional[dict] = Field(default=None, description="Grounding validation result")
    # Token usage for this query
    token_usage: Optional[dict] = Field(default=None, description="Token usage for this query")


class HealthResponse(BaseModel):
    """Response model for health check."""
    status: str
    version: str
    components: dict


class TokenUsage(BaseModel):
    """Token usage statistics."""
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_tokens: int = 0
    request_count: int = 0


class StatusResponse(BaseModel):
    """Response model for agent status."""
    llm_provider: Optional[str]
    splunk_connected: bool
    doc_rag_documents: int
    detection_rag_documents: int
    cim_rag_documents: int = 0
    attack_data_documents: int = 0
    token_usage: Optional[TokenUsage] = None


class ConfigResponse(BaseModel):
    """Response model for configuration."""
    llm_provider: Optional[str]
    llm_model: Optional[str]
    splunk_host: Optional[str]
    splunk_port: Optional[int]
    splunk_verify_ssl: bool = True
    has_splunk_credentials: bool = False
    has_llm_api_key: bool = False


class RAGSearchResult(BaseModel):
    """Single RAG search result."""
    id: str
    content: str
    score: float
    source: str
    metadata: dict = {}


class RAGSearchResponse(BaseModel):
    """Response model for RAG search."""
    results: List[RAGSearchResult]
    total: int
    query: str
