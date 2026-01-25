"""
Splunk Agent Orchestrator
=========================

Main orchestrator that combines all components into an intelligent workflow
for generating production-ready SPL queries.

Workflow:
    1. Input Processing - Parse and classify the input trigger
    2. Context Retrieval - Query both RAG collections for relevant documentation
    3. Initial Query Generation - Use LLM to generate candidate SPL query
    4. Metadata Discovery - Query Splunk API to verify indexes/sourcetypes/fields
    5. Query Validation - Execute query against Splunk (limited time range)
    6. Result Analysis - Use fieldsummary and result inspection
    7. Iterative Refinement - Loop back with feedback if needed
    8. Optimization - Apply SPL best practices
    9. Output - Return final query with documentation
"""

import logging
import time
from pathlib import Path
from typing import Optional, Callable

from src.llm_provider import get_provider, LLMProvider
from src.splunk_client import SplunkClient
from src.rag_spl_docs import SplunkRAG
from src.rag_detections import DetectionRAG
from src.rag_cim_docs import CIMRAG
from src.rag_attack_data import AttackDataRAG
from src.input_processor import InputProcessor, InputType

from src.agent.config import AgentConfig, DEFAULT_CONFIG_PATH
from src.agent.models import AgentResult
from src.agent.reasoning import ReasoningTrace, ReasoningStepType, ReasoningStep
from src.agent.handlers import (
    handle_natural_language,
    handle_log_source,
    handle_ioc_report,
)

logger = logging.getLogger(__name__)


class SplunkAgent:
    """
    Main agent orchestrator for SPL query generation.
    
    Combines LLM reasoning, RAG context, and Splunk validation
    to generate production-ready SPL queries.
    
    Usage:
        from src.agent import SplunkAgent
        
        agent = SplunkAgent()
        
        # Natural language input
        result = agent.run("Detect brute force login attempts")
        
        # Log source input
        result = agent.run("index=windows sourcetype=WinEventLog:Security")
        
        # IOC report input
        result = agent.run("https://example.com/threat-report.pdf")
        
        # Access the generated query
        print(result.spl_query)
        print(result.explanation)
    """
    
    def __init__(
        self,
        config_path: Path = DEFAULT_CONFIG_PATH,
        llm_provider: Optional[LLMProvider] = None,
        splunk_client: Optional[SplunkClient] = None,
        doc_rag: Optional[SplunkRAG] = None,
        detection_rag: Optional[DetectionRAG] = None,
        cim_rag: Optional[CIMRAG] = None,
        attack_data_rag: Optional[AttackDataRAG] = None,
    ):
        """
        Initialize the Splunk Agent.
        
        Args:
            config_path: Path to configuration file
            llm_provider: Optional pre-configured LLM provider
            splunk_client: Optional pre-configured Splunk client
            doc_rag: Optional pre-configured documentation RAG
            detection_rag: Optional pre-configured detection RAG
            cim_rag: Optional pre-configured CIM data models RAG
            attack_data_rag: Optional pre-configured attack data RAG
        """
        self.config = AgentConfig.from_yaml(config_path)
        self.config_path = config_path
        
        # Initialize components (lazy loading)
        self._llm_provider = llm_provider
        self._splunk_client = splunk_client
        self._doc_rag = doc_rag
        self._detection_rag = detection_rag
        self._cim_rag = cim_rag
        self._attack_data_rag = attack_data_rag
        self._input_processor = InputProcessor()
        
        # Track Splunk connection status
        self._splunk_connected = None
        
        # Track token usage
        self._token_usage = {
            "total_input_tokens": 0,
            "total_output_tokens": 0,
            "total_tokens": 0,
            "request_count": 0,
        }
    
    @property
    def llm(self) -> LLMProvider:
        """Get or initialize LLM provider."""
        if self._llm_provider is None:
            self._llm_provider = get_provider(config_path=self.config_path)
            logger.info(f"Initialized LLM provider: {self._llm_provider.provider_name}")
        return self._llm_provider
    
    @property
    def splunk(self) -> Optional[SplunkClient]:
        """Get or initialize Splunk client."""
        if self._splunk_client is None and self.config.enable_splunk_validation:
            try:
                self._splunk_client = SplunkClient.from_config(self.config_path)
                # Test connection
                result = self._splunk_client.test_connection()
                self._splunk_connected = result.get("connected", False)
                if self._splunk_connected:
                    logger.info(f"Connected to Splunk: {result.get('server_name')} v{result.get('version')}")
                else:
                    logger.warning(f"Splunk connection failed: {result.get('error')}")
            except Exception as e:
                logger.warning(f"Could not initialize Splunk client: {e}")
                self._splunk_connected = False
        return self._splunk_client
    
    @property
    def doc_rag(self) -> Optional[SplunkRAG]:
        """Get or initialize documentation RAG."""
        if self._doc_rag is None:
            try:
                self._doc_rag = SplunkRAG()
                stats = self._doc_rag.get_stats()
                logger.info(f"Loaded documentation RAG: {stats.get('total_documents', 0)} documents")
            except Exception as e:
                logger.warning(f"Could not initialize documentation RAG: {e}")
        return self._doc_rag
    
    @property
    def detection_rag(self) -> Optional[DetectionRAG]:
        """Get or initialize detection RAG."""
        if self._detection_rag is None:
            try:
                self._detection_rag = DetectionRAG()
                stats = self._detection_rag.get_stats()
                logger.info(f"Loaded detection RAG: {stats.get('total_documents', 0)} detections")
            except Exception as e:
                logger.warning(f"Could not initialize detection RAG: {e}")
        return self._detection_rag
    
    @property
    def cim_rag(self) -> Optional[CIMRAG]:
        """Get or initialize CIM data models RAG."""
        if self._cim_rag is None:
            try:
                self._cim_rag = CIMRAG()
                stats = self._cim_rag.get_stats()
                logger.info(f"Loaded CIM RAG: {stats.get('total_documents', 0)} documents ({stats.get('unique_data_models', 0)} data models)")
            except Exception as e:
                logger.warning(f"Could not initialize CIM RAG: {e}")
        return self._cim_rag
    
    @property
    def attack_data_rag(self) -> Optional[AttackDataRAG]:
        """Get or initialize attack data RAG."""
        if self._attack_data_rag is None:
            try:
                self._attack_data_rag = AttackDataRAG()
                stats = self._attack_data_rag.get_stats()
                logger.info(f"Loaded Attack Data RAG: {stats.get('total_documents', 0)} datasets ({stats.get('unique_mitre_techniques', 0)} MITRE techniques)")
            except Exception as e:
                logger.warning(f"Could not initialize Attack Data RAG: {e}")
        return self._attack_data_rag
    
    # =========================================================================
    # MAIN ENTRY POINT
    # =========================================================================
    
    def run(
        self, 
        user_input: str,
        show_reasoning: bool = False,
        reasoning_callback: Optional[Callable[["ReasoningStep"], None]] = None,
    ) -> AgentResult:
        """
        Process user input and generate SPL query.
        
        Args:
            user_input: Natural language, log source spec, or IOC report
            show_reasoning: If True, track detailed reasoning steps
            reasoning_callback: Optional callback for real-time reasoning updates
            
        Returns:
            AgentResult with generated query and metadata
        """
        start_time = time.time()
        
        # Reset token counter for this run
        self.reset_token_usage()
        
        # Create reasoning trace if requested
        trace = ReasoningTrace(callback=reasoning_callback) if show_reasoning else None
        
        # Step 1: Process and classify input
        logger.info("Step 1: Processing input...")
        processed_input = self._input_processor.process(user_input)
        logger.info(f"Input type: {processed_input.input_type.value}")
        
        # Route to appropriate handler with reasoning trace
        if processed_input.input_type == InputType.LOG_SOURCE:
            result = handle_log_source(self, processed_input, reasoning_trace=trace)
        elif processed_input.input_type == InputType.IOC_REPORT:
            result = handle_ioc_report(self, processed_input, reasoning_trace=trace)
        else:
            result = handle_natural_language(self, processed_input, reasoning_trace=trace)
        
        result.total_time = time.time() - start_time
        result.input_type = processed_input.input_type
        
        # Capture token usage for this run
        usage = self.get_token_usage()
        result.token_usage = {
            "input_tokens": usage.get("total_input_tokens", 0),
            "output_tokens": usage.get("total_output_tokens", 0),
            "total_tokens": usage.get("total_tokens", 0),
            "request_count": usage.get("request_count", 0),
        }
        
        return result
    
    # =========================================================================
    # CONTEXT RETRIEVAL
    # =========================================================================
    
    def _get_documentation_context(self, query_text: str) -> str:
        """Retrieve relevant documentation context."""
        if not self.doc_rag:
            return ""
        
        try:
            # Use positional argument (not keyword) to match SplunkRAG method signature
            context = self.doc_rag.get_context_for_agent(
                query_text,
                top_k=self.config.context_top_k,
            )
            return context
        except Exception as e:
            logger.warning(f"Documentation context retrieval failed: {e}")
            return ""
    
    def _get_detection_context(self, query_text: str) -> str:
        """Retrieve relevant detection rule context."""
        if not self.detection_rag:
            return ""
        
        try:
            context = self.detection_rag.get_context_for_agent(
                query_text,
                top_k=self.config.context_top_k,
            )
            return context
        except Exception as e:
            logger.warning(f"Detection context retrieval failed: {e}")
            return ""
    
    def _get_cim_context(self, query_text: str) -> str:
        """Retrieve relevant CIM data model context."""
        if not self.cim_rag:
            return ""
        
        try:
            context = self.cim_rag.get_context_for_agent(
                query_text,
                top_k=3,  # Fewer CIM results, they're very specific
            )
            return context
        except Exception as e:
            logger.warning(f"CIM context retrieval failed: {e}")
            return ""
    
    def _build_context_section(self, doc_context: str, detection_context: str, cim_context: str = "") -> str:
        """Build context section for prompts."""
        parts = []
        
        if cim_context:
            parts.append("## CIM-Compliant Fields (Use These for Standardized Queries)")
            parts.append("The following fields are from Splunk's Common Information Model. Use these field names when possible for cross-sourcetype compatibility:")
            parts.append(cim_context)
        
        if doc_context:
            parts.append("## SPL Documentation Reference")
            parts.append(doc_context)
        
        if detection_context:
            parts.append("## Relevant Detection Rules (Reference Only - Do Not Copy Macros)")
            parts.append("Note: The detection rules below may contain macros. Extract only the logic, not the macro syntax.")
            parts.append(detection_context)
        
        return "\n\n".join(parts) if parts else ""
    
    # =========================================================================
    # UTILITY METHODS
    # =========================================================================
    
    def track_tokens(self, response) -> None:
        """Track token usage from an LLM response.
        
        Args:
            response: LLMResponse object with token usage info
        """
        if hasattr(response, 'input_tokens'):
            self._token_usage["total_input_tokens"] += response.input_tokens or 0
            self._token_usage["total_output_tokens"] += response.output_tokens or 0
            self._token_usage["total_tokens"] += response.total_tokens or 0
            self._token_usage["request_count"] += 1
    
    def get_token_usage(self) -> dict:
        """Get current session token usage."""
        return self._token_usage.copy()
    
    def reset_token_usage(self) -> None:
        """Reset token usage counters."""
        self._token_usage = {
            "total_input_tokens": 0,
            "total_output_tokens": 0,
            "total_tokens": 0,
            "request_count": 0,
        }
    
    def get_status(self, test_llm: bool = True) -> dict:
        """Get status of all agent components.
        
        Args:
            test_llm: If True, make a test API call to verify LLM connection
        """
        status = {
            "llm_provider": None,
            "llm_connected": False,
            "llm_error": None,
            "splunk_connected": False,
            "doc_rag_documents": 0,
            "detection_rag_documents": 0,
            "cim_rag_chunks": 0,
            "attack_data_rag_datasets": 0,
        }
        
        # Check LLM
        try:
            status["llm_provider"] = f"{self.llm.provider_name}/{self.llm.model_name}"
            
            # Test LLM connection with a minimal request
            if test_llm:
                test_response = self.llm.generate(
                    prompt="Reply with only: OK",
                    system_prompt="You are a test. Reply with exactly 'OK' and nothing else."
                )
                if test_response and test_response.content:
                    status["llm_connected"] = True
        except Exception as e:
            status["llm_error"] = str(e)
        
        # Check Splunk
        if self.splunk:
            status["splunk_connected"] = self._splunk_connected
        
        # Check RAG systems
        if self.doc_rag:
            try:
                stats = self.doc_rag.get_stats()
                status["doc_rag_documents"] = stats.get("total_documents", 0)
            except Exception:
                pass
        
        if self.detection_rag:
            try:
                stats = self.detection_rag.get_stats()
                status["detection_rag_documents"] = stats.get("total_documents", 0)
            except Exception:
                pass
        
        if self.cim_rag:
            try:
                stats = self.cim_rag.get_stats()
                status["cim_rag_chunks"] = stats.get("total_documents", 0)
            except Exception:
                pass
        
        if self.attack_data_rag:
            try:
                stats = self.attack_data_rag.get_stats()
                status["attack_data_rag_datasets"] = stats.get("total_documents", 0)
            except Exception:
                pass
        
        # Add token usage stats
        status["token_usage"] = self._token_usage.copy()
        
        return status
