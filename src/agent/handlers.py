"""
Input Type Handlers
===================

Handler functions for different input types (natural language, log source, IOC report).
"""

import logging
from typing import TYPE_CHECKING, Optional

from src.agent.models import AgentResult, QueryStatus
from src.agent.prompts import (
    DIRECTIVE_SPL_SYNTAX,
    QUERY_GENERATION_PROMPT,
    LOG_SOURCE_PROMPT,
    IOC_QUERY_PROMPT,
)
from src.agent.validation import iterative_refinement, parse_llm_response, validate_query
from src.agent.reasoning import ReasoningTrace, ReasoningStepType
from src.agent.grounding import validate_query_grounding

if TYPE_CHECKING:
    from src.agent.orchestrator import SplunkAgent
    from src.input_processor import ProcessedInput

logger = logging.getLogger(__name__)


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _check_input_quality(agent: "SplunkAgent", user_input: str, threshold: float = 0.40) -> tuple[bool, float, str]:
    """
    Check if user input has meaningful similarity to known security/SPL content.
    
    Uses multiple heuristics to detect gibberish or unclear requests:
    1. Length and character composition checks
    2. Known security keyword matching (partial/stem matching)
    3. Sentence structure analysis
    4. RAG similarity scores (must be above threshold)
    
    Args:
        agent: The SplunkAgent instance with RAG access
        user_input: The user's input text
        threshold: Minimum similarity score required (default 0.40)
        
    Returns:
        Tuple of (is_valid, best_score, best_source)
    """
    best_score = 0.0
    best_source = ""
    
    # Quick sanity checks
    text = user_input.strip().lower()
    if not text or len(text) < 5:
        return False, 0.0, ""
    
    # Check if input has too many repeated characters (gibberish pattern)
    if len(text) > 10:
        text_no_spaces = text.replace(" ", "")
        unique_chars = len(set(text_no_spaces))
        # Compare against length WITHOUT spaces (the actual character content)
        if unique_chars < len(text_no_spaces) * 0.20:  # Less than 20% unique chars is gibberish
            return False, 0.0, ""
    
    # Check if input looks like complete nonsense (random letter sequences)
    words = text.split()
    if len(words) >= 3:
        # Check if most "words" look like real English words (have vowels, reasonable length)
        vowels = set("aeiou")
        gibberish_words = 0
        for word in words:
            # A word is likely gibberish if:
            # - Too long without vowels
            # - Very short repeated patterns
            word_clean = ''.join(c for c in word if c.isalpha())
            if len(word_clean) > 3 and not any(v in word_clean for v in vowels):
                gibberish_words += 1
            elif len(word_clean) > 0 and len(set(word_clean)) == 1:  # All same letter
                gibberish_words += 1
        
        # If more than 60% of words look like gibberish, reject
        if gibberish_words / len(words) > 0.6:
            return False, 0.0, ""
    
    # Security/SPL keyword stems for partial matching
    security_stems = {
        # Action words
        "detect", "find", "search", "query", "monitor", "alert", "hunt", "identify",
        # Threats
        "attack", "threat", "malware", "exploit", "vulnerab", "brute", "suspicious", "anomal", "unusual", "malicious",
        # Authentication
        "login", "logon", "auth", "credential", "password", "access", "failed", "success", "attempt",
        # Network
        "network", "traffic", "connect", "firewall", "dns", "http", "port", "inbound", "outbound",
        # Process/Execution
        "process", "command", "powershell", "script", "execut", "file", "binary", "executable",
        # System
        "registry", "service", "user", "admin", "privileg", "escalat", "system",
        # Lateral movement
        "lateral", "movement", "exfiltrat", "beacon", "ransomware", "remote", "local",
        # Splunk/SPL specific
        "index", "sourcetype", "splunk", "spl", "stats", "eval", "table", "tstats", "datamodel",
        # CIM specific - IMPORTANT for CIM queries
        "cim", "model", "endpoint", "authenticat", "filesystem", "web", "email",
        # Platforms
        "windows", "linux", "sysmon", "eventcode", "security",
        # IOC types
        "ioc", "indicator", "hash", "domain", "url", "ip",
        # File operations
        "download", "upload", "create", "delete", "modify", "write", "read", "modif",
        # Memory/Tools
        "memory", "dump", "lsass", "mimikatz", "psexec", "wmi", "rdp",
        # Directories/paths
        "director", "folder", "path", "temp", "sensitiv",
    }
    
    # Count keyword matches using partial/stem matching
    # Split on dots and spaces to handle "Endpoint.Processes" style terms
    all_terms = []
    for word in words:
        # Split on dots for CIM data model paths like "Endpoint.Processes"
        all_terms.extend(word.split('.'))
    
    keyword_matches = 0
    matched_stems = set()  # Avoid double-counting same stem
    for term in all_terms:
        term_clean = ''.join(c for c in term if c.isalpha()).lower()
        if len(term_clean) >= 3:
            for stem in security_stems:
                if stem in term_clean or term_clean in stem:
                    if stem not in matched_stems:
                        keyword_matches += 1
                        matched_stems.add(stem)
                    break
    
    # If we have multiple security keywords, it's likely a valid request
    if keyword_matches >= 2:
        logger.debug(f"Input quality: accepted ({keyword_matches} keywords matched)")
        return True, 0.8, "keyword_match"
    
    # If we have at least one keyword and a reasonable sentence structure, accept
    if keyword_matches >= 1 and len(words) >= 3:
        # Check for sentence-like structure (has common words like "the", "from", "on", "in", etc.)
        common_words = {"the", "a", "an", "in", "on", "from", "to", "for", "with", "using", "by", "and", "or"}
        has_structure = any(w in common_words for w in words)
        if has_structure:
            return True, 0.7, "structured_query"
    
    # If no keywords at all and long text, likely gibberish
    if keyword_matches == 0 and len(text) > 15:
        # Check if it looks like a log source spec
        if not any(x in text for x in ["index=", "sourcetype=", "source=", "host="]):
            logger.debug("Input quality: rejected (no keywords, no log source spec)")
            return False, 0.0, ""
    
    # For borderline cases, query RAGs for similarity
    if agent.doc_rag:
        try:
            results = agent.doc_rag.query(user_input, top_k=1)
            if results and results[0].similarity > best_score:
                best_score = results[0].similarity
                best_source = "SPL Documentation"
        except Exception:
            pass
    
    # Query detection RAG
    if agent.detection_rag:
        try:
            results = agent.detection_rag.search(user_input, top_k=1)
            if results and hasattr(results[0], 'score') and results[0].score > best_score:
                best_score = results[0].score
                best_source = "Security Detections"
        except Exception:
            pass
    
    # Query CIM RAG with enhanced query
    if agent.cim_rag:
        try:
            enhanced = _enhance_cim_query(user_input)
            results = agent.cim_rag.search(enhanced, top_k=1)
            if results and hasattr(results[0], 'score') and results[0].score > best_score:
                best_score = results[0].score
                best_source = "CIM Data Models"
        except Exception:
            pass
    
    # If we have at least one keyword match, lower the threshold significantly
    effective_threshold = threshold - 0.15 if keyword_matches >= 1 else threshold
    
    is_valid = best_score >= effective_threshold
    if is_valid:
        logger.debug(f"Input quality: accepted via RAG ({best_source}, score={best_score:.2f})")
    else:
        logger.debug(f"Input quality: rejected (RAG score {best_score:.2f} < {effective_threshold:.2f})")
    return is_valid, best_score, best_source


def _enhance_cim_query(user_input: str) -> str:
    """
    Enhance user input to better match CIM data model documentation.
    
    CIM docs describe fields like "action", "user", "src" - they don't use phrases
    like "brute force". This function adds relevant CIM terminology based on the
    detected topic.
    
    Args:
        user_input: Original user input
        
    Returns:
        Enhanced query for CIM RAG search
    """
    input_lower = user_input.lower()
    
    # Authentication/Login related queries
    auth_keywords = ["login", "logon", "brute force", "password", "credential", 
                     "authentication", "failed login", "account", "lockout"]
    if any(kw in input_lower for kw in auth_keywords):
        return "authentication login user src dest action failure success app authentication_method"
    
    # Process execution related queries
    process_keywords = ["process", "execution", "command", "powershell", "cmd", 
                        "script", "binary", "executable", "malware"]
    if any(kw in input_lower for kw in process_keywords):
        return "endpoint processes process_name process user dest parent_process command_line"
    
    # Network related queries
    network_keywords = ["network", "traffic", "connection", "firewall", "dns", 
                        "http", "web", "port", "ip address", "packet"]
    if any(kw in input_lower for kw in network_keywords):
        return "network traffic src dest src_port dest_port bytes protocol action"
    
    # Email related queries
    email_keywords = ["email", "phishing", "attachment", "mail", "smtp", "sender"]
    if any(kw in input_lower for kw in email_keywords):
        return "email sender recipient subject attachment src_user file_name"
    
    # DNS related queries
    if "dns" in input_lower:
        return "dns query answer record_type src dest domain"
    
    # File/endpoint related queries
    file_keywords = ["file", "document", "download", "upload", "write", "create", "delete"]
    if any(kw in input_lower for kw in file_keywords):
        return "endpoint filesystem file_name file_path user dest action file_hash"
    
    # Web related queries
    web_keywords = ["web", "http", "url", "request", "response", "proxy"]
    if any(kw in input_lower for kw in web_keywords):
        return "web http_method url dest src status bytes_out user_agent"
    
    # Default: return original with some general security terms
    return f"{user_input} security event src dest user action"


# =============================================================================
# INPUT TYPE HANDLERS
# =============================================================================

def handle_natural_language(
    agent: "SplunkAgent",
    processed_input: "ProcessedInput",
    reasoning_trace: Optional[ReasoningTrace] = None,
) -> AgentResult:
    """
    Handle natural language detection requests.
    
    Args:
        agent: The SplunkAgent instance
        processed_input: Processed user input
        reasoning_trace: Optional trace for Chain of Thought display
        
    Returns:
        AgentResult with generated query
    """
    trace = reasoning_trace or ReasoningTrace()
    
    result = AgentResult(
        status=QueryStatus.FAILED,
        spl_query="",
        explanation="",
        reasoning_trace=trace,
    )
    
    # Step: Input Classification (already done, record it)
    trace.add_step(
        ReasoningStepType.INPUT_CLASSIFICATION,
        "Classified input as natural language detection request",
        {
            "input_type": processed_input.input_type.value,
            "entities": processed_input.entities[:5] if processed_input.entities else [],
        }
    )
    
    # Early check: Validate input quality to reject gibberish/unclear requests
    is_valid, quality_score, best_source = _check_input_quality(agent, processed_input.original_input)
    if not is_valid:
        trace.add_step(
            ReasoningStepType.COMPLETE,
            "Request rejected - unclear or invalid input",
            {"quality_score": quality_score, "threshold": 0.35}
        )
        result.status = QueryStatus.FAILED
        result.explanation = (
            "I couldn't understand your request. Please provide a clear description of what you want to detect or search for.\n\n"
            "**Examples of valid requests:**\n"
            "- \"Detect brute force login attempts\"\n"
            "- \"Find PowerShell commands downloading files\"\n"
            "- \"Search for failed SSH authentication\"\n"
            "- \"index=windows sourcetype=WinEventLog:Security\"\n\n"
            "Try rephrasing your request with specific security terms or log source details."
        )
        result.warnings.append("Input quality too low - request appears unclear or contains gibberish")
        return result
    
    # Step 2: Retrieve context
    logger.info("Step 2: Retrieving context...")
    trace.start_step(ReasoningStepType.RAG_RETRIEVAL, "Querying knowledge bases for context")
    
    rag_results = []
    
    # Query SPL documentation RAG
    doc_context = agent._get_documentation_context(processed_input.original_input)
    if doc_context:
        # Extract score from context if available
        rag_results.append({
            "source": "SPL Documentation",
            "query": processed_input.original_input[:50],
            "matches": doc_context.count("---"),
            "top_score": 0.7,  # Default estimate
        })
    
    # Query detection RAG
    detection_context = agent._get_detection_context(processed_input.original_input)
    if detection_context:
        rag_results.append({
            "source": "Security Detections",
            "query": processed_input.original_input[:50],
            "matches": detection_context.count("---"),
            "top_score": 0.8,
        })
    
    # Query CIM RAG with enhanced query for better matching
    cim_query = _enhance_cim_query(processed_input.original_input)
    cim_context = agent._get_cim_context(cim_query)
    if cim_context:
        rag_results.append({
            "source": "CIM Data Models",
            "query": cim_query[:50],
            "matches": max(cim_context.count("CIM Data Model:"), cim_context.count("CIM Fields:")),
            "top_score": 0.65,
        })
    
    trace.complete_step({"rag_results": rag_results})
    
    result.documentation_context = doc_context
    result.detection_context = detection_context
    result.cim_context = cim_context
    
    # Build context section for prompt
    context_section = agent._build_context_section(doc_context, detection_context, cim_context)
    
    # Track context building
    trace.add_step(
        ReasoningStepType.CONTEXT_BUILDING,
        "Built context for LLM prompt",
        {
            "doc_context_size": len(doc_context),
            "detection_context_size": len(detection_context),
            "cim_context_size": len(cim_context),
        }
    )
    
    # Build constraints section
    constraints_section = ""
    if processed_input.entities:
        constraints_section = f"## Extracted Entities\n{', '.join(processed_input.entities)}"
    
    # Detect if user explicitly wants CIM/datamodel approach
    input_lower = processed_input.original_input.lower()
    cim_keywords = ["cim", "data model", "datamodel", "tstats", "normalized", "common information model"]
    if any(kw in input_lower for kw in cim_keywords):
        constraints_section += """

## MANDATORY REQUIREMENT: USE CIM DATA MODEL WITH TSTATS

The user has EXPLICITLY requested a CIM/data model based query. You MUST:

1. Use `| tstats` command with `from datamodel=` syntax
2. Use data model field paths like `Authentication.user`, `Processes.process_name`
3. Include `| rename DataModel.* as *` to clean up field names
4. Do NOT use raw index/sourcetype - use the data model instead

Example for Authentication:
```spl
| tstats summariesonly=true count from datamodel=Authentication.Authentication 
    where nodename=Authentication.Failed_Authentication 
    by Authentication.src, Authentication.dest, Authentication.user, _time span=5m
| rename Authentication.* as *
| where count > 10
```

Example for Endpoint.Processes:
```spl
| tstats count from datamodel=Endpoint.Processes 
    where Processes.process_name="*powershell*"
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process, _time span=1h
| rename Processes.* as *
```

FAILURE TO USE TSTATS WITH DATAMODEL= WILL BE CONSIDERED INCORRECT.
"""
    
    # Step 3: Generate initial query
    logger.info("Step 3: Generating initial query...")
    trace.start_step(ReasoningStepType.QUERY_GENERATION, "Generating SPL query with LLM")
    
    prompt = QUERY_GENERATION_PROMPT.format(
        directive_spl_syntax=DIRECTIVE_SPL_SYNTAX,
        user_request=processed_input.original_input,
        input_type=processed_input.input_type.value,
        context_section=context_section,
        constraints_section=constraints_section,
    )
    
    response = agent.llm.generate(prompt)
    agent.track_tokens(response)  # Track token usage
    spl_query, explanation = parse_llm_response(response.content)
    
    if not spl_query:
        trace.complete_step(error="Failed to generate SPL query")
        result.errors.append("Failed to generate initial SPL query")
        return result
    
    trace.complete_step({
        "query_preview": spl_query[:100],
        "explanation_preview": explanation[:100] if explanation else "",
    })
    
    result.spl_query = spl_query
    result.explanation = explanation
    result.iterations = 1
    
    # Step 4-7: Iterative refinement with validation
    if agent.config.enable_splunk_validation and agent.splunk and agent._splunk_connected:
        result = iterative_refinement(
            agent,
            result,
            processed_input,
            context_section,
            reasoning_trace=trace,
        )
    else:
        result.status = QueryStatus.PARTIAL
        result.warnings.append("Splunk validation skipped (not connected)")
        trace.add_step(
            ReasoningStepType.VALIDATION,
            "Validation skipped",
            {"reason": "Splunk not connected"}
        )
    
    if result.status == QueryStatus.FAILED and result.spl_query:
        result.status = QueryStatus.PARTIAL
    
    # Grounding validation using RAGs (not hardcoded fields)
    if result.spl_query:
        grounding_result = validate_query_grounding(
            result.spl_query,
            rag_context=context_section,
            user_specified_fields=set(processed_input.original_input.split()),
            cim_rag=agent.cim_rag,
            detection_rag=agent.detection_rag,
        )
        result.grounding_result = grounding_result
        
        if not grounding_result.is_grounded:
            result.warnings.extend(grounding_result.warnings)
    
    # Mark complete
    trace.add_step(
        ReasoningStepType.COMPLETE,
        "Query generation complete",
        {
            "status": result.status.value,
            "iterations": result.iterations,
            "is_grounded": result.grounding_result.is_grounded if result.grounding_result else None,
        }
    )
    
    return result


def handle_log_source(
    agent: "SplunkAgent",
    processed_input: "ProcessedInput",
    reasoning_trace: Optional[ReasoningTrace] = None,
) -> AgentResult:
    """
    Handle log source specification requests.
    
    Args:
        agent: The SplunkAgent instance
        processed_input: Processed user input with log source info
        reasoning_trace: Optional trace for Chain of Thought display
        
    Returns:
        AgentResult with generated query
    """
    from src.agent.validation import validate_query
    
    trace = reasoning_trace or ReasoningTrace()
    
    result = AgentResult(
        status=QueryStatus.FAILED,
        spl_query="",
        explanation="",
        reasoning_trace=trace,
    )
    
    log_source = processed_input.log_source
    
    # Track input classification
    trace.add_step(
        ReasoningStepType.INPUT_CLASSIFICATION,
        "Classified input as log source exploration",
        {
            "input_type": "log_source",
            "index": log_source.index,
            "sourcetype": log_source.sourcetype,
        }
    )
    
    # Step 2: Discover available fields via Splunk API
    available_fields = []
    field_stats = ""
    
    if agent.config.enable_field_discovery and agent.splunk and agent._splunk_connected:
        logger.info("Step 2: Discovering fields from Splunk...")
        trace.start_step(ReasoningStepType.FIELD_SELECTION, "Discovering fields from Splunk")
        
        try:
            if log_source.index:
                fields = agent.splunk.get_fields(
                    index=log_source.index,
                    sourcetype=log_source.sourcetype,
                    earliest_time="-30d",
                )
                available_fields = [f["field"] for f in fields]
                
                # Build field stats summary
                top_fields = sorted(fields, key=lambda x: x.get("count", 0), reverse=True)[:15]
                field_stats = "\n".join(
                    f"  - {f['field']}: {f['count']} values, {f['distinct_count']} distinct"
                    for f in top_fields
                )
                
                result.fields_discovered = available_fields[:20]
                logger.info(f"Discovered {len(available_fields)} fields")
                
                trace.complete_step({
                    "discovered_fields": available_fields[:10],
                    "total_fields": len(available_fields),
                })
        except Exception as e:
            logger.warning(f"Field discovery failed: {e}")
            result.warnings.append(f"Field discovery failed: {e}")
            trace.complete_step(error=str(e))
    
    # Get context
    trace.start_step(ReasoningStepType.RAG_RETRIEVAL, "Querying knowledge bases for context")
    
    doc_context = agent._get_documentation_context(
        f"sourcetype {log_source.sourcetype or ''} {log_source.index or ''}"
    )
    detection_context = agent._get_detection_context(
        f"index={log_source.index} sourcetype={log_source.sourcetype}"
    )
    cim_context = agent._get_cim_context(
        f"sourcetype {log_source.sourcetype or ''} security events"
    )
    
    rag_results = []
    if doc_context:
        rag_results.append({"source": "SPL Documentation", "matches": doc_context.count("---"), "top_score": 0.7})
    if detection_context:
        rag_results.append({"source": "Security Detections", "matches": detection_context.count("---"), "top_score": 0.8})
    if cim_context:
        rag_results.append({"source": "CIM Data Models", "matches": max(cim_context.count("CIM Data Model:"), cim_context.count("CIM Fields:")), "top_score": 0.65})
    
    trace.complete_step({"rag_results": rag_results})
    
    context_section = agent._build_context_section(doc_context, detection_context, cim_context)
    
    # Build log source spec string
    log_source_spec = []
    if log_source.index:
        log_source_spec.append(f"index={log_source.index}")
    if log_source.sourcetype:
        log_source_spec.append(f"sourcetype={log_source.sourcetype}")
    if log_source.source:
        log_source_spec.append(f"source={log_source.source}")
    if log_source.host:
        log_source_spec.append(f"host={log_source.host}")
    
    # Generate query
    logger.info("Step 3: Generating query for log source...")
    trace.start_step(ReasoningStepType.QUERY_GENERATION, "Generating SPL query with LLM")
    
    prompt = LOG_SOURCE_PROMPT.format(
        directive_spl_syntax=DIRECTIVE_SPL_SYNTAX,
        log_source_spec=" ".join(log_source_spec),
        available_fields=", ".join(available_fields[:30]) if available_fields else "Not discovered",
        field_stats=field_stats if field_stats else "Not available",
        context_section=context_section,
    )
    
    response = agent.llm.generate(prompt)
    agent.track_tokens(response)  # Track token usage
    spl_query, explanation = parse_llm_response(response.content)
    
    trace.complete_step({
        "query_preview": spl_query[:100] if spl_query else "",
    })
    
    result.spl_query = spl_query
    result.explanation = explanation
    result.iterations = 1
    result.documentation_context = doc_context
    result.detection_context = detection_context
    result.cim_context = cim_context
    
    # Validate if possible
    if spl_query and agent.config.enable_splunk_validation and agent.splunk and agent._splunk_connected:
        trace.start_step(ReasoningStepType.VALIDATION, "Validating query against Splunk")
        
        validation = validate_query(agent, spl_query)
        result.validated = validation.get("success", False)
        result.result_count = validation.get("result_count", 0)
        
        if result.validated:
            result.status = QueryStatus.SUCCESS
            trace.complete_step({
                "validated": True,
                "result_count": result.result_count,
            })
        else:
            result.status = QueryStatus.PARTIAL
            if validation.get("error"):
                result.warnings.append(f"Validation: {validation.get('error')}")
            trace.complete_step({
                "validated": False,
                "error": validation.get("error", "Unknown error"),
            })
    else:
        result.status = QueryStatus.PARTIAL if spl_query else QueryStatus.FAILED
    
    # Grounding validation using RAGs (not hardcoded fields)
    if spl_query:
        grounding_result = validate_query_grounding(
            spl_query,
            rag_context=f"{doc_context}\n{detection_context}\n{cim_context}",
            user_specified_fields=set(processed_input.original_input.split()),
            cim_rag=agent.cim_rag,
            detection_rag=agent.detection_rag,
        )
        result.grounding_result = grounding_result
        
        if not grounding_result.is_grounded:
            result.warnings.extend(grounding_result.warnings)
    
    # Mark complete
    trace.add_step(
        ReasoningStepType.COMPLETE,
        "Query generation complete",
        {
            "status": result.status.value, 
            "iterations": result.iterations,
            "is_grounded": result.grounding_result.is_grounded if result.grounding_result else None,
        }
    )
    
    return result


def handle_ioc_report(
    agent: "SplunkAgent",
    processed_input: "ProcessedInput",
    reasoning_trace: Optional[ReasoningTrace] = None,
) -> AgentResult:
    """
    Handle IOC report input.
    
    Args:
        agent: The SplunkAgent instance
        processed_input: Processed user input with IOC data
        reasoning_trace: Optional trace for Chain of Thought display
        
    Returns:
        AgentResult with generated query
    """
    trace = reasoning_trace or ReasoningTrace()
    
    result = AgentResult(
        status=QueryStatus.FAILED,
        spl_query="",
        explanation="",
        reasoning_trace=trace,
    )
    
    # Track input classification
    trace.add_step(
        ReasoningStepType.INPUT_CLASSIFICATION,
        "Classified input as IOC report",
        {
            "input_type": "ioc_report",
            "report_title": processed_input.report_title or "Unknown",
            "ioc_count": len(processed_input.iocs) if processed_input.iocs else 0,
        }
    )
    
    # Check if IOCs were extracted
    if not processed_input.iocs:
        trace.add_step(
            ReasoningStepType.ERROR,
            "No IOCs extracted from report",
            {"error": "IOC extraction failed"}
        )
        result.errors.append("No IOCs extracted from report")
        return result
    
    # Build IOC summary
    ioc_by_type = {}
    for ioc in processed_input.iocs:
        type_name = ioc.ioc_type.value
        if type_name not in ioc_by_type:
            ioc_by_type[type_name] = []
        ioc_by_type[type_name].append(ioc)
    
    ioc_summary = f"Report: {processed_input.report_title}\n"
    ioc_summary += f"Total IOCs: {len(processed_input.iocs)}\n"
    for type_name, iocs in sorted(ioc_by_type.items()):
        ioc_summary += f"  - {type_name}: {len(iocs)}\n"
    
    result.ioc_summary = ioc_summary
    
    # Track IOC extraction results
    trace.add_step(
        ReasoningStepType.CONTEXT_BUILDING,
        "Extracted IOCs from report",
        {
            "total_iocs": len(processed_input.iocs),
            "ioc_types": {k: len(v) for k, v in ioc_by_type.items()},
            "ttps": processed_input.ttps[:5] if processed_input.ttps else [],
        }
    )
    
    # Build IOC list for prompt (limit to high confidence)
    high_conf_iocs = processed_input.get_high_confidence_iocs(0.6)
    ioc_list_parts = []
    for ioc_type, iocs in ioc_by_type.items():
        values = [ioc.value for ioc in iocs if ioc.confidence >= 0.6][:20]
        if values:
            ioc_list_parts.append(f"{ioc_type}:\n  " + "\n  ".join(values))
    
    ioc_list = "\n\n".join(ioc_list_parts)
    
    # Get context
    ttps_str = ", ".join(processed_input.ttps) if processed_input.ttps else "None identified"
    
    trace.start_step(ReasoningStepType.RAG_RETRIEVAL, "Querying knowledge bases for detection patterns")
    
    detection_context = ""
    rag_results = []
    
    if processed_input.ttps:
        # Get detection context for each TTP
        for ttp in processed_input.ttps[:3]:
            ctx = agent._get_detection_context(f"MITRE ATT&CK {ttp}")
            if ctx:
                detection_context += f"\n{ctx}"
                rag_results.append({
                    "source": f"Detections for {ttp}",
                    "matches": ctx.count("---"),
                    "top_score": 0.75,
                })
    
    # Get CIM context for IOC hunting
    cim_context = agent._get_cim_context("network traffic DNS web email indicators")
    if cim_context:
        rag_results.append({
            "source": "CIM Data Models",
            "matches": max(cim_context.count("CIM Data Model:"), cim_context.count("CIM Fields:")),
            "top_score": 0.65,
        })
    
    trace.complete_step({"rag_results": rag_results})
    
    context_section = agent._build_context_section("", detection_context, cim_context)
    
    # Generate IOC hunting query
    logger.info("Step 3: Generating IOC hunting query...")
    trace.start_step(ReasoningStepType.QUERY_GENERATION, "Generating IOC hunting query with LLM")
    
    prompt = IOC_QUERY_PROMPT.format(
        directive_spl_syntax=DIRECTIVE_SPL_SYNTAX,
        ioc_summary=ioc_summary,
        ioc_list=ioc_list,
        ttps=ttps_str,
        context_section=context_section,
    )
    
    response = agent.llm.generate(prompt)
    agent.track_tokens(response)  # Track token usage
    spl_query, explanation = parse_llm_response(response.content)
    
    trace.complete_step({
        "query_preview": spl_query[:100] if spl_query else "",
        "ioc_types_in_query": list(ioc_by_type.keys()),
    })
    
    result.spl_query = spl_query
    result.explanation = explanation
    result.iterations = 1
    result.detection_context = detection_context
    result.cim_context = cim_context
    
    if spl_query:
        result.status = QueryStatus.PARTIAL
        result.warnings.append("IOC queries should be reviewed before production use")
        
        # Grounding validation using RAGs (not hardcoded fields)
        grounding_result = validate_query_grounding(
            spl_query,
            rag_context=f"{detection_context}\n{cim_context}",
            user_specified_fields=set(processed_input.original_input.split()),
            cim_rag=agent.cim_rag,
            detection_rag=agent.detection_rag,
        )
        result.grounding_result = grounding_result
        
        if not grounding_result.is_grounded:
            result.warnings.extend(grounding_result.warnings)
    
    # Mark complete
    trace.add_step(
        ReasoningStepType.COMPLETE,
        "IOC hunting query generation complete",
        {
            "status": result.status.value, 
            "ioc_count": len(processed_input.iocs),
            "is_grounded": result.grounding_result.is_grounded if result.grounding_result else None,
        }
    )
    
    return result
