"""
Query Validation
================

Query validation and iterative refinement logic for the Splunk Agent.

Includes SPL linting to catch common syntax errors before Splunk validation.
"""

import logging
import re
from typing import TYPE_CHECKING, Optional, Tuple, List

from src.agent.models import AgentResult, QueryStatus
from src.agent.prompts import DIRECTIVE_SPL_SYNTAX, REFINEMENT_PROMPT
from src.agent.reasoning import ReasoningTrace, ReasoningStepType

if TYPE_CHECKING:
    from src.agent.orchestrator import SplunkAgent
    from src.input_processor import ProcessedInput

logger = logging.getLogger(__name__)


# =============================================================================
# SPL LINTING - Catch common errors before Splunk validation
# =============================================================================

class SPLLintIssue:
    """Represents an SPL syntax issue found during linting."""
    
    def __init__(self, severity: str, message: str, line: int = 0, fix: str = None):
        self.severity = severity  # "error", "warning", "info"
        self.message = message
        self.line = line
        self.fix = fix  # Suggested fix or auto-fixed query segment


def lint_spl_query(query: str) -> Tuple[str, List[SPLLintIssue]]:
    """
    Lint an SPL query for common syntax errors and auto-fix when possible.
    
    Args:
        query: The SPL query to lint
        
    Returns:
        Tuple of (cleaned_query, list_of_issues)
    """
    issues = []
    cleaned_lines = []
    lines = query.split('\n')
    
    for i, line in enumerate(lines, 1):
        original_line = line
        stripped = line.strip()
        
        # Skip empty lines
        if not stripped:
            cleaned_lines.append(line)
            continue
        
        # =================================================================
        # RULE 1: Remove hash comments (SPL doesn't support #)
        # =================================================================
        if stripped.startswith('#'):
            # Check if it looks like actual SPL that accidentally starts with #
            if any(kw in stripped.lower() for kw in ['index=', 'sourcetype=', '| ', 'eval ', 'stats ', 'where ', 'search ']):
                # It's SPL with a leading #, remove the #
                line = line.lstrip('#').lstrip()
                issues.append(SPLLintIssue(
                    "warning", 
                    f"Line {i}: Removed leading '#' (SPL doesn't support hash comments)",
                    i,
                    line
                ))
            else:
                # It's a pure comment line, skip it entirely
                issues.append(SPLLintIssue(
                    "info", 
                    f"Line {i}: Removed comment line (SPL doesn't support hash comments)",
                    i
                ))
                continue
        
        # Check for inline # comments
        if '#' in line and not line.strip().startswith('|'):
            # Could be inline comment - check if it's after SPL content
            hash_pos = line.find('#')
            before_hash = line[:hash_pos].strip()
            if before_hash and any(kw in before_hash.lower() for kw in ['|', 'by', 'as', '=', '>', '<']):
                line = line[:hash_pos].rstrip()
                issues.append(SPLLintIssue(
                    "warning",
                    f"Line {i}: Removed inline comment",
                    i,
                    line
                ))
        
        # =================================================================
        # RULE 2: Check for invalid tstats FROM syntax
        # =================================================================
        tstats_from_match = re.search(r'\|\s*tstats\s+.*?\s+from\s+(?!datamodel=)(\w+)', line, re.IGNORECASE)
        if tstats_from_match:
            invalid_from = tstats_from_match.group(1)
            if invalid_from.lower() not in ['datamodel']:
                issues.append(SPLLintIssue(
                    "error",
                    f"Line {i}: Invalid tstats syntax 'from {invalid_from}'. tstats FROM clause requires 'datamodel=Model.Dataset'. Use 'WHERE index={invalid_from}' for index filtering, or use regular search instead.",
                    i
                ))
        
        # =================================================================
        # RULE 3: Check for non-indexed fields in tstats without datamodel
        # =================================================================
        if re.search(r'\|\s*tstats\s+', line, re.IGNORECASE):
            has_datamodel = 'datamodel=' in line.lower()
            if not has_datamodel:
                # Check for non-indexed fields
                non_indexed_fields = re.findall(r'\bby\s+([\w,\s]+?)(?:\s*\||\s*$)', line, re.IGNORECASE)
                if non_indexed_fields:
                    fields_str = non_indexed_fields[0]
                    indexed_fields = {'host', 'source', 'sourcetype', 'index', '_time', 'splunk_server'}
                    for field in re.split(r'[,\s]+', fields_str):
                        field_clean = field.strip().lower()
                        if field_clean and field_clean not in indexed_fields:
                            issues.append(SPLLintIssue(
                                "error",
                                f"Line {i}: Field '{field}' is not an indexed field. tstats without datamodel can only access: {', '.join(sorted(indexed_fields))}. Consider using a regular search or specify a data model.",
                                i
                            ))
                            break
        
        # =================================================================
        # RULE 4: Check for backtick macros
        # =================================================================
        macro_match = re.search(r'`(\w+)`', line)
        if macro_match:
            macro_name = macro_match.group(1)
            issues.append(SPLLintIssue(
                "error",
                f"Line {i}: Macro `{macro_name}` detected. Macros require Enterprise Security or custom apps. Use raw SPL instead.",
                i
            ))
        
        # =================================================================
        # RULE 5: Warn about Account_Name without mvindex
        # =================================================================
        if 'account_name' in line.lower() and 'mvindex' not in line.lower():
            if 'eventcode=4625' in query.lower() or 'eventcode=4624' in query.lower():
                issues.append(SPLLintIssue(
                    "warning",
                    f"Line {i}: Account_Name is multi-valued in Windows auth events. Consider using mvindex(Account_Name, 1) for target user.",
                    i
                ))
        
        cleaned_lines.append(line)
    
    cleaned_query = '\n'.join(cleaned_lines).strip()
    
    # =================================================================
    # POST-PROCESSING: Fix query-level issues
    # =================================================================
    
    # RULE 6: Query cannot start with parenthesis - add 'search' command
    if cleaned_query.startswith('('):
        issues.append(SPLLintIssue(
            "warning",
            "Query starts with '(' which is invalid SPL. Added 'search' command prefix.",
            1,
            "search " + cleaned_query
        ))
        cleaned_query = "search " + cleaned_query
    
    # RULE 7: Remove empty IN clauses like IN ("") or IN ("", "")
    empty_in_pattern = r'\s*(?:OR\s+)?(?:\w+\.?)?\w+\s+IN\s*\(\s*(?:""\s*,?\s*)*\)'
    if re.search(empty_in_pattern, cleaned_query, re.IGNORECASE):
        cleaned_query = re.sub(empty_in_pattern, '', cleaned_query, flags=re.IGNORECASE)
        issues.append(SPLLintIssue(
            "warning",
            "Removed empty IN clauses (no IOC values provided)",
            0
        ))
    
    # RULE 8: Remove orphaned OR operators
    cleaned_query = re.sub(r'\(\s*OR\s+', '(', cleaned_query)  # (OR ... -> (...
    cleaned_query = re.sub(r'\s+OR\s*\)', ')', cleaned_query)  # ... OR) -> ...)
    cleaned_query = re.sub(r'\s+OR\s+OR\s+', ' OR ', cleaned_query)  # OR OR -> OR
    cleaned_query = re.sub(r'\|\s*search\s+\|', '|', cleaned_query)  # | search | -> |
    
    # Final cleanup - remove any remaining empty line artifacts
    cleaned_query = re.sub(r'\n{3,}', '\n\n', cleaned_query)
    
    return cleaned_query, issues


def format_lint_issues(issues: List[SPLLintIssue]) -> str:
    """Format lint issues into a readable string for feedback."""
    if not issues:
        return ""
    
    lines = ["SPL Syntax Issues Detected:"]
    for issue in issues:
        prefix = "❌" if issue.severity == "error" else "⚠️" if issue.severity == "warning" else "ℹ️"
        lines.append(f"  {prefix} {issue.message}")
    
    return "\n".join(lines)


def validate_query(agent: "SplunkAgent", spl_query: str, auto_lint: bool = True) -> dict:
    """
    Validate SPL query against Splunk, with optional pre-validation linting.
    
    Args:
        agent: The SplunkAgent instance with Splunk client
        spl_query: The SPL query to validate
        auto_lint: If True, lint and auto-fix query before validation
        
    Returns:
        Dictionary with validation results including lint issues
    """
    result = {
        "success": False,
        "lint_issues": [],
        "original_query": spl_query,
    }
    
    # Step 1: Lint the query
    if auto_lint:
        cleaned_query, lint_issues = lint_spl_query(spl_query)
        result["lint_issues"] = lint_issues
        result["cleaned_query"] = cleaned_query
        
        # Check for critical lint errors
        critical_errors = [i for i in lint_issues if i.severity == "error"]
        if critical_errors:
            result["error"] = format_lint_issues(critical_errors)
            result["lint_errors"] = True
            logger.warning(f"SPL lint found {len(critical_errors)} critical errors")
            return result
        
        # Use cleaned query for validation
        spl_query = cleaned_query
    
    # Step 2: Validate against Splunk
    if not agent.splunk or not agent._splunk_connected:
        result["error"] = "Splunk not connected"
        return result
    
    try:
        splunk_result = agent.splunk.test_query(
            search=spl_query,
            earliest_time=agent.config.validation_time_range,
            max_results=agent.config.validation_max_results,
        )
        result.update(splunk_result)
        return result
    except Exception as e:
        result["error"] = str(e)
        return result


def build_validation_feedback(validation: dict) -> str:
    """
    Build feedback string from validation result.
    
    Args:
        validation: Dictionary containing validation results
        
    Returns:
        Formatted feedback string
    """
    parts = []
    
    # Include lint issues first (most important)
    lint_issues = validation.get("lint_issues", [])
    if lint_issues:
        parts.append("SPL SYNTAX ISSUES FOUND:")
        for issue in lint_issues:
            prefix = "ERROR" if issue.severity == "error" else "WARNING" if issue.severity == "warning" else "INFO"
            parts.append(f"  [{prefix}] {issue.message}")
        parts.append("")
    
    if validation.get("lint_errors"):
        parts.append("CRITICAL: The query has syntax errors that must be fixed before it can run.")
        parts.append("Common fixes:")
        parts.append("  - Remove all # comments (SPL doesn't support hash comments)")
        parts.append("  - Don't use 'tstats from <index_name>' - use 'tstats WHERE index=<name>' or datamodel=")
        parts.append("  - tstats can only access indexed fields (host, source, sourcetype) without a data model")
        parts.append("  - Use regular 'index=X | stats ...' instead of tstats for non-indexed fields")
        parts.append("")
    
    if validation.get("error") and not validation.get("lint_errors"):
        parts.append(f"Error: {validation['error']}")
        
        # Add specific guidance for common errors
        error_lower = validation['error'].lower()
        if "macro" in error_lower or "backtick" in error_lower:
            parts.append("\nIMPORTANT: Remove all macros (backtick syntax). Use raw SPL only.")
        if "unknown search command" in error_lower:
            parts.append("\nUse only standard SPL commands. Avoid custom commands that require apps.")
    
    if validation.get("result_count") == 0 and validation.get("success"):
        parts.append("The query ran but returned no results. Consider:")
        parts.append("  - Broadening the search criteria")
        parts.append("  - Checking if the index/sourcetype exists")
        parts.append("  - Adjusting the time range (add earliest=-24h or earliest=0)")
        parts.append("  - Using index=* to search all indexes")
        parts.append("  - Verifying field names match your data")
    
    if validation.get("messages"):
        for msg in validation["messages"]:
            parts.append(f"Splunk message: {msg.get('text', msg)}")
    
    if validation.get("fields"):
        parts.append(f"Available fields in results: {', '.join(validation['fields'][:10])}")
    
    return "\n".join(parts) if parts else "No specific feedback available"


def iterative_refinement(
    agent: "SplunkAgent",
    result: AgentResult,
    processed_input: "ProcessedInput",
    context_section: str,
    reasoning_trace: Optional[ReasoningTrace] = None,
) -> AgentResult:
    """
    Iteratively refine the query based on validation feedback.
    
    Args:
        agent: The SplunkAgent instance
        result: Current AgentResult with the query to refine
        processed_input: The processed user input
        context_section: Context from RAG systems
        reasoning_trace: Optional trace for Chain of Thought display
        
    Returns:
        Updated AgentResult with refined query
    """
    trace = reasoning_trace or result.reasoning_trace
    current_query = result.spl_query
    
    for iteration in range(2, agent.config.max_iterations + 1):
        logger.info(f"Step {3 + iteration}: Validation iteration {iteration}...")
        
        # Track validation step
        if trace:
            trace.start_step(
                ReasoningStepType.VALIDATION,
                f"Validating query (iteration {iteration})"
            )
        
        # Validate current query
        validation = validate_query(agent, current_query)
        
        # Record iteration
        result.iteration_history.append({
            "iteration": iteration,
            "query": current_query,
            "validation": validation,
        })
        
        if validation.get("success"):
            result.validated = True
            result.result_count = validation.get("result_count", 0)
            result.status = QueryStatus.SUCCESS
            
            # Extract fields from results
            if validation.get("fields"):
                result.fields_discovered = validation["fields"][:20]
            
            logger.info(f"Query validated successfully with {result.result_count} results")
            
            if trace:
                trace.complete_step({
                    "validated": True,
                    "result_count": result.result_count,
                    "fields_found": len(result.fields_discovered),
                })
            break
        
        # Query failed - attempt refinement
        issue = validation.get("error", "Query returned no results")
        feedback = build_validation_feedback(validation)
        
        if trace:
            trace.complete_step({
                "validated": False,
                "error": issue[:100],
            })
        
        logger.info(f"Refining query due to: {issue[:100]}...")
        
        # Track refinement step
        if trace:
            trace.start_step(
                ReasoningStepType.REFINEMENT,
                f"Refining query based on feedback"
            )
        
        # Build previous attempts summary
        previous_attempts = ""
        if len(result.iteration_history) > 1:
            attempts = []
            for hist in result.iteration_history[:-1]:
                attempts.append(f"- Iteration {hist['iteration']}: {hist['validation'].get('error', 'No error')[:80]}")
            previous_attempts = "\n".join(attempts)
        
        # Generate refined query
        prompt = REFINEMENT_PROMPT.format(
            directive_spl_syntax=DIRECTIVE_SPL_SYNTAX,
            user_request=processed_input.original_input,
            previous_query=current_query,
            issue=issue,
            feedback=feedback,
            context_section=context_section,
            iteration_number=iteration,
            max_iterations=max_iterations,
            previous_attempts=previous_attempts or "None",
        )
        
        response = agent.llm.generate(prompt)
        agent.track_tokens(response)  # Track token usage
        new_query, new_explanation = parse_llm_response(response.content)
        
        if new_query and new_query != current_query:
            current_query = new_query
            result.spl_query = new_query
            result.explanation = new_explanation
            result.iterations = iteration
            
            if trace:
                trace.complete_step({
                    "iteration": iteration,
                    "reason": issue[:50],
                    "query_preview": new_query[:80],
                })
        else:
            logger.warning("Refinement did not produce a new query")
            result.warnings.append(f"Iteration {iteration}: Refinement failed")
            
            if trace:
                trace.complete_step(error="Refinement failed to produce new query")
            break
    
    if not result.validated:
        result.warnings.append(f"Query could not be fully validated after {result.iterations} iterations")
    
    return result


def parse_llm_response(response: str) -> tuple[str, str]:
    """
    Parse LLM response to extract SPL query and explanation.
    
    Applies SPL linting to clean up common syntax errors.
    
    Args:
        response: Raw LLM response text
        
    Returns:
        Tuple of (spl_query, explanation)
    """
    spl_query = ""
    explanation = ""
    
    # Look for ```spl or ```splunk code blocks
    spl_pattern = r'```(?:spl|splunk)?\s*\n(.*?)\n```'
    matches = re.findall(spl_pattern, response, re.DOTALL | re.IGNORECASE)
    
    if matches:
        spl_query = matches[0].strip()
    else:
        # Try generic code block
        code_pattern = r'```\s*\n(.*?)\n```'
        matches = re.findall(code_pattern, response, re.DOTALL)
        if matches:
            # Take the first code block that looks like SPL
            for match in matches:
                if any(kw in match.lower() for kw in ['index=', 'sourcetype=', '| stats', '| search', '| where', 'tstats']):
                    spl_query = match.strip()
                    break
            if not spl_query and matches:
                spl_query = matches[0].strip()
    
    # Apply SPL linting to clean up the query
    if spl_query:
        cleaned_query, lint_issues = lint_spl_query(spl_query)
        
        # Log lint issues for debugging
        if lint_issues:
            for issue in lint_issues:
                if issue.severity == "error":
                    logger.warning(f"SPL Lint Error: {issue.message}")
                elif issue.severity == "warning":
                    logger.info(f"SPL Lint Warning: {issue.message}")
        
        spl_query = cleaned_query
    
    # Extract explanation
    explanation_patterns = [
        r'###?\s*Explanation\s*\n(.*?)(?=###|\Z)',
        r'\*\*Explanation\*\*:?\s*(.*?)(?=\*\*|\Z)',
        r'Explanation:?\s*\n(.*?)(?=###|\Z)',
    ]
    
    for pattern in explanation_patterns:
        match = re.search(pattern, response, re.DOTALL | re.IGNORECASE)
        if match:
            explanation = match.group(1).strip()
            break
    
    # Fallback: use everything after the code block
    if not explanation and spl_query:
        parts = response.split('```')
        if len(parts) > 2:
            explanation = parts[-1].strip()
            # Clean up any markdown headers
            explanation = re.sub(r'^#+\s*.*$', '', explanation, flags=re.MULTILINE).strip()
    
    return spl_query, explanation
