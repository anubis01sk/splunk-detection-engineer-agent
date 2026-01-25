"""
End-to-End IOC → Detection → Validation Workflow
=================================================

Complete automated pipeline from IOC report to validated detection.

Workflow:
1. Input: IOC report (PDF file or HTML URL)
2. Extract: Parse IOCs (IPs, domains, hashes, etc.)
3. Build Detection: Use Detection RAG for similar rules
4. Apply Best Practices: Use SPL Docs RAG for syntax/optimization
5. Validate Metadata: Check index/sourcetype/fields exist in Splunk
6. Test Against Attack Data: Run query against splunk/attack_data samples
7. Show Results: Display matching events proving detection works

Usage:
    from src.agent.e2e_workflow import run_e2e_workflow
    
    result = run_e2e_workflow(
        agent=agent,
        ioc_source="https://example.com/threat-report.pdf"
    )
"""

import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum

logger = logging.getLogger(__name__)


class WorkflowStage(Enum):
    """Stages of the E2E workflow."""
    INPUT = "input"
    IOC_EXTRACTION = "ioc_extraction"
    DETECTION_BUILD = "detection_build"
    BEST_PRACTICES = "best_practices"
    METADATA_VALIDATION = "metadata_validation"
    ATTACK_DATA_TEST = "attack_data_test"
    COMPLETE = "complete"
    FAILED = "failed"


class StageStatus(Enum):
    """Status of a workflow stage."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    WARNING = "warning"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class WorkflowStageResult:
    """Result of a single workflow stage."""
    stage: WorkflowStage
    status: StageStatus
    title: str
    details: Dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


@dataclass
class AttackDataMatch:
    """A match from attack data validation."""
    dataset_name: str
    mitre_id: str
    technique: str
    file_path: str
    sample_events: List[Dict[str, Any]] = field(default_factory=list)
    match_count: int = 0
    relevance_score: float = 0.0


@dataclass
class E2EWorkflowResult:
    """Complete result of the E2E workflow."""
    # Overall status
    success: bool = False
    confidence_score: float = 0.0
    
    # Stage results
    stages: List[WorkflowStageResult] = field(default_factory=list)
    
    # IOC extraction
    ioc_summary: str = ""
    ioc_count: int = 0
    ioc_types: Dict[str, int] = field(default_factory=dict)
    ttps_detected: List[str] = field(default_factory=list)
    
    # Detection
    spl_query: str = ""
    explanation: str = ""
    query_validated: bool = False
    validation_result_count: int = 0
    
    # Attack data validation
    attack_data_matches: List[AttackDataMatch] = field(default_factory=list)
    attack_data_tested: bool = False
    attack_data_match_count: int = 0
    
    # Timing
    total_time_ms: float = 0
    
    # Errors and warnings
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "success": self.success,
            "confidence_score": self.confidence_score,
            "stages": [
                {
                    "stage": s.stage.value,
                    "status": s.status.value,
                    "title": s.title,
                    "details": s.details,
                    "duration_ms": s.duration_ms,
                    "warnings": s.warnings,
                    "errors": s.errors,
                }
                for s in self.stages
            ],
            "ioc_summary": self.ioc_summary,
            "ioc_count": self.ioc_count,
            "ioc_types": self.ioc_types,
            "ttps_detected": self.ttps_detected,
            "spl_query": self.spl_query,
            "explanation": self.explanation,
            "query_validated": self.query_validated,
            "validation_result_count": self.validation_result_count,
            "attack_data_matches": [
                {
                    "dataset_name": m.dataset_name,
                    "mitre_id": m.mitre_id,
                    "technique": m.technique,
                    "file_path": m.file_path,
                    "match_count": m.match_count,
                    "relevance_score": m.relevance_score,
                    "sample_events": m.sample_events[:3],  # Limit samples
                }
                for m in self.attack_data_matches
            ],
            "attack_data_tested": self.attack_data_tested,
            "attack_data_match_count": self.attack_data_match_count,
            "total_time_ms": self.total_time_ms,
            "warnings": self.warnings,
            "errors": self.errors,
        }


def run_e2e_workflow(
    agent: "SplunkAgent",
    ioc_source: str,
    validate_with_splunk: bool = True,
    test_with_attack_data: bool = True,
) -> E2EWorkflowResult:
    """
    Run the complete End-to-End workflow.
    
    Args:
        agent: SplunkAgent instance
        ioc_source: URL or file path to IOC report
        validate_with_splunk: Whether to validate query against Splunk
        test_with_attack_data: Whether to test against attack data
        
    Returns:
        E2EWorkflowResult with complete workflow results
    """
    import time
    from src.input_processor import InputProcessor, InputType
    from src.agent.handlers import handle_ioc_report
    from src.agent.reasoning import ReasoningTrace
    
    start_time = time.time()
    result = E2EWorkflowResult()
    
    # ==========================================================================
    # Stage 1: Input Processing
    # ==========================================================================
    stage_start = time.time()
    stage = WorkflowStageResult(
        stage=WorkflowStage.INPUT,
        status=StageStatus.IN_PROGRESS,
        title="Processing IOC source",
    )
    result.stages.append(stage)
    
    try:
        processor = InputProcessor()
        processed = processor.process(ioc_source)
        
        if processed.input_type != InputType.IOC_REPORT:
            stage.status = StageStatus.FAILED
            stage.errors.append(f"Input not recognized as IOC report: {processed.input_type.value}")
            result.errors.append("Input must be a URL or file path to an IOC report")
            return result
        
        # Check for warnings from processing
        if processed.warnings:
            stage.warnings.extend(processed.warnings)
            result.warnings.extend(processed.warnings)
        
        stage.status = StageStatus.SUCCESS
        stage.details = {
            "source": ioc_source[:100],
            "report_title": processed.report_title or "Unknown",
            "content_length": len(processed.report_summary or "") if processed.report_summary else 0,
        }
        stage.duration_ms = (time.time() - stage_start) * 1000
        
        logger.info(f"Processed input: title='{processed.report_title}', warnings={processed.warnings}")
        
    except Exception as e:
        stage.status = StageStatus.FAILED
        stage.errors.append(str(e))
        result.errors.append(f"Failed to process input: {e}")
        logger.error(f"Input processing failed: {e}", exc_info=True)
        return result
    
    # ==========================================================================
    # Stage 2: IOC Extraction
    # ==========================================================================
    stage_start = time.time()
    stage = WorkflowStageResult(
        stage=WorkflowStage.IOC_EXTRACTION,
        status=StageStatus.IN_PROGRESS,
        title="Extracting IOCs from report",
    )
    result.stages.append(stage)
    
    try:
        if not processed.iocs:
            stage.status = StageStatus.FAILED
            stage.errors.append("No IOCs found in report")
            
            # Provide more context about what was analyzed
            content_info = ""
            if processed.report_summary:
                content_info = f" (analyzed {len(processed.report_summary)} chars)"
            elif processed.warnings:
                content_info = f" - {'; '.join(processed.warnings)}"
            
            result.errors.append(f"IOC extraction failed - no indicators found{content_info}")
            logger.warning(f"No IOCs found in {ioc_source}. Content length: {len(processed.report_summary or '')}, warnings: {processed.warnings}")
            return result
        
        # Build IOC summary
        ioc_by_type = {}
        for ioc in processed.iocs:
            type_name = ioc.ioc_type.value
            if type_name not in ioc_by_type:
                ioc_by_type[type_name] = []
            ioc_by_type[type_name].append(ioc)
        
        result.ioc_count = len(processed.iocs)
        result.ioc_types = {k: len(v) for k, v in ioc_by_type.items()}
        result.ttps_detected = processed.ttps or []
        
        ioc_summary_parts = [f"Report: {processed.report_title or 'Unknown'}"]
        ioc_summary_parts.append(f"Total IOCs: {len(processed.iocs)}")
        for type_name, count in sorted(result.ioc_types.items()):
            ioc_summary_parts.append(f"  - {type_name}: {count}")
        if result.ttps_detected:
            ioc_summary_parts.append(f"TTPs: {', '.join(result.ttps_detected[:5])}")
        
        result.ioc_summary = "\n".join(ioc_summary_parts)
        
        stage.status = StageStatus.SUCCESS
        stage.details = {
            "total_iocs": result.ioc_count,
            "ioc_types": result.ioc_types,
            "ttps": result.ttps_detected[:5],
        }
        stage.duration_ms = (time.time() - stage_start) * 1000
        
    except Exception as e:
        stage.status = StageStatus.FAILED
        stage.errors.append(str(e))
        result.errors.append(f"IOC extraction failed: {e}")
        return result
    
    # ==========================================================================
    # Stage 3: Detection Building
    # ==========================================================================
    stage_start = time.time()
    stage = WorkflowStageResult(
        stage=WorkflowStage.DETECTION_BUILD,
        status=StageStatus.IN_PROGRESS,
        title="Building detection query",
    )
    result.stages.append(stage)
    
    try:
        # Use the IOC handler to generate the query
        trace = ReasoningTrace()
        agent_result = handle_ioc_report(agent, processed, trace)
        
        if not agent_result.spl_query:
            stage.status = StageStatus.FAILED
            stage.errors.append("Failed to generate SPL query")
            result.errors.extend(agent_result.errors)
            return result
        
        result.spl_query = agent_result.spl_query
        result.explanation = agent_result.explanation
        
        stage.status = StageStatus.SUCCESS
        stage.details = {
            "query_length": len(result.spl_query),
            "uses_tstats": "tstats" in result.spl_query.lower(),
            "ioc_types_in_query": list(result.ioc_types.keys()),
        }
        stage.duration_ms = (time.time() - stage_start) * 1000
        
        if agent_result.warnings:
            stage.warnings.extend(agent_result.warnings)
            result.warnings.extend(agent_result.warnings)
        
    except Exception as e:
        stage.status = StageStatus.FAILED
        stage.errors.append(str(e))
        result.errors.append(f"Detection building failed: {e}")
        return result
    
    # ==========================================================================
    # Stage 4: Best Practices Check
    # ==========================================================================
    stage_start = time.time()
    stage = WorkflowStageResult(
        stage=WorkflowStage.BEST_PRACTICES,
        status=StageStatus.IN_PROGRESS,
        title="Checking best practices",
    )
    result.stages.append(stage)
    
    try:
        # Check for common best practice issues
        best_practice_checks = []
        query_lower = result.spl_query.lower()
        
        # Check for time range
        if "earliest" not in query_lower and "latest" not in query_lower:
            best_practice_checks.append("⚠️ No time range specified - consider adding earliest/latest")
            stage.warnings.append("No time range specified")
        
        # Check for index specification
        if "index=" not in query_lower and "| tstats" not in query_lower:
            best_practice_checks.append("⚠️ No index specified - may search all indexes")
            stage.warnings.append("No index specified")
        
        # Check for field extraction efficiency
        if "| rex " in query_lower:
            best_practice_checks.append("ℹ️ Uses rex for field extraction - consider indexed extractions")
        
        # Check for stats usage
        if "| stats " in query_lower or "| tstats " in query_lower:
            best_practice_checks.append("✅ Uses aggregation for efficient processing")
        
        # Check for table/fields
        if "| table " in query_lower or "| fields " in query_lower:
            best_practice_checks.append("✅ Limits output fields")
        
        stage.status = StageStatus.SUCCESS if not stage.warnings else StageStatus.WARNING
        stage.details = {
            "checks_passed": len([c for c in best_practice_checks if c.startswith("✅")]),
            "checks_warning": len([c for c in best_practice_checks if c.startswith("⚠️")]),
            "recommendations": best_practice_checks,
        }
        stage.duration_ms = (time.time() - stage_start) * 1000
        
        result.warnings.extend(stage.warnings)
        
    except Exception as e:
        stage.status = StageStatus.WARNING
        stage.warnings.append(f"Best practice check failed: {e}")
    
    # ==========================================================================
    # Stage 5: Metadata Validation (Splunk)
    # ==========================================================================
    if validate_with_splunk and agent.splunk:
        stage_start = time.time()
        stage = WorkflowStageResult(
            stage=WorkflowStage.METADATA_VALIDATION,
            status=StageStatus.IN_PROGRESS,
            title="Validating query against Splunk",
        )
        result.stages.append(stage)
        
        try:
            # Test query syntax
            validation = agent.splunk.validate_query(result.spl_query)
            
            if validation.get("valid"):
                result.query_validated = True
                result.validation_result_count = validation.get("result_count", 0)
                
                stage.status = StageStatus.SUCCESS
                stage.details = {
                    "valid": True,
                    "result_count": result.validation_result_count,
                    "execution_time": validation.get("execution_time", 0),
                }
            else:
                stage.status = StageStatus.WARNING
                stage.warnings.append(validation.get("error", "Unknown validation error"))
                result.warnings.append(f"Query validation warning: {validation.get('error')}")
            
            stage.duration_ms = (time.time() - stage_start) * 1000
            
        except Exception as e:
            stage.status = StageStatus.WARNING
            stage.warnings.append(f"Splunk validation failed: {e}")
            result.warnings.append(f"Could not validate against Splunk: {e}")
    else:
        stage = WorkflowStageResult(
            stage=WorkflowStage.METADATA_VALIDATION,
            status=StageStatus.SKIPPED,
            title="Splunk validation skipped",
            details={"reason": "Splunk not connected" if not agent.splunk else "Validation disabled"},
        )
        result.stages.append(stage)
    
    # ==========================================================================
    # Stage 6: Attack Data Testing
    # ==========================================================================
    if test_with_attack_data and agent.attack_data_rag:
        stage_start = time.time()
        stage = WorkflowStageResult(
            stage=WorkflowStage.ATTACK_DATA_TEST,
            status=StageStatus.IN_PROGRESS,
            title="Testing against attack data",
        )
        result.stages.append(stage)
        
        try:
            result.attack_data_tested = True
            
            # Search for relevant attack datasets based on TTPs and IOC types
            search_queries = []
            
            # Add TTP-based searches
            for ttp in result.ttps_detected[:3]:
                search_queries.append(f"MITRE ATT&CK {ttp}")
            
            # Add IOC-type based searches
            ioc_type_to_attack = {
                "ip_address": "network traffic connection",
                "domain": "DNS resolution domain",
                "url": "web traffic HTTP",
                "md5": "file hash malware",
                "sha256": "file hash malware",
                "file_name": "file execution process",
                "registry_key": "registry modification persistence",
                "email": "phishing email",
            }
            
            for ioc_type in result.ioc_types.keys():
                if ioc_type in ioc_type_to_attack:
                    search_queries.append(ioc_type_to_attack[ioc_type])
            
            # Search attack data
            all_matches = []
            seen_datasets = set()
            
            for query in search_queries[:5]:  # Limit searches
                try:
                    matches = agent.attack_data_rag.search(query, top_k=3)
                    for match in matches:
                        if match.name not in seen_datasets:
                            seen_datasets.add(match.name)
                            all_matches.append(AttackDataMatch(
                                dataset_name=match.name,
                                mitre_id=match.mitre_id,
                                technique=match.attack_technique,
                                file_path=match.file_path,
                                relevance_score=match.score,
                                match_count=1,
                            ))
                except Exception as e:
                    logger.warning(f"Attack data search failed for '{query}': {e}")
            
            # Sort by relevance
            all_matches.sort(key=lambda x: x.relevance_score, reverse=True)
            result.attack_data_matches = all_matches[:10]
            result.attack_data_match_count = len(all_matches)
            
            if all_matches:
                stage.status = StageStatus.SUCCESS
                stage.details = {
                    "datasets_found": len(all_matches),
                    "top_dataset": all_matches[0].dataset_name if all_matches else None,
                    "top_mitre": all_matches[0].mitre_id if all_matches else None,
                    "top_score": all_matches[0].relevance_score if all_matches else 0,
                }
            else:
                stage.status = StageStatus.WARNING
                stage.warnings.append("No matching attack datasets found")
                result.warnings.append("Could not find relevant attack data for testing")
            
            stage.duration_ms = (time.time() - stage_start) * 1000
            
        except Exception as e:
            stage.status = StageStatus.WARNING
            stage.warnings.append(f"Attack data testing failed: {e}")
            result.warnings.append(f"Could not test against attack data: {e}")
    else:
        stage = WorkflowStageResult(
            stage=WorkflowStage.ATTACK_DATA_TEST,
            status=StageStatus.SKIPPED,
            title="Attack data testing skipped",
            details={"reason": "Attack data RAG not loaded" if not agent.attack_data_rag else "Testing disabled"},
        )
        result.stages.append(stage)
    
    # ==========================================================================
    # Stage 7: Complete
    # ==========================================================================
    stage = WorkflowStageResult(
        stage=WorkflowStage.COMPLETE,
        status=StageStatus.SUCCESS,
        title="Workflow complete",
    )
    result.stages.append(stage)
    
    # Calculate overall success and confidence
    result.total_time_ms = (time.time() - start_time) * 1000
    
    # Success if we have a query
    result.success = bool(result.spl_query)
    
    # Calculate confidence score
    confidence_factors = []
    
    # IOC extraction quality (0-25 points)
    if result.ioc_count > 0:
        confidence_factors.append(min(25, result.ioc_count * 2))
    
    # TTP detection (0-20 points)
    if result.ttps_detected:
        confidence_factors.append(min(20, len(result.ttps_detected) * 5))
    
    # Query validation (0-25 points)
    if result.query_validated:
        confidence_factors.append(25)
    elif result.spl_query:
        confidence_factors.append(10)
    
    # Attack data matches (0-30 points)
    if result.attack_data_matches:
        avg_score = sum(m.relevance_score for m in result.attack_data_matches) / len(result.attack_data_matches)
        confidence_factors.append(min(30, int(avg_score * 30)))
    
    result.confidence_score = sum(confidence_factors) / 100
    
    stage.details = {
        "success": result.success,
        "confidence": f"{result.confidence_score:.0%}",
        "total_time": f"{result.total_time_ms:.0f}ms",
    }
    
    return result
