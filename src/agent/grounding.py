"""
Agent Grounding
===============

Validation and enforcement to prevent hallucination by ensuring the agent
only uses information from provided context (RAGs, Splunk metadata).

This module:
- Validates field names against CIM RAG (official Splunk CIM fields)
- Validates against Detection RAG (fields used in real detections)
- Tracks source attribution for responses
- Calculates grounding scores
- Flags unknown/unverified elements

The grounding system uses the existing RAG databases rather than hardcoded
field lists, ensuring it stays current with official Splunk documentation.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, TYPE_CHECKING
from enum import Enum

if TYPE_CHECKING:
    from src.rag_cim_docs import CIMRAG
    from src.rag_detections import DetectionRAG

logger = logging.getLogger(__name__)


class FieldSource(Enum):
    """Source of field validation."""
    CIM_DATA_MODEL = "cim"
    DETECTION_RAG = "detection"
    SPL_DOCS = "spl_docs"
    SPLUNK_METADATA = "splunk_metadata"
    USER_SPECIFIED = "user_specified"
    UNKNOWN = "unknown"


@dataclass
class FieldValidation:
    """Result of validating a field name."""
    field_name: str
    is_known: bool
    source: FieldSource
    confidence: float
    suggestions: List[str] = field(default_factory=list)


@dataclass 
class GroundingResult:
    """Result of grounding validation for a query."""
    is_grounded: bool
    grounding_score: float  # 0.0 to 1.0
    known_fields: List[FieldValidation] = field(default_factory=list)
    unknown_fields: List[FieldValidation] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    sources_used: Set[str] = field(default_factory=set)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for API responses."""
        return {
            "is_grounded": self.is_grounded,
            "grounding_score": self.grounding_score,
            "known_fields_count": len(self.known_fields),
            "unknown_fields_count": len(self.unknown_fields),
            "unknown_fields": [f.field_name for f in self.unknown_fields],
            "warnings": self.warnings,
            "sources_used": list(self.sources_used),
        }


# =============================================================================
# MINIMAL HARDCODED FIELDS (Only SPL built-ins that NEVER change)
# =============================================================================

# Standard Splunk indexed fields (always available in every Splunk installation)
INDEXED_FIELDS = {
    "_time", "_raw", "_indextime", "host", "source", "sourcetype", "index",
    "splunk_server", "linecount", "punct", "eventtype", "_bkt", "_cd",
}

# SPL-generated fields (created by commands, not in data)
SPL_GENERATED_FIELDS = {
    # Aggregation results
    "count", "sum", "avg", "min", "max", "stdev", "dc", "values", "list",
    "earliest", "latest", "first", "last", "range", "perc", "median",
    "sparkline", "duration", "span", "rate", "_span", "_spandays",
    # tstats keywords
    "nodename", "summariesonly", "prestats", "local", "append",
    # Common aliases created by users
    "firstTime", "lastTime", "totalCount",
}


# =============================================================================
# GROUNDING VALIDATOR CLASS
# =============================================================================

class GroundingValidator:
    """
    Validates SPL queries against known field sources.
    
    Uses the RAG systems dynamically to validate fields, ensuring
    the grounding stays current with official Splunk documentation.
    """
    
    def __init__(
        self,
        cim_rag: Optional["CIMRAG"] = None,
        detection_rag: Optional["DetectionRAG"] = None,
    ):
        """
        Initialize the grounding validator.
        
        Args:
            cim_rag: CIM RAG instance for field validation
            detection_rag: Detection RAG for finding similar queries
        """
        self.cim_rag = cim_rag
        self.detection_rag = detection_rag
        
        # Cache for CIM fields (populated on first use)
        self._cim_fields_cache: Optional[Set[str]] = None
        self._detection_fields_cache: Optional[Set[str]] = None
    
    def get_cim_fields(self) -> Set[str]:
        """
        Get all known CIM fields from the CIM RAG.
        
        Returns:
            Set of field names from CIM data models
        """
        if self._cim_fields_cache is not None:
            return self._cim_fields_cache
        
        if not self.cim_rag:
            logger.warning("CIM RAG not available for field validation")
            return set()
        
        try:
            fields = set()
            
            # Get all data models
            data_models = self.cim_rag.list_data_models()
            
            # Extract fields from each data model
            for model in data_models:
                model_fields = self.cim_rag.get_fields_for_model(model)
                fields.update(model_fields)
            
            # Also extract fields from a general search
            results = self.cim_rag.search("fields", top_k=50)
            for result in results:
                if result.field_names:
                    fields.update(result.field_names)
            
            self._cim_fields_cache = fields
            logger.info(f"Loaded {len(fields)} CIM fields from RAG")
            return fields
            
        except Exception as e:
            logger.warning(f"Failed to load CIM fields from RAG: {e}")
            return set()
    
    def get_detection_fields(self, query_context: str = "") -> Set[str]:
        """
        Get fields used in similar detections from the Detection RAG.
        
        Args:
            query_context: Context to find similar detections
            
        Returns:
            Set of field names from similar detections
        """
        if not self.detection_rag:
            return set()
        
        try:
            fields = set()
            
            # Search for similar detections
            search_query = query_context if query_context else "detection"
            results = self.detection_rag.search(search_query, top_k=10)
            
            # Extract fields from detection SPL queries
            for result in results:
                if hasattr(result, 'search') and result.search:
                    detection_fields = extract_fields_from_spl(result.search)[0]
                    fields.update(detection_fields)
            
            return fields
            
        except Exception as e:
            logger.warning(f"Failed to load detection fields from RAG: {e}")
            return set()
    
    def validate_field(
        self,
        field_name: str,
        query_context: str = "",
    ) -> FieldValidation:
        """
        Validate a single field name against known sources.
        
        Args:
            field_name: The field name to validate
            query_context: Optional context for smarter validation
            
        Returns:
            FieldValidation with source and confidence
        """
        field_lower = field_name.lower()
        field_clean = field_name.strip()
        
        # 1. Check indexed fields (highest confidence)
        if field_clean in INDEXED_FIELDS or field_lower in {f.lower() for f in INDEXED_FIELDS}:
            return FieldValidation(field_name, True, FieldSource.SPL_DOCS, 1.0)
        
        # 2. Check SPL-generated fields
        if field_clean in SPL_GENERATED_FIELDS or field_lower in {f.lower() for f in SPL_GENERATED_FIELDS}:
            return FieldValidation(field_name, True, FieldSource.SPL_DOCS, 1.0)
        
        # 3. Check CIM fields from RAG
        cim_fields = self.get_cim_fields()
        if field_clean in cim_fields or field_lower in {f.lower() for f in cim_fields}:
            return FieldValidation(field_name, True, FieldSource.CIM_DATA_MODEL, 0.95)
        
        # 4. Check detection fields from RAG
        detection_fields = self.get_detection_fields(query_context)
        if field_clean in detection_fields or field_lower in {f.lower() for f in detection_fields}:
            return FieldValidation(field_name, True, FieldSource.DETECTION_RAG, 0.90)
        
        # 5. Check for CIM-prefixed fields (e.g., Authentication.user)
        if "." in field_clean:
            prefix = field_clean.split(".")[0].lower()
            if prefix in {"authentication", "endpoint", "processes", "network", "web", "email", "alerts", "change"}:
                return FieldValidation(field_name, True, FieldSource.CIM_DATA_MODEL, 0.85)
        
        # 6. Find similar fields for suggestions
        suggestions = self._find_similar_fields(field_name, cim_fields)
        
        return FieldValidation(
            field_name,
            False,
            FieldSource.UNKNOWN,
            0.0,
            suggestions[:3]
        )
    
    def _find_similar_fields(self, field_name: str, known_fields: Set[str]) -> List[str]:
        """Find similar field names for suggestions."""
        suggestions = []
        field_lower = field_name.lower()
        
        for known in known_fields:
            known_lower = known.lower()
            # Check for partial matches
            if field_lower in known_lower or known_lower in field_lower:
                suggestions.append(known)
            # Check for similar patterns (e.g., user vs src_user)
            elif field_lower.replace("_", "") in known_lower.replace("_", ""):
                suggestions.append(known)
        
        return suggestions[:5]
    
    def validate_query(
        self,
        spl_query: str,
        rag_context: str = "",
        user_specified_fields: Optional[Set[str]] = None,
    ) -> GroundingResult:
        """
        Validate all fields in an SPL query.
        
        Args:
            spl_query: The SPL query to validate
            rag_context: Context from RAG retrieval
            user_specified_fields: Fields explicitly mentioned by user
            
        Returns:
            GroundingResult with validation details
        """
        user_fields = user_specified_fields or set()
        
        # Extract fields from the query
        used_fields, created_fields = extract_fields_from_spl(spl_query)
        
        # Only validate used fields (not created ones)
        fields_to_validate = used_fields - created_fields - SPL_GENERATED_FIELDS
        
        known_validations = []
        unknown_validations = []
        sources_used = set()
        
        for field_name in fields_to_validate:
            # Skip if user explicitly mentioned this field
            if field_name.lower() in {f.lower() for f in user_fields}:
                validation = FieldValidation(field_name, True, FieldSource.USER_SPECIFIED, 0.95)
                known_validations.append(validation)
                sources_used.add("user_specified")
                continue
            
            # Check if field appears in RAG context
            if rag_context and field_name.lower() in rag_context.lower():
                validation = FieldValidation(field_name, True, FieldSource.SPL_DOCS, 0.90)
                known_validations.append(validation)
                sources_used.add("spl_docs")
                continue
            
            # Validate against RAG sources
            validation = self.validate_field(field_name, rag_context)
            
            if validation.is_known:
                known_validations.append(validation)
                sources_used.add(validation.source.value)
            else:
                unknown_validations.append(validation)
        
        # Calculate grounding score
        total_fields = len(known_validations) + len(unknown_validations)
        if total_fields == 0:
            grounding_score = 1.0  # No fields to validate
        else:
            # Weight known fields by their confidence
            known_score = sum(v.confidence for v in known_validations)
            grounding_score = known_score / total_fields
        
        # Determine if query is grounded
        is_grounded = len(unknown_validations) == 0 or grounding_score >= 0.7
        
        # Generate warnings for unknown fields
        warnings = []
        if unknown_validations:
            unknown_names = [v.field_name for v in unknown_validations]
            warnings.append(
                f"Unknown fields detected: {', '.join(unknown_names)}. "
                "These may not exist in your Splunk environment."
            )
        
        return GroundingResult(
            is_grounded=is_grounded,
            grounding_score=grounding_score,
            known_fields=known_validations,
            unknown_fields=unknown_validations,
            warnings=warnings,
            sources_used=sources_used,
        )


# =============================================================================
# FIELD EXTRACTION
# =============================================================================

def extract_fields_from_spl(spl_query: str) -> Tuple[Set[str], Set[str]]:
    """
    Extract field names from an SPL query.
    
    Separates fields into:
    - used_fields: Fields that must exist in the data
    - created_fields: Fields created by the query (eval, stats as, rename as)
    
    Returns:
        Tuple of (used_fields, created_fields)
    """
    used_fields = set()
    created_fields = set()
    
    # Normalize query
    query = spl_query.replace('\n', ' ').replace('\r', ' ')
    
    # Pattern for fields created by eval
    eval_pattern = r'\beval\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*='
    for match in re.finditer(eval_pattern, query, re.IGNORECASE):
        created_fields.add(match.group(1))
    
    # Pattern for fields created by "stats ... as <field>"
    stats_as_pattern = r'\bas\s+([a-zA-Z_][a-zA-Z0-9_]*)'
    for match in re.finditer(stats_as_pattern, query, re.IGNORECASE):
        field = match.group(1)
        # Avoid false positives from "stats as" being part of field list
        if field.lower() not in {'by', 'and', 'or', 'not', 'where'}:
            created_fields.add(field)
    
    # Pattern for fields created by "rename ... as <field>"
    rename_as_pattern = r'\brename\s+\S+\s+as\s+([a-zA-Z_][a-zA-Z0-9_]*)'
    for match in re.finditer(rename_as_pattern, query, re.IGNORECASE):
        created_fields.add(match.group(1))
    
    # Extract all potential field references
    # Pattern matches field=value, field IN (...), by field, etc.
    field_patterns = [
        r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*[=!<>]',  # field=value, field!=value
        r'\bby\s+([a-zA-Z_][a-zA-Z0-9_]*)',       # by field
        r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s+IN\s*\(',  # field IN (...)
        r'\bwhere\s+([a-zA-Z_][a-zA-Z0-9_]*)',    # where field
        r'\bsearch\s+([a-zA-Z_][a-zA-Z0-9_]*)',   # search field
        r'"\*\\\\([a-zA-Z_][a-zA-Z0-9_]*)',       # wildcard paths
    ]
    
    for pattern in field_patterns:
        for match in re.finditer(pattern, query, re.IGNORECASE):
            field = match.group(1)
            # Skip SPL keywords and common values
            if field.lower() not in {
                'index', 'sourcetype', 'source', 'host', 'and', 'or', 'not',
                'where', 'by', 'as', 'in', 'from', 'to', 'true', 'false',
                'null', 'search', 'stats', 'eval', 'table', 'fields',
                'rename', 'sort', 'head', 'tail', 'dedup', 'tstats',
            }:
                used_fields.add(field)
    
    # Extract fields from stats functions
    stats_func_pattern = r'\b(?:count|sum|avg|min|max|dc|values|list)\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)'
    for match in re.finditer(stats_func_pattern, query, re.IGNORECASE):
        used_fields.add(match.group(1))
    
    # Extract fields after "by" in stats/chart commands
    by_fields_pattern = r'\bby\s+((?:[a-zA-Z_][a-zA-Z0-9_]*(?:\s*,\s*)?)+)'
    for match in re.finditer(by_fields_pattern, query, re.IGNORECASE):
        fields_str = match.group(1)
        for field in re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)', fields_str):
            if field.lower() not in {'and', 'or', 'not', 'as'}:
                used_fields.add(field)
    
    return used_fields, created_fields


# =============================================================================
# CONVENIENCE FUNCTION (for backward compatibility)
# =============================================================================

# Global validator instance (lazy initialized)
_global_validator: Optional[GroundingValidator] = None


def get_validator(
    cim_rag: Optional["CIMRAG"] = None,
    detection_rag: Optional["DetectionRAG"] = None,
) -> GroundingValidator:
    """Get or create a global grounding validator."""
    global _global_validator
    
    if _global_validator is None or cim_rag is not None or detection_rag is not None:
        _global_validator = GroundingValidator(cim_rag, detection_rag)
    
    return _global_validator


def validate_query_grounding(
    spl_query: str,
    rag_context: str = "",
    user_specified_fields: Optional[Set[str]] = None,
    cim_rag: Optional["CIMRAG"] = None,
    detection_rag: Optional["DetectionRAG"] = None,
) -> GroundingResult:
    """
    Validate an SPL query's grounding against known field sources.
    
    This is a convenience function that uses the global validator or creates
    one with the provided RAGs.
    
    Args:
        spl_query: The SPL query to validate
        rag_context: Context from RAG retrieval (fields mentioned here are trusted)
        user_specified_fields: Fields explicitly mentioned by the user
        cim_rag: Optional CIM RAG for field validation
        detection_rag: Optional Detection RAG for field validation
        
    Returns:
        GroundingResult with validation details
    """
    validator = get_validator(cim_rag, detection_rag)
    return validator.validate_query(spl_query, rag_context, user_specified_fields)
