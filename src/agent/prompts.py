"""
Agent Prompt Templates
======================

Prompt loader for external prompt files in the `prompts/` directory.

All prompts are externalized to markdown files for easy customization:
- prompts/system_prompt.md - Main agent personality/instructions
- prompts/DIRECTIVE_spl_syntax.md - Critical SPL syntax rules
- prompts/PROMPT_query_generation.md - Query generation template
- prompts/PROMPT_refinement.md - Query refinement template
- prompts/PROMPT_ioc_hunting.md - IOC hunting template
- prompts/PROMPT_log_source.md - Log source exploration template
- prompts/SKILL_*.md - Domain knowledge (SPL syntax, detection engineering, IOC extraction)
- prompts/templates/*.spl - SPL query templates

NO FALLBACK PROMPTS: If a prompt file is missing, the system will raise an error.
This ensures prompt files are always present and up-to-date.
"""

import logging
from pathlib import Path
from functools import lru_cache

logger = logging.getLogger(__name__)

# Base path for prompts directory
PROMPTS_DIR = Path(__file__).parent.parent.parent / "prompts"


class PromptFileNotFoundError(Exception):
    """Raised when a required prompt file is missing."""
    pass


# =============================================================================
# FILE LOADERS
# =============================================================================

@lru_cache(maxsize=32)
def load_prompt_file(filename: str, required: bool = True) -> str:
    """
    Load a prompt file from the prompts directory.
    
    Args:
        filename: Name of the file in prompts/ directory
        required: If True, raise error when file not found
        
    Returns:
        Content of the file
        
    Raises:
        PromptFileNotFoundError: If file not found and required=True
    """
    filepath = PROMPTS_DIR / filename
    if filepath.exists():
        try:
            content = filepath.read_text(encoding="utf-8")
            logger.debug(f"Loaded prompt file: {filename}")
            return content
        except Exception as e:
            raise PromptFileNotFoundError(f"Could not read prompt file {filename}: {e}")
    else:
        if required:
            raise PromptFileNotFoundError(
                f"Required prompt file not found: {filepath}\n"
                f"Please ensure all prompt files exist in the prompts/ directory."
            )
        logger.warning(f"Optional prompt file not found: {filepath}")
        return ""


def clear_prompt_cache():
    """Clear the prompt file cache (useful for hot-reloading during development)."""
    load_prompt_file.cache_clear()


# =============================================================================
# PROMPT ACCESSORS
# =============================================================================

def get_system_prompt() -> str:
    """Get the main system prompt from external file."""
    return load_prompt_file("system_prompt.md")


def get_directive(directive_name: str) -> str:
    """
    Get a directive from external file.
    
    Args:
        directive_name: Name of the directive (e.g., "spl_syntax")
        
    Returns:
        Content of the directive file
        
    Raises:
        PromptFileNotFoundError: If directive file not found
    """
    return load_prompt_file(f"DIRECTIVE_{directive_name}.md")


def get_prompt(prompt_name: str) -> str:
    """
    Get a prompt template from external file.
    
    Args:
        prompt_name: Name of the prompt (e.g., "query_generation", "refinement")
        
    Returns:
        Content of the prompt file
        
    Raises:
        PromptFileNotFoundError: If prompt file not found
    """
    return load_prompt_file(f"PROMPT_{prompt_name}.md")


def get_skill(skill_name: str) -> str:
    """
    Get a skill definition from external file.
    
    Args:
        skill_name: Name of the skill (e.g., "spl_syntax", "detection_engineering")
        
    Returns:
        Content of the skill file, or empty string if not found (skills are optional)
    """
    return load_prompt_file(f"SKILL_{skill_name}.md", required=False)


def get_template(template_name: str) -> str:
    """
    Get an SPL template from external file.
    
    Args:
        template_name: Name of the template (e.g., "detection", "hunting")
        
    Returns:
        Content of the template file, or empty string if not found (templates are optional)
    """
    return load_prompt_file(f"templates/{template_name}_template.spl", required=False)


# =============================================================================
# COMPILED PROMPTS (With Directive Injection)
# =============================================================================

def get_directive_spl_syntax() -> str:
    """
    Get the SPL syntax directive (no macros, no comments, etc.).
    
    Raises:
        PromptFileNotFoundError: If DIRECTIVE_spl_syntax.md not found
    """
    return get_directive("spl_syntax")


# Backward compatibility alias
get_no_macro_instruction = get_directive_spl_syntax


def get_query_generation_prompt() -> str:
    """
    Get the query generation prompt with directive injection.
    
    Raises:
        PromptFileNotFoundError: If prompt file not found
    """
    prompt = get_prompt("query_generation")
    return prompt.replace("{directive_spl_syntax}", get_directive_spl_syntax())


def get_refinement_prompt() -> str:
    """
    Get the refinement prompt with directive injection.
    
    Raises:
        PromptFileNotFoundError: If prompt file not found
    """
    prompt = get_prompt("refinement")
    return prompt.replace("{directive_spl_syntax}", get_directive_spl_syntax())


def get_ioc_hunting_prompt() -> str:
    """
    Get the IOC hunting prompt with directive injection.
    
    Raises:
        PromptFileNotFoundError: If prompt file not found
    """
    prompt = get_prompt("ioc_hunting")
    return prompt.replace("{directive_spl_syntax}", get_directive_spl_syntax())


def get_log_source_prompt() -> str:
    """
    Get the log source exploration prompt with directive injection.
    
    Raises:
        PromptFileNotFoundError: If prompt file not found
    """
    prompt = get_prompt("log_source")
    return prompt.replace("{directive_spl_syntax}", get_directive_spl_syntax())


# =============================================================================
# BACKWARDS COMPATIBILITY (Legacy variable names)
# =============================================================================

# These are loaded lazily to maintain backwards compatibility
# with code that imports these directly

# Primary export - use this name going forward
DIRECTIVE_SPL_SYNTAX = get_directive_spl_syntax()

# Legacy alias (deprecated - use DIRECTIVE_SPL_SYNTAX instead)
NO_MACRO_INSTRUCTION = DIRECTIVE_SPL_SYNTAX

# Pre-compiled prompts with directive already injected
QUERY_GENERATION_PROMPT = get_query_generation_prompt()
REFINEMENT_PROMPT = get_refinement_prompt()
IOC_QUERY_PROMPT = get_ioc_hunting_prompt()
LOG_SOURCE_PROMPT = get_log_source_prompt()


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def build_enriched_prompt(base_prompt: str, include_skills: list[str] = None) -> str:
    """
    Build an enriched prompt by combining the base prompt with relevant skills.
    
    Args:
        base_prompt: The base prompt template
        include_skills: List of skill names to include
        
    Returns:
        Enriched prompt with skills appended
    """
    parts = [base_prompt]
    
    if include_skills:
        for skill_name in include_skills:
            skill_content = get_skill(skill_name)
            if skill_content:
                parts.append(f"\n## Reference: {skill_name.replace('_', ' ').title()}\n")
                parts.append(skill_content)
    
    return "\n".join(parts)


def list_available_prompts() -> dict:
    """List all available prompt files."""
    prompts = {
        "directives": [],
        "prompts": [],
        "skills": [],
        "templates": [],
    }
    
    if PROMPTS_DIR.exists():
        for file in PROMPTS_DIR.glob("*.md"):
            name = file.stem
            if name.startswith("DIRECTIVE_"):
                prompts["directives"].append(name.replace("DIRECTIVE_", ""))
            elif name.startswith("PROMPT_"):
                prompts["prompts"].append(name.replace("PROMPT_", ""))
            elif name.startswith("SKILL_"):
                prompts["skills"].append(name.replace("SKILL_", ""))
        
        templates_dir = PROMPTS_DIR / "templates"
        if templates_dir.exists():
            for file in templates_dir.glob("*.spl"):
                prompts["templates"].append(file.stem.replace("_template", ""))
    
    return prompts
