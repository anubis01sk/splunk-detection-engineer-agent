#!/usr/bin/env python3
"""
Splunk SPL Agent - Input Processor
===================================

Handles three types of input triggers for the Splunk SPL Agent:
    1. Natural Language - Plain English detection descriptions
    2. Log Source Specification - Index/sourcetype/field discovery
    3. IOC Report Processing - URL/PDF indicator extraction

The processor classifies input type, extracts relevant information,
and prepares structured data for the agent orchestrator.

Usage:
    from input_processor import InputProcessor, ProcessedInput
    
    processor = InputProcessor()
    
    # Natural language input
    result = processor.process("Detect brute force login attempts")
    
    # Log source specification
    result = processor.process("index=windows sourcetype=WinEventLog:Security")
    
    # IOC report (URL or file path)
    result = processor.process("https://example.com/threat-report.pdf")
    result = processor.process("/path/to/report.pdf")

Dependencies:
    pip install pdfplumber playwright pyyaml
    playwright install chromium

Author: Claude (Anthropic)
"""

import re
import json
import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union
from enum import Enum
from urllib.parse import urlparse
import logging

# Module-level logger - configuration is done by entry points (cli.py, server.py)
logger = logging.getLogger(__name__)


# =============================================================================
# DATA STRUCTURES
# =============================================================================

class InputType(Enum):
    """Classification of input types."""
    NATURAL_LANGUAGE = "natural_language"
    LOG_SOURCE = "log_source"
    IOC_REPORT = "ioc_report"
    UNKNOWN = "unknown"


class IOCType(Enum):
    """Types of Indicators of Compromise."""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    FILE_NAME = "file_name"
    FILE_PATH = "file_path"
    REGISTRY_KEY = "registry_key"
    CVE = "cve"
    MITRE_ATTACK = "mitre_attack"


@dataclass
class IOC:
    """A single Indicator of Compromise with metadata."""
    value: str
    ioc_type: IOCType
    confidence: float  # 0.0 to 1.0
    context: str = ""  # Surrounding text for context
    
    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "type": self.ioc_type.value,
            "confidence": self.confidence,
            "context": self.context,
        }


@dataclass
class LogSourceSpec:
    """Parsed log source specification."""
    index: Optional[str] = None
    sourcetype: Optional[str] = None
    source: Optional[str] = None
    host: Optional[str] = None
    fields: list[str] = field(default_factory=list)
    raw_query: str = ""
    
    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "sourcetype": self.sourcetype,
            "source": self.source,
            "host": self.host,
            "fields": self.fields,
            "raw_query": self.raw_query,
        }


@dataclass
class ProcessedInput:
    """
    Structured output from input processing.
    
    Contains the classified input type, extracted entities,
    and any additional context for the agent.
    """
    input_type: InputType
    original_input: str
    
    # For natural language inputs
    intent: str = ""
    entities: list[str] = field(default_factory=list)
    
    # For log source inputs
    log_source: Optional[LogSourceSpec] = None
    
    # For IOC report inputs
    iocs: list[IOC] = field(default_factory=list)
    report_title: str = ""
    report_summary: str = ""
    ttps: list[str] = field(default_factory=list)  # MITRE ATT&CK techniques
    
    # Processing metadata
    confidence: float = 1.0
    warnings: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        result = {
            "input_type": self.input_type.value,
            "original_input": self.original_input,
            "confidence": self.confidence,
            "warnings": self.warnings,
        }
        
        if self.input_type == InputType.NATURAL_LANGUAGE:
            result["intent"] = self.intent
            result["entities"] = self.entities
        elif self.input_type == InputType.LOG_SOURCE:
            result["log_source"] = self.log_source.to_dict() if self.log_source else None
        elif self.input_type == InputType.IOC_REPORT:
            result["iocs"] = [ioc.to_dict() for ioc in self.iocs]
            result["report_title"] = self.report_title
            result["report_summary"] = self.report_summary
            result["ttps"] = self.ttps
        
        return result
    
    def get_iocs_by_type(self, ioc_type: IOCType) -> list[IOC]:
        """Get IOCs filtered by type."""
        return [ioc for ioc in self.iocs if ioc.ioc_type == ioc_type]
    
    def get_high_confidence_iocs(self, threshold: float = 0.7) -> list[IOC]:
        """Get IOCs above confidence threshold."""
        return [ioc for ioc in self.iocs if ioc.confidence >= threshold]


# =============================================================================
# IOC EXTRACTION PATTERNS
# =============================================================================

class IOCPatterns:
    """Regular expression patterns for IOC extraction."""
    
    # IPv4 address (with validation for valid octets)
    IPV4 = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )
    
    # IPv6 address (simplified pattern)
    IPV6 = re.compile(
        r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
        r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'
        r'\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b'
    )
    
    # Domain name (excludes common false positives)
    DOMAIN = re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' 
        r'(?:com|net|org|edu|gov|mil|int|io|co|uk|de|fr|ru|cn|jp|br|au|in|'
        r'info|biz|xyz|top|online|site|tech|cloud|app|dev|pro|me|tv|cc|ws|'
        r'onion|bit|zip|mov)\b',
        re.IGNORECASE
    )
    
    # URL (http/https/ftp)
    URL = re.compile(
        r'\b(?:https?|ftp)://[^\s<>"{}|\\^`\[\]]+',
        re.IGNORECASE
    )
    
    # MD5 hash (32 hex characters)
    MD5 = re.compile(r'\b[a-fA-F0-9]{32}\b')
    
    # SHA1 hash (40 hex characters)
    SHA1 = re.compile(r'\b[a-fA-F0-9]{40}\b')
    
    # SHA256 hash (64 hex characters)
    SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
    
    # Email address
    EMAIL = re.compile(
        r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
    )
    
    # Windows file path
    WINDOWS_PATH = re.compile(
        r'\b[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*\b'
    )
    
    # Unix file path
    UNIX_PATH = re.compile(
        r'\b/(?:[^/\0\s]+/)*[^/\0\s]+\b'
    )
    
    # File name with common extensions
    FILE_NAME = re.compile(
        r'\b[\w\-\.]+\.(?:exe|dll|bat|ps1|vbs|js|jar|msi|scr|com|pif|cmd|'
        r'hta|wsf|lnk|doc|docx|xls|xlsx|pdf|zip|rar|7z|iso|img)\b',
        re.IGNORECASE
    )
    
    # Windows Registry key
    REGISTRY_KEY = re.compile(
        r'\b(?:HKEY_[A-Z_]+|HK[A-Z]{2})\\[^\s"\'<>]+',
        re.IGNORECASE
    )
    
    # CVE identifier
    CVE = re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.IGNORECASE)
    
    # MITRE ATT&CK technique ID
    MITRE_ATTACK = re.compile(r'\b[TS]\d{4}(?:\.\d{3})?\b')


# =============================================================================
# INPUT HANDLERS
# =============================================================================

class InputHandler(ABC):
    """Abstract base class for input handlers."""
    
    @abstractmethod
    def can_handle(self, input_text: str) -> bool:
        """Check if this handler can process the input."""
        pass
    
    @abstractmethod
    def process(self, input_text: str) -> ProcessedInput:
        """Process the input and return structured data."""
        pass


class NaturalLanguageHandler(InputHandler):
    """
    Handler for natural language detection descriptions.
    
    Extracts intent and security-related entities from plain English text.
    """
    
    # Keywords indicating security-related intent
    DETECTION_KEYWORDS = {
        "detect", "find", "identify", "monitor", "alert", "hunt", "search",
        "discover", "track", "watch", "flag", "catch", "spot", "notice",
    }
    
    # Security entity patterns
    SECURITY_ENTITIES = {
        "attack_type": [
            "brute force", "credential dumping", "lateral movement", "privilege escalation",
            "data exfiltration", "ransomware", "malware", "phishing", "injection",
            "denial of service", "dos", "ddos", "man in the middle", "mitm",
            "command and control", "c2", "c&c", "beaconing", "persistence",
            "defense evasion", "discovery", "collection", "impact", "execution",
        ],
        "data_source": [
            "windows event", "sysmon", "firewall", "proxy", "dns", "network traffic",
            "endpoint", "authentication", "audit log", "security log", "process",
            "registry", "file system", "active directory", "cloud", "aws", "azure", "gcp",
        ],
        "target": [
            "user", "admin", "administrator", "service account", "system", "domain controller",
            "server", "workstation", "endpoint", "database", "web server", "application",
        ],
    }
    
    def can_handle(self, input_text: str) -> bool:
        """Natural language is the fallback handler."""
        # Check it's not a log source spec or URL/file
        if self._looks_like_log_source(input_text):
            return False
        if self._looks_like_ioc_report(input_text):
            return False
        return True
    
    def _looks_like_log_source(self, text: str) -> bool:
        """Check if input looks like a log source specification."""
        log_source_patterns = [
            r'\bindex\s*=',
            r'\bsourcetype\s*=',
            r'\bsource\s*=',
            r'\bhost\s*=',
        ]
        return any(re.search(p, text, re.IGNORECASE) for p in log_source_patterns)
    
    def _looks_like_ioc_report(self, text: str) -> bool:
        """Check if input looks like a URL, file path, or inline IOC request."""
        text = text.strip()
        text_lower = text.lower()
        
        # URL
        if re.match(r'^https?://', text, re.IGNORECASE):
            return True
        # File path
        if text.endswith('.pdf') or text.endswith('.html') or text.endswith('.txt'):
            return True
        if text.startswith('/') or re.match(r'^[a-zA-Z]:\\', text):
            return True
        
        # Inline IOC request detection
        # Keywords that suggest user is providing IOCs directly
        ioc_keywords = [
            r'\bioc[s]?\b', r'\bindicator[s]?\b', r'\bhunt\s+for\b', r'\bsearch\s+for\s+these\b',
            r'\blookup\b', r'\bfind\s+these\b', r'\bcheck\s+for\b',
        ]
        has_ioc_keyword = any(re.search(kw, text_lower) for kw in ioc_keywords)
        
        # Check if text contains actual IOC patterns (hashes, IPs, domains)
        has_hash = bool(IOCPatterns.MD5.search(text) or IOCPatterns.SHA256.search(text) or IOCPatterns.SHA1.search(text))
        has_ip = bool(IOCPatterns.IPV4.search(text))
        has_domain = bool(re.search(r'\b[a-z0-9][-a-z0-9]*\.[a-z]{2,}\b', text_lower))
        
        # If has IOC keyword AND actual IOC values, treat as IOC request
        if has_ioc_keyword and (has_hash or has_ip or has_domain):
            return True
        
        # If multiple IOC types present (likely an IOC list)
        ioc_type_count = sum([has_hash, has_ip, has_domain])
        if ioc_type_count >= 2:
            return True
        
        return False
    
    def process(self, input_text: str) -> ProcessedInput:
        """Process natural language input."""
        input_lower = input_text.lower()
        
        # Extract intent
        intent = self._extract_intent(input_lower)
        
        # Extract entities
        entities = self._extract_entities(input_lower)
        
        # Calculate confidence based on detected keywords
        confidence = self._calculate_confidence(input_lower, entities)
        
        return ProcessedInput(
            input_type=InputType.NATURAL_LANGUAGE,
            original_input=input_text,
            intent=intent,
            entities=entities,
            confidence=confidence,
        )
    
    def _extract_intent(self, text: str) -> str:
        """Extract the primary intent from the text."""
        for keyword in self.DETECTION_KEYWORDS:
            if keyword in text:
                # Find what comes after the keyword
                pattern = rf'{keyword}\s+(.+?)(?:\.|$)'
                match = re.search(pattern, text)
                if match:
                    return f"{keyword} {match.group(1).strip()}"
        return text[:100]  # Fallback to truncated input
    
    def _extract_entities(self, text: str) -> list[str]:
        """Extract security-related entities from the text."""
        entities = []
        
        for category, patterns in self.SECURITY_ENTITIES.items():
            for pattern in patterns:
                if pattern in text:
                    entities.append(f"{category}:{pattern}")
        
        # Extract MITRE ATT&CK references
        mitre_matches = IOCPatterns.MITRE_ATTACK.findall(text.upper())
        for match in mitre_matches:
            entities.append(f"mitre:{match}")
        
        return entities
    
    def _calculate_confidence(self, text: str, entities: list[str]) -> float:
        """Calculate confidence score for the classification."""
        score = 0.5  # Base score
        
        # Boost for detection keywords
        if any(kw in text for kw in self.DETECTION_KEYWORDS):
            score += 0.2
        
        # Boost for extracted entities
        score += min(0.3, len(entities) * 0.05)
        
        return min(1.0, score)


class LogSourceHandler(InputHandler):
    """
    Handler for log source specifications.
    
    Parses Splunk search terms like index=, sourcetype=, etc.
    """
    
    # Patterns for log source components
    INDEX_PATTERN = re.compile(r'\bindex\s*=\s*["\']?(\S+?)["\']?(?:\s|$)', re.IGNORECASE)
    SOURCETYPE_PATTERN = re.compile(r'\bsourcetype\s*=\s*["\']?(\S+?)["\']?(?:\s|$)', re.IGNORECASE)
    SOURCE_PATTERN = re.compile(r'\bsource\s*=\s*["\']?(\S+?)["\']?(?:\s|$)', re.IGNORECASE)
    HOST_PATTERN = re.compile(r'\bhost\s*=\s*["\']?(\S+?)["\']?(?:\s|$)', re.IGNORECASE)
    
    # Keywords that indicate user wants a detection rule, not just exploration
    DETECTION_KEYWORDS = {
        "detection", "rule", "alert", "siem", "detect", "hunt", "threat",
        "malicious", "attack", "suspicious", "security", "monitor", "trigger",
        "create a", "build a", "generate a", "write a",
    }
    
    def can_handle(self, input_text: str) -> bool:
        """Check if input contains log source specifications."""
        # If input contains detection keywords, let NaturalLanguageHandler handle it
        # even if it has index= specifications (user wants detection, not exploration)
        input_lower = input_text.lower()
        if any(kw in input_lower for kw in self.DETECTION_KEYWORDS):
            return False
        
        patterns = [
            self.INDEX_PATTERN,
            self.SOURCETYPE_PATTERN,
            self.SOURCE_PATTERN,
            self.HOST_PATTERN,
        ]
        return any(p.search(input_text) for p in patterns)
    
    def process(self, input_text: str) -> ProcessedInput:
        """Process log source specification."""
        log_source = LogSourceSpec(raw_query=input_text)
        
        # Extract index
        match = self.INDEX_PATTERN.search(input_text)
        if match:
            log_source.index = match.group(1).strip('"\'')
        
        # Extract sourcetype
        match = self.SOURCETYPE_PATTERN.search(input_text)
        if match:
            log_source.sourcetype = match.group(1).strip('"\'')
        
        # Extract source
        match = self.SOURCE_PATTERN.search(input_text)
        if match:
            log_source.source = match.group(1).strip('"\'')
        
        # Extract host
        match = self.HOST_PATTERN.search(input_text)
        if match:
            log_source.host = match.group(1).strip('"\'')
        
        # Calculate confidence
        specified_count = sum(1 for x in [log_source.index, log_source.sourcetype, 
                                           log_source.source, log_source.host] if x)
        confidence = 0.5 + (specified_count * 0.125)
        
        return ProcessedInput(
            input_type=InputType.LOG_SOURCE,
            original_input=input_text,
            log_source=log_source,
            confidence=confidence,
        )


class IOCReportHandler(InputHandler):
    """
    Handler for IOC reports (URLs, PDF files, and inline IOC text).
    
    Fetches content using Playwright and extracts indicators of compromise.
    Also handles inline IOC requests like "Hunt for IOCs: IP 1.2.3.4, domain evil.com"
    """
    
    def __init__(self):
        self._browser = None
        self._playwright = None
    
    def can_handle(self, input_text: str) -> bool:
        """Check if input is a URL, file path, or inline IOC request."""
        text = input_text.strip()
        text_lower = text.lower()
        
        # URL
        if re.match(r'^https?://', text, re.IGNORECASE):
            return True
        
        # PDF file path
        if text.endswith('.pdf'):
            path = Path(text)
            return path.exists() or text.startswith('http')
        
        # HTML/text file
        if text.endswith(('.html', '.htm', '.txt')):
            path = Path(text)
            return path.exists()
        
        # Inline IOC request detection
        ioc_keywords = [
            r'\bioc[s]?\b', r'\bindicator[s]?\b', r'\bhunt\s+for\b', 
            r'\bsearch\s+for\s+these\b', r'\blookup\b', r'\bfind\s+these\b',
        ]
        has_ioc_keyword = any(re.search(kw, text_lower) for kw in ioc_keywords)
        
        # Check for actual IOC patterns
        has_hash = bool(IOCPatterns.MD5.search(text) or IOCPatterns.SHA256.search(text))
        has_ip = bool(IOCPatterns.IPV4.search(text))
        
        # If has IOC keyword AND actual IOC values, treat as IOC request
        if has_ioc_keyword and (has_hash or has_ip):
            return True
        
        return False
    
    def process(self, input_text: str) -> ProcessedInput:
        """Process IOC report input (URL, file, or inline text)."""
        input_text = input_text.strip()
        warnings = []
        content = ""
        title = ""
        
        # Determine input type: URL, file, or inline text
        if re.match(r'^https?://', input_text, re.IGNORECASE):
            # URL - fetch content
            content, title = self._fetch_url(input_text)
            if not content:
                warnings.append(f"Failed to fetch content from URL: {input_text}")
                content = ""
                title = ""
        elif input_text.endswith(('.pdf', '.html', '.htm', '.txt')) or input_text.startswith('/') or re.match(r'^[a-zA-Z]:\\', input_text):
            # Local file path
            path = Path(input_text)
            if not path.exists():
                return ProcessedInput(
                    input_type=InputType.IOC_REPORT,
                    original_input=input_text,
                    confidence=0.0,
                    warnings=[f"File not found: {input_text}"],
                )
            
            if path.suffix.lower() == '.pdf':
                content, title = self._extract_pdf(path)
            else:
                content = path.read_text(encoding='utf-8', errors='ignore')
                title = path.stem
        else:
            # Inline IOC text - use the input directly as content
            content = input_text
            title = "Inline IOC Request"
            logger.info(f"Processing inline IOC request: {input_text[:100]}...")
        
        # Extract IOCs from content
        iocs = self._extract_iocs(content)
        
        # Extract TTPs (MITRE ATT&CK techniques)
        ttps = self._extract_ttps(content)
        
        # Generate summary
        summary = self._generate_summary(content, iocs)
        
        # Calculate overall confidence
        confidence = self._calculate_confidence(iocs, ttps)
        
        return ProcessedInput(
            input_type=InputType.IOC_REPORT,
            original_input=input_text,
            iocs=iocs,
            report_title=title,
            report_summary=summary,
            ttps=ttps,
            confidence=confidence,
            warnings=warnings,
        )
    
    def _fetch_url(self, url: str) -> tuple[str, str]:
        """Fetch content from URL using httpx first, then Playwright as fallback."""
        # Try simple HTTP fetch first (faster, works for most pages)
        content, title = self._fetch_url_simple(url)
        if content and len(content) > 500:
            logger.info(f"Successfully fetched URL with httpx: {len(content)} chars")
            return content, title
        
        # Fallback to Playwright for JavaScript-heavy pages
        logger.info("Trying Playwright for JavaScript rendering...")
        return self._fetch_url_playwright(url)
    
    def _fetch_url_simple(self, url: str) -> tuple[str, str]:
        """Fetch content from URL using httpx (fast, no JS rendering)."""
        try:
            import httpx
            from bs4 import BeautifulSoup
            
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            }
            
            with httpx.Client(timeout=30, follow_redirects=True, verify=False) as client:
                response = client.get(url, headers=headers)
                response.raise_for_status()
                html = response.text
            
            logger.info(f"Fetched {len(html)} bytes from {url}")
            
            # Parse with BeautifulSoup
            soup = BeautifulSoup(html, 'html.parser')
            
            # Get title
            title = soup.title.string if soup.title else ""
            
            # Try to find main article content first (common in security blogs)
            article_selectors = [
                'article',
                '.post-content',
                '.entry-content',
                '.article-content',
                '.blog-content',
                '.c-article__content',  # Securelist
                '#content',
                'main',
                '.main-content',
            ]
            
            main_content = None
            for selector in article_selectors:
                main_content = soup.select_one(selector)
                if main_content:
                    logger.info(f"Found main content using selector: {selector}")
                    break
            
            # Use main content if found, otherwise use body
            content_soup = main_content if main_content else soup.body or soup
            
            # Remove script, style, and navigation elements
            for element in content_soup.find_all(['script', 'style', 'nav', 'header', 'footer', 'aside', 'noscript']):
                element.decompose()
            
            # Extract text content
            text_parts = []
            
            # Get main text
            text_parts.append(content_soup.get_text(separator='\n', strip=True))
            
            # Also extract text from code blocks and pre tags (common in security reports)
            # Re-parse original to get code blocks that might have been removed
            soup_fresh = BeautifulSoup(html, 'html.parser')
            code_blocks = soup_fresh.find_all(['code', 'pre', 'samp'])
            for block in code_blocks:
                block_text = block.get_text(strip=True)
                if block_text and len(block_text) > 10:
                    text_parts.append(block_text)
            
            # Look for IOC tables (common in threat reports)
            tables = soup_fresh.find_all('table')
            for table in tables:
                for row in table.find_all('tr'):
                    cells = [cell.get_text(strip=True) for cell in row.find_all(['td', 'th'])]
                    if cells:
                        text_parts.append(' | '.join(cells))
            
            text = '\n'.join(text_parts)
            logger.info(f"Extracted {len(text)} chars of text content")
            
            return text, title
            
        except ImportError as e:
            logger.warning(f"httpx or BeautifulSoup not available: {e}")
            return "", ""
        except Exception as e:
            logger.warning(f"Simple fetch failed for {url}: {e}")
            return "", ""
    
    def _fetch_url_playwright(self, url: str) -> tuple[str, str]:
        """Fetch content from URL using Playwright (handles JavaScript)."""
        try:
            from playwright.sync_api import sync_playwright
            
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                
                # Set reasonable timeout
                page.set_default_timeout(30000)
                
                # Navigate to URL
                page.goto(url, wait_until='networkidle')
                
                # Get page title
                title = page.title() or ""
                
                # Get page content
                content = page.content()
                
                # Also try to get just text content
                text_content = page.evaluate('document.body.innerText')
                
                browser.close()
                
                # Prefer text content if available
                return text_content or content, title
                
        except Exception as e:
            logger.error(f"Playwright fetch failed for {url}: {e}")
            return "", ""
    
    def _extract_pdf(self, path: Path) -> tuple[str, str]:
        """Extract text content from PDF file."""
        try:
            import pdfplumber
            
            text_parts = []
            title = path.stem
            
            with pdfplumber.open(path) as pdf:
                # Try to get title from metadata
                if pdf.metadata and pdf.metadata.get('Title'):
                    title = pdf.metadata['Title']
                
                # Extract text from all pages
                for page in pdf.pages:
                    text = page.extract_text()
                    if text:
                        text_parts.append(text)
                    
                    # Also extract tables
                    tables = page.extract_tables()
                    for table in tables:
                        for row in table:
                            text_parts.append(' | '.join(str(cell) for cell in row if cell))
            
            return '\n\n'.join(text_parts), title
            
        except ImportError:
            logger.error("pdfplumber not installed. Run: pip install pdfplumber")
            return "", path.stem
        except Exception as e:
            logger.error(f"Error extracting PDF {path}: {e}")
            return "", path.stem
    
    def _extract_iocs(self, content: str) -> list[IOC]:
        """Extract all IOCs from content."""
        iocs = []
        
        # Skip if no content
        if not content:
            logger.warning("IOC extraction: No content provided")
            return iocs
        
        logger.info(f"IOC extraction: Analyzing {len(content)} characters")
        
        # Track seen values to avoid duplicates
        seen = set()
        
        # Extract each IOC type
        ioc_extractors = [
            (IOCPatterns.SHA256, IOCType.SHA256, 0.95),
            (IOCPatterns.SHA1, IOCType.SHA1, 0.95),
            (IOCPatterns.MD5, IOCType.MD5, 0.90),
            (IOCPatterns.IPV4, IOCType.IP_ADDRESS, 0.85),
            (IOCPatterns.IPV6, IOCType.IP_ADDRESS, 0.85),
            (IOCPatterns.URL, IOCType.URL, 0.90),
            (IOCPatterns.DOMAIN, IOCType.DOMAIN, 0.75),
            (IOCPatterns.EMAIL, IOCType.EMAIL, 0.80),
            (IOCPatterns.FILE_NAME, IOCType.FILE_NAME, 0.85),
            (IOCPatterns.WINDOWS_PATH, IOCType.FILE_PATH, 0.80),
            (IOCPatterns.REGISTRY_KEY, IOCType.REGISTRY_KEY, 0.90),
            (IOCPatterns.CVE, IOCType.CVE, 0.95),
        ]
        
        for pattern, ioc_type, base_confidence in ioc_extractors:
            for match in pattern.finditer(content):
                value = match.group()
                
                # Skip duplicates
                if value.lower() in seen:
                    continue
                seen.add(value.lower())
                
                # Skip common false positives
                if self._is_false_positive(value, ioc_type):
                    continue
                
                # Get surrounding context
                start = max(0, match.start() - 50)
                end = min(len(content), match.end() + 50)
                context = content[start:end].replace('\n', ' ').strip()
                
                # Adjust confidence based on context
                confidence = self._adjust_confidence(value, ioc_type, base_confidence, context)
                
                iocs.append(IOC(
                    value=value,
                    ioc_type=ioc_type,
                    confidence=confidence,
                    context=context,
                ))
        
        # Sort by confidence
        iocs.sort(key=lambda x: x.confidence, reverse=True)
        
        # Log results
        if iocs:
            ioc_summary = {}
            for ioc in iocs:
                ioc_summary[ioc.ioc_type.value] = ioc_summary.get(ioc.ioc_type.value, 0) + 1
            logger.info(f"IOC extraction: Found {len(iocs)} IOCs - {ioc_summary}")
        else:
            logger.warning("IOC extraction: No IOCs found after filtering")
        
        return iocs
    
    def _is_false_positive(self, value: str, ioc_type: IOCType) -> bool:
        """Check if extracted value is likely a false positive."""
        value_lower = value.lower()
        
        if ioc_type == IOCType.DOMAIN:
            # Common non-malicious domains (security vendors, big tech, etc.)
            benign_domains = {
                'example.com', 'localhost.com', 'test.com', 'microsoft.com',
                'google.com', 'github.com', 'splunk.com', 'windows.com',
                'kaspersky.com', 'securelist.com', 'virustotal.com',
                'mandiant.com', 'crowdstrike.com', 'fireeye.com',
                'symantec.com', 'mcafee.com', 'trendmicro.com',
                'sophos.com', 'malwarebytes.com', 'eset.com',
                'paloaltonetworks.com', 'fortinet.com', 'cisco.com',
                'cisa.gov', 'nist.gov', 'mitre.org', 'attack.mitre.org',
                'twitter.com', 'linkedin.com', 'facebook.com',
                'wikipedia.org', 'reddit.com', 'youtube.com',
                'w3.org', 'schema.org', 'cloudflare.com',
            }
            # Check if domain or any parent domain is benign
            for benign in benign_domains:
                if value_lower == benign or value_lower.endswith('.' + benign):
                    return True
            
            # Version numbers that look like domains
            if re.match(r'^\d+\.\d+\.\d+$', value):
                return True
        
        elif ioc_type == IOCType.EMAIL:
            # Emails from security vendors/report authors
            benign_email_domains = {
                'kaspersky.com', 'securelist.com', 'virustotal.com',
                'mandiant.com', 'crowdstrike.com', 'fireeye.com',
                'microsoft.com', 'google.com', 'gmail.com',
                'symantec.com', 'mcafee.com', 'trendmicro.com',
            }
            email_domain = value_lower.split('@')[-1] if '@' in value_lower else ''
            if email_domain in benign_email_domains:
                return True
        
        elif ioc_type == IOCType.IP_ADDRESS:
            # Private/reserved ranges (still extract but lower confidence)
            if value.startswith(('10.', '192.168.', '172.16.', '172.17.', 
                                  '172.18.', '172.19.', '172.2', '172.3',
                                  '127.', '0.', '255.')):
                return False  # Don't skip, but confidence will be lower
        
        elif ioc_type == IOCType.FILE_NAME:
            # Common benign file names and system files
            benign_files = {
                'readme.txt', 'license.txt', 'index.html',
                'ntoskrnl.exe',  # Windows kernel - commonly mentioned but not IOC
                'cmd.exe', 'powershell.exe', 'explorer.exe',  # System executables
            }
            if value_lower in benign_files:
                return True
        
        return False
    
    def _adjust_confidence(self, value: str, ioc_type: IOCType, 
                          base_confidence: float, context: str) -> float:
        """Adjust confidence based on value and context."""
        confidence = base_confidence
        context_lower = context.lower()
        
        # Boost confidence for IOC-related context
        ioc_keywords = ['indicator', 'ioc', 'malicious', 'threat', 'attack',
                        'compromise', 'malware', 'suspicious', 'observed']
        if any(kw in context_lower for kw in ioc_keywords):
            confidence = min(1.0, confidence + 0.1)
        
        # Lower confidence for private IPs
        if ioc_type == IOCType.IP_ADDRESS:
            if value.startswith(('10.', '192.168.', '172.16.', '127.')):
                confidence = max(0.3, confidence - 0.3)
        
        # Lower confidence for example domains
        if ioc_type == IOCType.DOMAIN:
            if 'example' in value.lower() or 'test' in value.lower():
                confidence = max(0.2, confidence - 0.4)
        
        return round(confidence, 2)
    
    def _extract_ttps(self, content: str) -> list[str]:
        """Extract MITRE ATT&CK technique IDs from content."""
        ttps = set()
        
        # Find all MITRE ATT&CK references
        for match in IOCPatterns.MITRE_ATTACK.finditer(content):
            ttps.add(match.group().upper())
        
        result = sorted(list(ttps))
        if result:
            logger.info(f"TTP extraction: Found {len(result)} MITRE techniques - {result[:10]}")
        return result
    
    def _generate_summary(self, content: str, iocs: list[IOC]) -> str:
        """Generate a brief summary of the report."""
        if not content:
            return "No content extracted from report."
        
        # Count IOCs by type
        type_counts = {}
        for ioc in iocs:
            type_name = ioc.ioc_type.value
            type_counts[type_name] = type_counts.get(type_name, 0) + 1
        
        parts = [f"Extracted {len(iocs)} indicators of compromise."]
        
        if type_counts:
            breakdown = ", ".join(f"{count} {ioc_type}(s)" 
                                  for ioc_type, count in sorted(type_counts.items()))
            parts.append(f"Breakdown: {breakdown}.")
        
        return " ".join(parts)
    
    def _calculate_confidence(self, iocs: list[IOC], ttps: list[str]) -> float:
        """Calculate overall confidence for IOC report processing."""
        if not iocs and not ttps:
            return 0.3
        
        # Base confidence on number and quality of IOCs
        if iocs:
            avg_ioc_confidence = sum(ioc.confidence for ioc in iocs) / len(iocs)
            confidence = 0.5 + (avg_ioc_confidence * 0.3)
        else:
            confidence = 0.4
        
        # Boost for TTPs
        if ttps:
            confidence = min(1.0, confidence + 0.1)
        
        return round(confidence, 2)


# =============================================================================
# MAIN INPUT PROCESSOR
# =============================================================================

class InputProcessor:
    """
    Main input processor that classifies and routes inputs to appropriate handlers.
    """
    
    def __init__(self):
        # Initialize handlers in priority order
        self._handlers = [
            LogSourceHandler(),      # Most specific
            IOCReportHandler(),      # URLs and files
            NaturalLanguageHandler(), # Fallback
        ]
    
    def process(self, input_text: str) -> ProcessedInput:
        """
        Process input and return structured data.
        
        Args:
            input_text: User input (natural language, log source spec, or IOC report)
            
        Returns:
            ProcessedInput with classified type and extracted data
        """
        input_text = input_text.strip()
        
        if not input_text:
            return ProcessedInput(
                input_type=InputType.UNKNOWN,
                original_input=input_text,
                confidence=0.0,
                warnings=["Empty input provided"],
            )
        
        # Try each handler in order
        for handler in self._handlers:
            if handler.can_handle(input_text):
                logger.info(f"Processing with {handler.__class__.__name__}")
                return handler.process(input_text)
        
        # Fallback to unknown
        return ProcessedInput(
            input_type=InputType.UNKNOWN,
            original_input=input_text,
            confidence=0.0,
            warnings=["Could not classify input type"],
        )
    
    def classify(self, input_text: str) -> InputType:
        """
        Classify input type without full processing.
        
        Args:
            input_text: User input
            
        Returns:
            InputType enum value
        """
        input_text = input_text.strip()
        
        for handler in self._handlers:
            if handler.can_handle(input_text):
                if isinstance(handler, LogSourceHandler):
                    return InputType.LOG_SOURCE
                elif isinstance(handler, IOCReportHandler):
                    return InputType.IOC_REPORT
                elif isinstance(handler, NaturalLanguageHandler):
                    return InputType.NATURAL_LANGUAGE
        
        return InputType.UNKNOWN


# =============================================================================
# CLI INTERFACE
# =============================================================================

def main():
    """CLI entry point."""
    import sys
    
    if len(sys.argv) < 2:
        print("""
Splunk SPL Agent - Input Processor
===================================

Usage:
    python input_processor.py process "<input>"      Process and classify input
    python input_processor.py classify "<input>"     Just classify input type
    python input_processor.py extract "<file/url>"   Extract IOCs from file/URL
    python input_processor.py interactive            Interactive mode

Examples:
    # Natural language
    python input_processor.py process "Detect brute force login attempts"
    
    # Log source specification
    python input_processor.py process "index=windows sourcetype=WinEventLog:Security"
    
    # IOC report (URL)
    python input_processor.py process "https://example.com/threat-report.html"
    
    # IOC report (PDF file)
    python input_processor.py process "/path/to/report.pdf"
    
    # Just classify
    python input_processor.py classify "index=main | stats count"
    
    # Extract IOCs
    python input_processor.py extract report.pdf
""")
        sys.exit(0)
    
    command = sys.argv[1].lower()
    processor = InputProcessor()
    
    if command == "process":
        if len(sys.argv) < 3:
            print("Error: input text required")
            sys.exit(1)
        
        input_text = sys.argv[2]
        print(f"\nProcessing: {input_text[:100]}{'...' if len(input_text) > 100 else ''}\n")
        
        result = processor.process(input_text)
        
        print(f"Input Type: {result.input_type.value}")
        print(f"Confidence: {result.confidence:.2f}")
        
        if result.warnings:
            print(f"Warnings: {', '.join(result.warnings)}")
        
        if result.input_type == InputType.NATURAL_LANGUAGE:
            print(f"\nIntent: {result.intent}")
            print(f"Entities: {', '.join(result.entities) if result.entities else 'None'}")
        
        elif result.input_type == InputType.LOG_SOURCE:
            ls = result.log_source
            print(f"\nLog Source Specification:")
            print(f"  Index: {ls.index or 'Not specified'}")
            print(f"  Sourcetype: {ls.sourcetype or 'Not specified'}")
            print(f"  Source: {ls.source or 'Not specified'}")
            print(f"  Host: {ls.host or 'Not specified'}")
        
        elif result.input_type == InputType.IOC_REPORT:
            print(f"\nReport Title: {result.report_title}")
            print(f"Summary: {result.report_summary}")
            
            if result.ttps:
                print(f"\nMITRE ATT&CK Techniques: {', '.join(result.ttps)}")
            
            if result.iocs:
                print(f"\nExtracted IOCs ({len(result.iocs)}):")
                for ioc in result.iocs[:20]:  # Limit display
                    print(f"  [{ioc.confidence:.2f}] {ioc.ioc_type.value}: {ioc.value}")
                if len(result.iocs) > 20:
                    print(f"  ... and {len(result.iocs) - 20} more")
    
    elif command == "classify":
        if len(sys.argv) < 3:
            print("Error: input text required")
            sys.exit(1)
        
        input_text = sys.argv[2]
        input_type = processor.classify(input_text)
        print(f"Input Type: {input_type.value}")
    
    elif command == "extract":
        if len(sys.argv) < 3:
            print("Error: file or URL required")
            sys.exit(1)
        
        input_text = sys.argv[2]
        result = processor.process(input_text)
        
        if result.input_type != InputType.IOC_REPORT:
            print("Error: Input is not recognized as an IOC report")
            sys.exit(1)
        
        print(f"\nReport: {result.report_title}")
        print(f"Summary: {result.report_summary}")
        
        if result.ttps:
            print(f"\nMITRE ATT&CK Techniques:")
            for ttp in result.ttps:
                print(f"  - {ttp}")
        
        if result.iocs:
            print(f"\nExtracted IOCs ({len(result.iocs)}):")
            print("-" * 60)
            
            # Group by type
            by_type = {}
            for ioc in result.iocs:
                type_name = ioc.ioc_type.value
                if type_name not in by_type:
                    by_type[type_name] = []
                by_type[type_name].append(ioc)
            
            for type_name, iocs in sorted(by_type.items()):
                print(f"\n{type_name.upper()} ({len(iocs)}):")
                for ioc in iocs:
                    print(f"  [{ioc.confidence:.2f}] {ioc.value}")
        else:
            print("\nNo IOCs extracted")
    
    elif command == "interactive":
        print("\nSplunk SPL Agent - Input Processor")
        print("Type 'quit' to exit\n")
        
        while True:
            try:
                input_text = input("Input> ").strip()
                
                if not input_text:
                    continue
                
                if input_text.lower() == "quit":
                    break
                
                result = processor.process(input_text)
                
                print(f"\nType: {result.input_type.value} (confidence: {result.confidence:.2f})")
                
                if result.input_type == InputType.NATURAL_LANGUAGE:
                    print(f"Intent: {result.intent}")
                    if result.entities:
                        print(f"Entities: {', '.join(result.entities)}")
                
                elif result.input_type == InputType.LOG_SOURCE:
                    ls = result.log_source
                    parts = []
                    if ls.index:
                        parts.append(f"index={ls.index}")
                    if ls.sourcetype:
                        parts.append(f"sourcetype={ls.sourcetype}")
                    print(f"Parsed: {' '.join(parts)}")
                
                elif result.input_type == InputType.IOC_REPORT:
                    print(f"IOCs: {len(result.iocs)}")
                    if result.ttps:
                        print(f"TTPs: {', '.join(result.ttps)}")
                
                print()
                
            except KeyboardInterrupt:
                print("\n")
                break
            except Exception as e:
                print(f"Error: {e}\n")
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
