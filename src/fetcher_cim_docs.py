#!/usr/bin/env python3
"""
Splunk CIM Documentation Fetcher (Smart Update)
================================================

Smart fetcher for Splunk Common Information Model (CIM) documentation
with automatic version checking.

Features:
- Automatic version detection from Splunk CIM docs
- Smart updates: only downloads when newer version available
- Parses all CIM data model field definitions
- JSON Lines output for RAG integration

Commands:
    python -m src.fetcher_cim_docs              # Smart update (download if needed)
    python -m src.fetcher_cim_docs check        # Check for updates
    python -m src.fetcher_cim_docs force        # Force re-download
    python -m src.fetcher_cim_docs stats        # Show local data statistics

Dependencies:
    pip install playwright beautifulsoup4 lxml httpx
    playwright install chromium
"""

import asyncio
import json
import re
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

try:
    from playwright.async_api import async_playwright, Page, Browser
except ImportError:
    print("Playwright not installed. Run: pip install playwright && playwright install chromium")
    raise

from bs4 import BeautifulSoup


# =============================================================================
# VERSION CONFIGURATION
# =============================================================================

# CIM version - 6.3 is latest as of Jan 2026
DEFAULT_VERSION = "6.3"
MAX_MAJOR_VERSION = 8
MAX_MINOR_VERSION = 9

# Data model categories to crawl
# Note: Some data models contain multiple sub-models (e.g., 'endpoint' contains
# Ports, Processes, Services, Filesystem, Registry as sub-sections)
# URL slugs verified from: https://help.splunk.com/en/data-management/common-information-model/
CIM_DATA_MODELS = [
    "alerts",
    "authentication",
    "certificates",
    "change",
    "data-access",
    "databases",
    "data-loss-prevention",   # DLP - full name in URL
    "email",
    "endpoint",               # Contains: Ports, Processes, Services, Filesystem, Registry
    "interprocess-messaging",
    "intrusion-detection",
    "java-virtual-machines-jvm",  # JVM - plural with suffix
    "malware",
    "network-resolution-dns",
    "network-sessions",
    "network-traffic",
    "performance",
    "splunk-audit-logs",
    "ticket-management",
    "updates",
    # Note: "user-login-activity" / "ueba" don't exist as CIM data models
    # User login data is covered by the "authentication" data model
    "vulnerabilities",
    "web",
]

STATS_FILE = "splunk_cim_docs.stats.json"
DATA_FILE = "splunk_cim_docs.jsonl"

BASE_URL = "https://help.splunk.com/en/data-management/common-information-model"


def get_seed_urls(version: str = DEFAULT_VERSION) -> list[str]:
    """Generate seed URLs for CIM data models for a specific version."""
    urls = [f"{BASE_URL}/{version}/data-models/{model}" for model in CIM_DATA_MODELS]
    # Add the main data models index
    urls.insert(0, f"{BASE_URL}/{version}/data-models")
    return urls


# =============================================================================
# VERSION DETECTION
# =============================================================================

def generate_versions() -> list[str]:
    """Generate version list starting from DEFAULT_VERSION going forward."""
    versions = []
    major, minor = map(int, DEFAULT_VERSION.split('.'))
    
    while major <= MAX_MAJOR_VERSION:
        while minor <= MAX_MINOR_VERSION:
            versions.append(f"{major}.{minor}")
            minor += 1
        major += 1
        minor = 0
    
    return versions


async def detect_latest_version() -> tuple[str, bool]:
    """
    Detect the latest available CIM documentation version.
    
    Returns:
        Tuple of (version, success)
    """
    import httpx
    
    print(f"[*] Checking for latest CIM documentation version (starting from {DEFAULT_VERSION})...")
    
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    
    latest_found = DEFAULT_VERSION
    consecutive_failures = 0
    
    for version in generate_versions():
        test_url = f"{BASE_URL}/{version}/data-models/alerts"
        
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=10.0, headers=headers) as client:
                response = await client.get(test_url)
                final_url = str(response.url)
                
                if response.status_code == 200 and f"/{version}/" in final_url:
                    print(f"    ✓ {version} exists")
                    latest_found = version
                    consecutive_failures = 0
                else:
                    consecutive_failures += 1
                    if consecutive_failures >= 2:
                        break
        except Exception as e:
            consecutive_failures += 1
            if consecutive_failures >= 2:
                break
    
    print(f"[+] Latest available version: {latest_found}")
    return latest_found, True


# =============================================================================
# DATA MODELS
# =============================================================================

@dataclass
class CIMField:
    """A field definition from CIM."""
    name: str
    data_type: str
    description: str
    required: bool = False
    multi_value: bool = False
    example: str = ""
    constraints: list[str] = field(default_factory=list)


@dataclass
class CIMDataModel:
    """A CIM data model with its fields."""
    name: str
    display_name: str
    description: str
    version: str
    url: str
    fields: list[CIMField] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "version": self.version,
            "url": self.url,
            "tags": self.tags,
            "fields": [
                {
                    "name": f.name,
                    "data_type": f.data_type,
                    "description": f.description,
                    "required": f.required,
                    "multi_value": f.multi_value,
                    "example": f.example,
                    "constraints": f.constraints,
                }
                for f in self.fields
            ],
        }
    
    def to_chunks(self) -> list[dict]:
        """Convert to RAG-friendly chunks."""
        chunks = []
        
        # Main data model chunk
        field_list = "\n".join(
            f"- {f.name} ({f.data_type}): {f.description}"
            for f in self.fields[:10]
        )
        
        main_chunk = {
            "id": f"cim_{self.name}_overview",
            "data_model": self.name,
            "display_name": self.display_name,
            "type": "overview",
            "content": (
                f"CIM Data Model: {self.display_name}\n\n"
                f"{self.description}\n\n"
                f"Available fields ({len(self.fields)} total):\n{field_list}"
            ),
            "url": self.url,
            "version": self.version,
        }
        chunks.append(main_chunk)
        
        # Field chunks (group by 5 fields)
        for i in range(0, len(self.fields), 5):
            field_group = self.fields[i:i+5]
            field_content = "\n\n".join(
                f"**{f.name}** ({f.data_type})\n"
                f"Description: {f.description}\n"
                f"Required: {'Yes' if f.required else 'No'}\n"
                f"Multi-value: {'Yes' if f.multi_value else 'No'}"
                + (f"\nExample: {f.example}" if f.example else "")
                for f in field_group
            )
            
            chunk = {
                "id": f"cim_{self.name}_fields_{i//5}",
                "data_model": self.name,
                "display_name": self.display_name,
                "type": "fields",
                "content": (
                    f"CIM Data Model: {self.display_name} - Fields\n\n"
                    f"{field_content}"
                ),
                "url": self.url,
                "version": self.version,
                "field_names": [f.name for f in field_group],
            }
            chunks.append(chunk)
        
        return chunks


# =============================================================================
# PARSER
# =============================================================================

def parse_cim_page(html: str, url: str, version: str) -> list[CIMDataModel]:
    """
    Parse a CIM data model page and extract field definitions.
    
    Handles both single-model pages and multi-model pages (like 'endpoint'
    which contains Ports, Processes, Services, Filesystem, Registry).
    
    Args:
        html: HTML content of the page
        url: URL of the page
        version: CIM version
        
    Returns:
        List of CIMDataModel objects (may be multiple for pages with sub-sections)
    """
    soup = BeautifulSoup(html, 'lxml')
    
    # Extract base model name from URL
    base_model_name = url.rstrip('/').split('/')[-1]
    
    # Check for multi-section pages (nested articles with h2 titles)
    # These have sections like: Ports, Processes, Services, etc.
    nested_sections = soup.find_all('article', class_='nested1')
    
    # Also look for sections with h2 headers that have field tables
    if not nested_sections:
        nested_sections = soup.find_all('section', id=True)
    
    # If we have multiple sections with their own tables, parse each separately
    data_models = []
    
    if nested_sections:
        for section in nested_sections:
            # Get section title
            h2 = section.find(['h2', 'h3'])
            if not h2:
                continue
            
            section_name = h2.get_text(strip=True)
            
            # Skip non-data-model sections (like "Overview", "Introduction", etc.)
            skip_titles = [
                'overview', 'introduction', 'about', 'example', 'description',
                'difference', 'fields for', 'search example', 'constraint', 
                'accelerate', 'tags', 'event type'
            ]
            if any(skip in section_name.lower() for skip in skip_titles):
                continue
            
            # Parse fields from tables in this section
            fields = parse_fields_from_element(section)
            
            if fields:
                # Create a sub-model name
                sub_model_name = f"{base_model_name}_{section_name.lower().replace(' ', '_')}"
                
                # Get section description
                section_desc = ""
                first_p = section.find('p')
                if first_p:
                    section_desc = first_p.get_text(strip=True)
                
                data_model = CIMDataModel(
                    name=sub_model_name,
                    display_name=section_name,
                    description=section_desc,
                    url=url,
                    version=version,
                    fields=fields,
                )
                data_models.append(data_model)
    
    # If no sub-sections found, or no fields in sub-sections, parse whole page
    if not data_models:
        # Get page title
        title_elem = soup.find('h1')
        display_name = title_elem.get_text(strip=True) if title_elem else base_model_name.replace('-', ' ').title()
        
        # Get description (first paragraph after title)
        description = ""
        main_content = soup.find('main') or soup.find('article') or soup
        first_p = main_content.find('p')
        if first_p:
            description = first_p.get_text(strip=True)
        
        # Parse all fields from the page
        fields = parse_fields_from_element(soup)
        
        if fields:
            data_model = CIMDataModel(
                name=base_model_name,
                display_name=display_name,
                description=description,
                url=url,
                version=version,
                fields=fields,
            )
            data_models.append(data_model)
    
    return data_models


def parse_fields_from_element(element) -> list[CIMField]:
    """
    Parse CIM fields from tables within an HTML element.
    
    Handles various Splunk CIM table formats including:
    - Standard tables with "Field name", "Data type", "Description" columns
    - Tables with "Dataset field name" column containing full paths like "Alerts.action"
    - Tables where field names might be in different column positions
    
    Args:
        element: BeautifulSoup element to search for tables
        
    Returns:
        List of CIMField objects
    """
    fields = []
    seen_field_names = set()  # Track duplicates
    tables = element.find_all('table')
    
    for table in tables:
        # Look for field definition tables
        header_row = table.find('tr')
        if not header_row:
            continue
            
        headers = [th.get_text(strip=True).lower() for th in header_row.find_all(['th', 'td'])]
        
        # Check if this is a field definition table
        if not headers:
            continue
        
        # Find column indices - check multiple possible header names
        # Splunk CIM uses various column names: "field name", "dataset field name", etc.
        name_idx = None
        for i, h in enumerate(headers):
            # Look for field name column (but not "data type" which also contains "type")
            if ('field' in h and 'type' not in h) or h == 'name' or h == 'field':
                name_idx = i
                break
        
        type_idx = next((i for i, h in enumerate(headers) if 'type' in h or 'data type' in h), None)
        desc_idx = next((i for i, h in enumerate(headers) if 'description' in h or 'desc' in h), None)
        req_idx = next((i for i, h in enumerate(headers) if 'required' in h or 'req' in h), None)
        
        # If no obvious field name column found, try first column
        if name_idx is None and len(headers) >= 2:
            name_idx = 0
        
        if name_idx is None:
            continue
        
        # Parse rows
        for row in table.find_all('tr')[1:]:  # Skip header
            cells = row.find_all(['td', 'th'])
            if len(cells) <= name_idx:
                continue
            
            # Extract field name from the cell
            raw_field_name = cells[name_idx].get_text(strip=True) if name_idx < len(cells) else ""
            
            # Handle hierarchical field names like "Alerts.action" -> "action"
            if '.' in raw_field_name:
                field_name = raw_field_name.split('.')[-1]
            else:
                field_name = raw_field_name
            
            data_type = cells[type_idx].get_text(strip=True) if type_idx and type_idx < len(cells) else "string"
            field_desc = cells[desc_idx].get_text(strip=True) if desc_idx and desc_idx < len(cells) else ""
            
            # If the field name looks like a data model name (repeated), try to extract from description
            # Common patterns: "The <field_name> ...", "<field_name> is ..."
            if field_name and field_desc:
                # If field name matches a data model pattern (single capitalized word repeated)
                # and description starts with "The ", try to extract actual field name
                if field_name[0].isupper() and field_name.isalpha() and len(field_name) > 3:
                    # Check if this looks like a data model name being repeated
                    # Try to extract field name from description
                    import re
                    
                    # Pattern 1: "The <field_name> ..." at start
                    match = re.match(r'^The\s+([a-z_]+)\s+', field_desc, re.IGNORECASE)
                    if match:
                        extracted = match.group(1).lower().replace(' ', '_')
                        if len(extracted) >= 2 and extracted not in ('the', 'this', 'that', 'field'):
                            field_name = extracted
                    
                    # Pattern 2: Look for common field name patterns in description
                    if not match:
                        # Look for field-like names in the first sentence
                        common_field_patterns = [
                            r'(?:for\s+the\s+|named\s+|called\s+)(\w+)',
                            r'(\w+)\s+(?:field|value|attribute)',
                        ]
                        for pattern in common_field_patterns:
                            match = re.search(pattern, field_desc[:100], re.IGNORECASE)
                            if match:
                                extracted = match.group(1).lower()
                                if len(extracted) >= 2 and extracted not in ('the', 'this', 'that', 'field'):
                                    field_name = extracted
                                    break
            
            # Check if required
            required = False
            if req_idx and req_idx < len(cells):
                req_text = cells[req_idx].get_text(strip=True).lower()
                required = req_text in ('yes', 'true', 'required', '✓', '✔')
            
            # Skip invalid field names and duplicates
            if field_name and not field_name.startswith('---') and field_name not in seen_field_names:
                # Clean up field name
                field_name = field_name.strip().lower().replace(' ', '_')
                
                # Skip if it's just a data model name or too generic
                skip_names = {'alerts', 'processes', 'authentication', 'network', 'endpoint', 
                             'string', 'number', 'boolean', 'multi-value', 'integer'}
                if field_name in skip_names:
                    continue
                
                field = CIMField(
                    name=field_name,
                    data_type=data_type,
                    description=field_desc,
                    required=required,
                )
                fields.append(field)
                seen_field_names.add(field_name)
    
    return fields
    
    # Also look for fields in definition lists
    dls = soup.find_all('dl')
    for dl in dls:
        dts = dl.find_all('dt')
        dds = dl.find_all('dd')
        
        for dt, dd in zip(dts, dds):
            field_name = dt.get_text(strip=True)
            field_desc = dd.get_text(strip=True)
            
            if field_name and not any(f.name == field_name for f in fields):
                field = CIMField(
                    name=field_name,
                    data_type="string",
                    description=field_desc,
                )
                fields.append(field)
    
    if not fields:
        return None
    
    return CIMDataModel(
        name=model_name,
        display_name=display_name,
        description=description,
        version=version,
        url=url,
        fields=fields,
    )


# =============================================================================
# CRAWLER
# =============================================================================

async def crawl_cim_docs(
    version: str = DEFAULT_VERSION,
    output_dir: Path = Path("data"),
    delay: float = 1.0,
) -> dict:
    """
    Crawl CIM documentation for all data models.
    
    Args:
        version: CIM version to crawl
        output_dir: Directory for output files
        delay: Delay between requests in seconds
        
    Returns:
        Statistics dictionary
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    data_models = []
    all_chunks = []
    failed_urls = []
    
    print("=" * 70)
    print("SPLUNK CIM DOCUMENTATION CRAWLER")
    print("=" * 70)
    print(f"Version: {version}")
    print(f"Data models to crawl: {len(CIM_DATA_MODELS)}")
    print(f"Output directory: {output_dir}")
    print("=" * 70)
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        
        for i, model in enumerate(CIM_DATA_MODELS, 1):
            url = f"{BASE_URL}/{version}/data-models/{model}"
            print(f"[{i}/{len(CIM_DATA_MODELS)}] {model}...")
            
            try:
                await page.goto(url, wait_until="networkidle", timeout=30000)
                await asyncio.sleep(delay)
                
                html = await page.content()
                parsed_models = parse_cim_page(html, url, version)
                
                if parsed_models:
                    total_fields = 0
                    total_chunks = 0
                    for dm in parsed_models:
                        data_models.append(dm)
                        chunks = dm.to_chunks()
                        all_chunks.extend(chunks)
                        total_fields += len(dm.fields)
                        total_chunks += len(chunks)
                    
                    # Show what was parsed
                    if len(parsed_models) == 1:
                        dm = parsed_models[0]
                        print(f"    ✓ {dm.display_name}: {len(dm.fields)} fields, {len(dm.to_chunks())} chunks")
                    else:
                        print(f"    ✓ {len(parsed_models)} sub-models: {total_fields} fields, {total_chunks} chunks")
                        for dm in parsed_models:
                            print(f"        - {dm.display_name}: {len(dm.fields)} fields")
                else:
                    print(f"    ✗ No fields found")
                    failed_urls.append(url)
                    
            except Exception as e:
                print(f"    ✗ Error: {e}")
                failed_urls.append(url)
        
        await browser.close()
    
    # Save JSON Lines file
    jsonl_path = output_dir / DATA_FILE
    with open(jsonl_path, 'w', encoding='utf-8') as f:
        for chunk in all_chunks:
            f.write(json.dumps(chunk, ensure_ascii=False) + '\n')
    print(f"\nJSON Lines file: {jsonl_path}")
    
    # Save stats
    total_fields = sum(len(dm.fields) for dm in data_models)
    stats = {
        "version": version,
        "total_data_models": len(data_models),
        "total_fields": total_fields,
        "total_chunks": len(all_chunks),
        "failed_urls": len(failed_urls),
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "source": BASE_URL,
        "data_models": [dm.name for dm in data_models],
    }
    
    stats_path = output_dir / STATS_FILE
    with open(stats_path, 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2)
    print(f"[+] Stats saved to {stats_path}")
    
    print("=" * 70)
    print("CRAWL COMPLETE")
    print("=" * 70)
    print(f"Data models: {len(data_models)}")
    print(f"Total fields: {total_fields}")
    print(f"Total chunks: {len(all_chunks)}")
    print(f"Failed URLs: {len(failed_urls)}")
    print("=" * 70)
    
    return stats


# =============================================================================
# SMART UPDATE
# =============================================================================

async def smart_update(output_dir: Path = Path("data"), force: bool = False) -> bool:
    """
    Perform smart update: check version and download if needed.
    
    Args:
        output_dir: Directory for output files
        force: Force download even if up to date
        
    Returns:
        True if update was performed
    """
    output_dir = Path(output_dir)
    stats_path = output_dir / STATS_FILE
    data_path = output_dir / DATA_FILE
    
    print("=" * 70)
    print("SPLUNK CIM DOCUMENTATION - SMART UPDATE")
    print("=" * 70)
    
    # Detect latest version
    latest_version, success = await detect_latest_version()
    
    # Check local version
    local_version = None
    local_chunks = 0
    
    if stats_path.exists():
        try:
            with open(stats_path, 'r') as f:
                local_stats = json.load(f)
            local_version = local_stats.get("version")
            local_chunks = local_stats.get("total_chunks", 0)
            print(f"Local file exists: True")
            print(f"Local version: {local_version} ({local_chunks} chunks)")
            print(f"Last updated: {local_stats.get('last_updated', 'Unknown')}")
        except Exception as e:
            print(f"Local file exists: True (error reading: {e})")
    else:
        print(f"Local file exists: False")
    
    print(f"Remote version: {latest_version}")
    
    # Determine if update needed
    needs_update = False
    reason = ""
    
    if force:
        needs_update = True
        reason = "Force mode"
    elif not data_path.exists():
        needs_update = True
        reason = "No local data found"
    elif local_chunks == 0:
        needs_update = True
        reason = "Local data is empty (0 chunks)"
    elif local_version and local_version != latest_version:
        # Compare versions
        try:
            local_parts = list(map(int, local_version.split('.')))
            remote_parts = list(map(int, latest_version.split('.')))
            if remote_parts > local_parts:
                needs_update = True
                reason = f"Newer version available ({local_version} → {latest_version})"
        except ValueError:
            needs_update = True
            reason = "Version comparison failed"
    
    print(f"Update available: {needs_update}")
    if reason:
        print(f"Reason: {reason}")
    
    if needs_update:
        print(f"\n[*] Downloading version {latest_version}...")
        await crawl_cim_docs(version=latest_version, output_dir=output_dir)
        return True
    else:
        print("\n[✓] Already up to date!")
        return False


# =============================================================================
# CLI
# =============================================================================

def print_stats(output_dir: Path = Path("data")):
    """Print local data statistics."""
    stats_path = output_dir / STATS_FILE
    
    if not stats_path.exists():
        print("No local CIM data found. Run 'python -m src.fetcher_cim_docs' to download.")
        return
    
    with open(stats_path, 'r') as f:
        stats = json.load(f)
    
    print("\nSplunk CIM Documentation - Local Data")
    print("=" * 50)
    print(f"Version: {stats.get('version', 'Unknown')}")
    print(f"Data Models: {stats.get('total_data_models', 0)}")
    print(f"Total Fields: {stats.get('total_fields', 0)}")
    print(f"Total Chunks: {stats.get('total_chunks', 0)}")
    print(f"Last Updated: {stats.get('last_updated', 'Unknown')}")
    print(f"Source: {stats.get('source', 'Unknown')}")
    
    if stats.get('data_models'):
        print(f"\nData Models Included:")
        for dm in stats['data_models']:
            print(f"  - {dm}")
    print("=" * 50)


def main():
    """CLI entry point."""
    import sys
    
    output_dir = Path("data")
    
    # Default command if no args or args start with --
    if len(sys.argv) < 2 or sys.argv[1].startswith('--'):
        asyncio.run(smart_update(output_dir=output_dir))
        return
    
    command = sys.argv[1].lower()
    
    if command == "check":
        latest_version, _ = asyncio.run(detect_latest_version())
        
        # Show local info
        stats_path = output_dir / STATS_FILE
        local_version = None
        local_chunks = 0
        
        if stats_path.exists():
            with open(stats_path, 'r') as f:
                stats = json.load(f)
            local_version = stats.get('version')
            local_chunks = stats.get('total_chunks', 0)
            print(f"\nLocal version: {local_version}")
            print(f"Local chunks: {local_chunks}")
            if stats.get('last_updated'):
                print(f"Last updated: {stats.get('last_updated')}")
        else:
            print("\n[!] No local data found")
        
        # Determine if update needed
        print()
        if not local_version or local_chunks == 0:
            print("[!] Update available: No local data found")
            print("    Run 'python -m src.fetcher_cim_docs' to update.")
        elif local_version != latest_version:
            print(f"[!] Update available: {local_version} → {latest_version}")
            print("    Run 'python -m src.fetcher_cim_docs' to update.")
        else:
            print("[✓] Already up to date.")
    
    elif command == "force":
        asyncio.run(smart_update(output_dir=output_dir, force=True))
    
    elif command == "version":
        # Download a specific version
        if len(sys.argv) < 3:
            print("Error: version number required")
            print("Usage: python -m src.fetcher_cim_docs version 6.3")
            sys.exit(1)
        
        version = sys.argv[2]
        print(f"[*] Downloading CIM version {version}...")
        asyncio.run(crawl_cim_docs(output_dir=output_dir, version=version))
    
    elif command == "stats":
        print_stats(output_dir)
    
    elif command == "help" or command == "--help":
        print("""
Splunk CIM Documentation Fetcher (Smart Update)
================================================

Commands:
    python -m src.fetcher_cim_docs              Smart update (download if needed)
    python -m src.fetcher_cim_docs check        Check for updates
    python -m src.fetcher_cim_docs force        Force re-download
    python -m src.fetcher_cim_docs version 6.3  Download specific version
    python -m src.fetcher_cim_docs stats        Show local data statistics
    python -m src.fetcher_cim_docs help         Show this help

Output:
    data/splunk_cim_docs.jsonl      CIM field definitions for RAG
    data/splunk_cim_docs.stats.json Version and statistics
""")
    
    else:
        print(f"Unknown command: {command}")
        print("Run 'python -m src.fetcher_cim_docs help' for usage.")
        sys.exit(1)


if __name__ == "__main__":
    main()
