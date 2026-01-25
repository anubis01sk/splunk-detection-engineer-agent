#!/usr/bin/env python3
"""
Splunk Documentation Fetcher (Smart Update)
============================================

Smart fetcher for Splunk SPL documentation with automatic version checking.

Features:
- Automatic version detection from Splunk docs
- Smart updates: only downloads when newer version available
- Local cache with version tracking
- Multiple output formats (JSON Lines for RAG)

Commands:
    python -m src.fetcher_spl_docs              # Smart update (download if needed)
    python -m src.fetcher_spl_docs check        # Check for updates
    python -m src.fetcher_spl_docs force        # Force re-download
    python -m src.fetcher_spl_docs crawl        # Legacy crawl command

Dependencies:
    pip install playwright beautifulsoup4 lxml httpx
    playwright install chromium
"""

import asyncio
import hashlib
import json
import re
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

try:
    from playwright.async_api import async_playwright, Page, Browser, BrowserContext
except ImportError:
    print("Playwright not installed. Run: pip install playwright && playwright install chromium")
    raise

from src.parser_spl_docs import (
    SplunkDocScraper,
    SplunkDocument,
    URLPatterns,
    SELECTORS,
    MAX_CHUNK_CHARS,
    MIN_CHUNK_CHARS,
)


# =============================================================================
# VERSION CONFIGURATION
# =============================================================================

# Version detection: starts from DEFAULT_VERSION and checks forward
# Checks: 10.2 → 10.3 → ... → 10.9 → 11.0 → 11.1 → ...
DEFAULT_VERSION = "10.2"
MAX_MAJOR_VERSION = 12  # Stop checking at this major version
MAX_MINOR_VERSION = 9   # Check up to X.9 before moving to next major

# Stats file for tracking local version
STATS_FILE = "splunk_spl_docs.stats.json"
DATA_FILE = "splunk_spl_docs.jsonl"


def get_seed_urls(version: str = DEFAULT_VERSION) -> list[str]:
    """Generate seed URLs for a specific documentation version.
    
    Includes both Search Manual and SPL Search Reference sections.
    These are index pages that contain sidebar navigation with all links.
    """
    base = "https://help.splunk.com/en/splunk-enterprise/search"
    return [
        # Search Manual - main sections (sidebar will have all sub-pages)
        f"{base}/search-manual/{version}/search-overview/get-started-with-search",
        f"{base}/search-manual/{version}/search-primer/search-command-primer",
        f"{base}/search-manual/{version}/optimize-searches/about-search-optimization",
        
        # SPL Search Reference - main index and key sections
        f"{base}/spl-search-reference/{version}",  # Main index
        f"{base}/spl-search-reference/{version}/introduction/welcome-to-the-search-reference",
        f"{base}/spl-search-reference/{version}/quick-reference/splunk-quick-reference-guide",
        f"{base}/spl-search-reference/{version}/evaluation-functions/evaluation-functions",
        f"{base}/spl-search-reference/{version}/statistical-and-charting-functions/statistical-and-charting-functions",
        f"{base}/spl-search-reference/{version}/search-commands/abstract",  # First command, sidebar has all
    ]


def get_allowed_paths(version: str = DEFAULT_VERSION) -> list[str]:
    """Generate allowed path prefixes for a specific version."""
    return [
        f"/en/splunk-enterprise/search/spl-search-reference/{version}/",
        f"/en/splunk-enterprise/search/search-manual/{version}/",
    ]


# =============================================================================
# VERSION DETECTION
# =============================================================================

def generate_versions() -> list[str]:
    """
    Generate version list starting from DEFAULT_VERSION going forward.
    
    Example: 10.2 → 10.3 → 10.4 → ... → 10.9 → 11.0 → 11.1 → ...
    """
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
    Detect the latest available Splunk documentation version.
    
    Checks incrementally from DEFAULT_VERSION forward (10.2 → 10.3 → 10.4 → ...)
    and returns the highest available version.
    
    Returns:
        Tuple of (version, success)
    """
    import httpx
    
    print(f"[*] Checking for latest Splunk documentation version (starting from {DEFAULT_VERSION})...")
    
    # Browser headers - Splunk redirects non-browser requests to /upgrade_browser
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    
    latest_found = DEFAULT_VERSION
    consecutive_failures = 0
    
    # Check versions incrementally: 10.2 → 10.3 → 10.4 → ...
    for version in generate_versions():
        test_url = f"https://help.splunk.com/en/splunk-enterprise/search/search-manual/{version}/search-primer/search-command-primer"
        
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
                    # Stop after 2 consecutive failures (no more versions in this sequence)
                    if consecutive_failures >= 2:
                        break
        except Exception:
            consecutive_failures += 1
            if consecutive_failures >= 2:
                break
    
    print(f"[+] Latest available version: {latest_found}")
    return latest_found, True


def get_local_version(data_dir: Path) -> Optional[dict]:
    """
    Get local version info from stats file.
    
    Returns:
        Dict with version info or None if not found
    """
    stats_path = data_dir / STATS_FILE
    
    if not stats_path.exists():
        return None
    
    try:
        with open(stats_path, 'r') as f:
            return json.load(f)
    except Exception:
        return None


def save_stats(data_dir: Path, version: str, total_pages: int, total_chunks: int):
    """Save version and statistics to stats file."""
    stats_path = data_dir / STATS_FILE
    
    stats = {
        "version": version,
        "total_pages": total_pages,
        "total_chunks": total_chunks,
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "source": "help.splunk.com"
    }
    
    with open(stats_path, 'w') as f:
        json.dump(stats, f, indent=2)
    
    print(f"[+] Stats saved to {stats_path}")


def compare_versions(local: str, remote: str) -> int:
    """
    Compare two version strings.
    
    Returns:
        -1 if local < remote (update available)
        0 if local == remote (up to date)
        1 if local > remote (local is newer)
    """
    def parse_version(v: str) -> tuple:
        parts = v.split('.')
        return tuple(int(p) for p in parts)
    
    try:
        local_parts = parse_version(local)
        remote_parts = parse_version(remote)
        
        if local_parts < remote_parts:
            return -1
        elif local_parts > remote_parts:
            return 1
        else:
            return 0
    except ValueError:
        return 0  # Can't compare, assume equal


# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class CrawlConfig:
    """Configuration for the crawler."""
    output_dir: str = "data"
    save_html: bool = False
    save_json: bool = True
    save_markdown: bool = True
    save_jsonl: bool = True
    jsonl_filename: str = DATA_FILE
    max_pages: int = 500
    max_depth: int = 10
    delay_between_pages: float = 2.0
    page_load_timeout: int = 60000
    network_idle_timeout: int = 30000
    scroll_delay_ms: int = 300
    max_scrolls: int = 20
    base_url: str = "https://help.splunk.com"
    allowed_path_prefixes: list[str] = field(default_factory=lambda: get_allowed_paths(DEFAULT_VERSION))
    headless: bool = True
    viewport_width: int = 1920
    viewport_height: int = 1080
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
    version: str = DEFAULT_VERSION  # Splunk docs version


@dataclass
class CrawlResult:
    """Result of crawling a single page."""
    url: str
    title: str
    chunks: list[dict]
    links: list[str]
    success: bool
    error: Optional[str] = None
    duration: float = 0.0


@dataclass
class CrawlStats:
    """Statistics from a crawl session."""
    pages_crawled: int = 0
    pages_failed: int = 0
    pages_skipped: int = 0
    total_chunks: int = 0
    total_links: int = 0
    duration: float = 0.0


# =============================================================================
# CRAWLER
# =============================================================================

class SplunkCrawler:
    """
    Async crawler for Splunk documentation.
    
    Uses Playwright for JavaScript-rendered content and implements
    BFS traversal with depth limiting.
    """
    
    def __init__(self, config: CrawlConfig):
        self.config = config
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._page: Optional[Page] = None
        self._playwright = None
        self._visited: set[str] = set()
        self._all_chunks: list[dict] = []
        self._stats = CrawlStats()
    
    async def __aenter__(self):
        """Async context manager entry."""
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(headless=self.config.headless)
        self._context = await self._browser.new_context(
            viewport={"width": self.config.viewport_width, "height": self.config.viewport_height},
            user_agent=self.config.user_agent,
        )
        self._page = await self._context.new_page()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._page:
            await self._page.close()
        if self._context:
            await self._context.close()
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL for deduplication."""
        parsed = urlparse(url)
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        return normalized.rstrip('/')
    
    def _is_allowed_url(self, url: str) -> bool:
        """Check if URL is within allowed scope."""
        if not url.startswith(self.config.base_url):
            # Also allow shortened help.splunk.com URLs
            if not url.startswith("https://help.splunk.com/en/"):
                return False
        
        parsed = urlparse(url)
        path = parsed.path
        
        # Check for version-specific paths
        for prefix in self.config.allowed_path_prefixes:
            if prefix in path:
                return True
        
        # Also allow generic search reference pages (resourceId style)
        if "resourceId=Splunk_Search" in url or "resourceId=SplunkCloud_Search" in url:
            return True
        
        return False
    
    async def _scroll_page(self):
        """Scroll page to load lazy content."""
        for _ in range(self.config.max_scrolls):
            await self._page.evaluate("window.scrollBy(0, window.innerHeight)")
            await asyncio.sleep(self.config.scroll_delay_ms / 1000)
    
    async def _extract_sidebar_links(self) -> list[str]:
        """Extract links from the sidebar navigation menu.
        
        Splunk docs use a tree-view sidebar with role='treeitem' for navigation.
        This is where all the important documentation links are.
        """
        try:
            # Wait for sidebar to load
            await self._page.wait_for_selector('li[role="treeitem"] a', timeout=5000)
            
            # Extract all sidebar links using JavaScript
            sidebar_links = await self._page.evaluate("""
                () => {
                    const links = Array.from(document.querySelectorAll('li[role="treeitem"] a'));
                    return links
                        .map(a => a.href)
                        .filter(href => href && href.includes('help.splunk.com'));
                }
            """)
            return sidebar_links or []
        except Exception:
            # Sidebar might not exist on all pages
            return []
    
    async def _crawl_page(self, url: str) -> CrawlResult:
        """Crawl a single page and extract content."""
        import time
        start_time = time.time()
        
        try:
            await self._page.goto(
                url,
                wait_until="networkidle",
                timeout=self.config.page_load_timeout,
            )
            
            await self._scroll_page()
            
            # Extract sidebar links FIRST (before parsing content)
            sidebar_links = await self._extract_sidebar_links()
            
            html_content = await self._page.content()
            
            scraper = SplunkDocScraper()
            doc = scraper.parse_html(html_content, url)
            
            chunks = []
            for i, section in enumerate(doc.sections):
                chunk = {
                    "id": hashlib.sha256(f"{url}:{i}:{section.title}".encode()).hexdigest()[:16],
                    "content": section.content,
                    "code_examples": [{"language": cb.language, "code": cb.content} for cb in section.code_blocks],
                    "tables": [t.to_dict() for t in section.tables],
                    "chunk_index": i,
                    "total_chunks": len(doc.sections),
                    "metadata": {
                        "title": doc.title,
                        "section_heading": section.title,
                        "section_id": section.id,
                        "url": url,
                        "breadcrumb": doc.breadcrumbs,
                        "manual": "search-manual" if "search-manual" in url else "spl-search-reference",
                        "scraped_at": datetime.now(timezone.utc).isoformat(),
                        "version": self.config.version,
                    }
                }
                chunks.append(chunk)
            
            duration = time.time() - start_time
            
            # Combine sidebar links with content links
            content_links = doc.get_internal_urls()
            all_links = list(set(sidebar_links + content_links))
            
            return CrawlResult(
                url=url,
                title=doc.title,
                chunks=chunks,
                links=all_links,
                success=True,
                duration=duration,
            )
            
        except Exception as e:
            duration = time.time() - start_time
            return CrawlResult(
                url=url,
                title="",
                chunks=[],
                links=[],
                success=False,
                error=str(e),
                duration=duration,
            )
    
    async def crawl(self, seed_urls: Optional[list[str]] = None) -> CrawlStats:
        """
        Crawl documentation starting from seed URLs.
        
        Args:
            seed_urls: Starting URLs (uses default if None)
            
        Returns:
            CrawlStats with crawl statistics
        """
        import time
        
        if seed_urls is None:
            seed_urls = get_seed_urls(self.config.version)
        
        Path(self.config.output_dir).mkdir(parents=True, exist_ok=True)
        
        queue = deque()
        for url in seed_urls:
            queue.append((url, 0))
        
        start_time = time.time()
        page_num = 0
        
        print("=" * 70)
        print("SPLUNK DOCUMENTATION CRAWLER")
        print("=" * 70)
        print(f"Version: {self.config.version}")
        print(f"Seed URLs: {len(seed_urls)}")
        print(f"Max pages: {self.config.max_pages}")
        print(f"Max depth: {self.config.max_depth}")
        print(f"Output directory: {self.config.output_dir}")
        print("=" * 70)
        print()
        
        try:
            while queue and page_num < self.config.max_pages:
                url, depth = queue.popleft()
                
                normalized = self._normalize_url(url)
                if normalized in self._visited:
                    continue
                
                if depth > self.config.max_depth:
                    self._stats.pages_skipped += 1
                    continue
                
                if not self._is_allowed_url(url):
                    self._stats.pages_skipped += 1
                    continue
                
                self._visited.add(normalized)
                page_num += 1
                
                result = await self._crawl_page(url)
                
                if result.success:
                    self._stats.pages_crawled += 1
                    self._stats.total_chunks += len(result.chunks)
                    self._stats.total_links += len(result.links)
                    self._all_chunks.extend(result.chunks)
                    
                    print(f"[{page_num}] Depth {depth}: {url}")
                    print(f"    ✓ {result.title}")
                    print(f"      Chunks: {len(result.chunks)}, Links: {len(result.links)}, Time: {result.duration:.1f}s")
                    
                    for link in result.links:
                        link_normalized = self._normalize_url(link)
                        if link_normalized not in self._visited and self._is_allowed_url(link):
                            queue.append((link, depth + 1))
                else:
                    self._stats.pages_failed += 1
                    print(f"[{page_num}] Depth {depth}: {url}")
                    print(f"    ✗ Error: {result.error}")
                
                if self.config.delay_between_pages > 0:
                    await asyncio.sleep(self.config.delay_between_pages)
        
        except KeyboardInterrupt:
            print("\n[!] Crawl interrupted by user")
        
        self._stats.duration = time.time() - start_time
        
        # Save results
        self._save_results()
        
        return self._stats
    
    def _save_results(self):
        """Save crawl results to files."""
        # Save JSON Lines (for RAG ingestion)
        if self.config.save_jsonl:
            jsonl_path = Path(self.config.output_dir) / self.config.jsonl_filename
            with open(jsonl_path, 'w', encoding='utf-8') as f:
                for chunk in self._all_chunks:
                    f.write(json.dumps(chunk, ensure_ascii=False) + '\n')
            print(f"JSON Lines file: {jsonl_path}")
        
        # Save manifest
        manifest = {
            "version": self.config.version,
            "crawled_at": datetime.now(timezone.utc).isoformat(),
            "stats": {
                "pages_crawled": self._stats.pages_crawled,
                "pages_failed": self._stats.pages_failed,
                "pages_skipped": self._stats.pages_skipped,
                "total_chunks": self._stats.total_chunks,
                "total_links": self._stats.total_links,
                "duration_seconds": self._stats.duration,
            },
            "config": {
                "max_pages": self.config.max_pages,
                "max_depth": self.config.max_depth,
                "version": self.config.version,
            }
        }
        
        manifest_path = Path(self.config.output_dir) / "crawl_manifest.json"
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)
        print(f"Manifest saved: {manifest_path}")
        
        # Save stats file for version tracking
        save_stats(
            Path(self.config.output_dir),
            self.config.version,
            self._stats.pages_crawled,
            self._stats.total_chunks
        )
        
        print()
        print("=" * 70)
        print("CRAWL COMPLETE")
        print("=" * 70)
        print(f"Pages crawled: {self._stats.pages_crawled}")
        print(f"Pages failed: {self._stats.pages_failed}")
        print(f"Pages skipped: {self._stats.pages_skipped}")
        print(f"Total chunks: {self._stats.total_chunks}")
        print(f"Total links found: {self._stats.total_links}")
        print(f"Duration: {self._stats.duration:.1f}s")
        print(f"Output directory: {self.config.output_dir}")
        print(f"JSON Lines file: {self.config.output_dir}/{self.config.jsonl_filename}")
        print("=" * 70)


# =============================================================================
# SMART UPDATE FUNCTIONS
# =============================================================================

async def check_for_updates(data_dir: str = "data") -> dict:
    """
    Check if updates are available for SPL documentation.
    
    Returns:
        Dict with status information
    """
    data_path = Path(data_dir)
    jsonl_path = data_path / DATA_FILE
    
    result = {
        "local_exists": jsonl_path.exists(),
        "local_version": None,
        "local_chunks": 0,
        "local_updated": None,
        "remote_version": None,
        "update_available": False,
    }
    
    # Check local version
    local_info = get_local_version(data_path)
    if local_info:
        result["local_version"] = local_info.get("version")
        result["local_chunks"] = local_info.get("total_chunks", 0)
        result["local_updated"] = local_info.get("last_updated")
    
    # Check remote version
    remote_version, success = await detect_latest_version()
    result["remote_version"] = remote_version
    
    # Determine if update needed
    if not result["local_exists"]:
        result["update_available"] = True
        result["reason"] = "No local data found"
    elif result["local_version"] is None:
        result["update_available"] = True
        result["reason"] = "Local version unknown"
    elif result["local_chunks"] == 0:
        result["update_available"] = True
        result["reason"] = "Local data is empty (0 chunks)"
    elif compare_versions(result["local_version"], remote_version) < 0:
        result["update_available"] = True
        result["reason"] = f"Newer version available: {result['local_version']} → {remote_version}"
    else:
        result["reason"] = "Already up to date"
    
    return result


async def smart_update(
    data_dir: str = "data",
    force: bool = False,
    delay: float = 0.5,
    no_html: bool = True,
    no_markdown: bool = True,
) -> bool:
    """
    Smart update: download SPL docs only if needed.
    
    Args:
        data_dir: Output directory
        force: Force download even if up to date
        delay: Delay between pages
        no_html: Skip saving HTML files
        no_markdown: Skip saving Markdown files
        
    Returns:
        True if download was performed
    """
    print("=" * 70)
    print("SPLUNK SPL DOCUMENTATION - SMART UPDATE")
    print("=" * 70)
    print()
    
    # Check for updates
    status = await check_for_updates(data_dir)
    
    print(f"Local file exists: {status['local_exists']}")
    if status['local_version']:
        print(f"Local version: {status['local_version']} ({status['local_chunks']} chunks)")
        print(f"Last updated: {status['local_updated']}")
    print(f"Remote version: {status['remote_version']}")
    print(f"Update available: {status['update_available']}")
    if status.get('reason'):
        print(f"Reason: {status['reason']}")
    print()
    
    if not force and not status['update_available']:
        print("[✓] No update needed. Use 'force' command to re-download.")
        return False
    
    if force:
        print("[!] Force mode: downloading regardless of version...")
    else:
        print(f"[*] Downloading version {status['remote_version']}...")
    
    print()
    
    # Configure and run crawler
    version = status['remote_version'] or DEFAULT_VERSION
    config = CrawlConfig(
        output_dir=data_dir,
        version=version,
        delay_between_pages=delay,
        save_html=not no_html,
        save_markdown=not no_markdown,
        allowed_path_prefixes=get_allowed_paths(version),
    )
    
    async with SplunkCrawler(config) as crawler:
        await crawler.crawl(get_seed_urls(version))
    
    return True


# =============================================================================
# CLI INTERFACE
# =============================================================================

def print_stats(data_dir: Path = Path("data")):
    """Print local data statistics."""
    stats_path = data_dir / STATS_FILE
    
    if not stats_path.exists():
        print("No local SPL documentation found. Run 'python -m src.fetcher_spl_docs' to download.")
        return
    
    with open(stats_path, 'r') as f:
        stats = json.load(f)
    
    print("\nSplunk SPL Documentation - Local Data")
    print("=" * 50)
    print(f"Version: {stats.get('version', 'Unknown')}")
    print(f"Total Pages: {stats.get('total_pages', 0)}")
    print(f"Total Chunks: {stats.get('total_chunks', 0)}")
    print(f"Total Links Found: {stats.get('total_links', 0)}")
    print(f"Last Updated: {stats.get('last_updated', 'Unknown')}")
    print(f"Source: {stats.get('source', 'Unknown')}")
    print("=" * 50)


def print_usage():
    """Print CLI usage."""
    print("""
Splunk SPL Documentation Fetcher (Smart Update)
================================================

Commands:
    python -m src.fetcher_spl_docs              Smart update (download if needed)
    python -m src.fetcher_spl_docs check        Check for updates without downloading
    python -m src.fetcher_spl_docs force        Force re-download even if up to date
    python -m src.fetcher_spl_docs stats        Show local data statistics
    python -m src.fetcher_spl_docs help         Show this help message
    python -m src.fetcher_spl_docs crawl [opts] Legacy crawl with options

Options (for crawl command):
    --output-dir DIR   Output directory (default: data)
    --max-pages N      Maximum pages to crawl (default: 500)
    --max-depth N      Maximum link depth (default: 10)
    --delay N          Delay between pages in seconds (default: 0.5)
    --no-html          Don't save HTML files (default)
    --no-markdown      Don't save Markdown files (default)
    --version V        Splunk version to crawl (default: auto-detect)

Output:
    data/splunk_spl_docs.jsonl      SPL documentation chunks for RAG
    data/splunk_spl_docs.stats.json Version and statistics

Examples:
    python -m src.fetcher_spl_docs                           # Smart update
    python -m src.fetcher_spl_docs check                     # Check for updates
    python -m src.fetcher_spl_docs force                     # Force re-download
    python -m src.fetcher_spl_docs stats                     # Show local stats
    python -m src.fetcher_spl_docs crawl --delay 0.5         # Legacy crawl
    python -m src.fetcher_spl_docs crawl --version 10.2      # Crawl specific version

Source: https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/
""")


def main():
    """CLI entry point."""
    import sys
    
    args = sys.argv[1:]
    
    # Show help only if explicitly requested
    if args and args[0] in ["-h", "--help", "help"]:
        print_usage()
        return
    
    # Determine command - default to smart update if no command or starts with --
    if not args or args[0].startswith("--"):
        command = "update"  # Default: smart update
    else:
        command = args[0].lower()
    
    if command == "check":
        # Check for updates
        async def run_check():
            status = await check_for_updates()
            
            # Show local info
            if status['local_exists'] and status['local_version']:
                print(f"\nLocal version: {status['local_version']}")
                print(f"Local chunks: {status['local_chunks']}")
                if status['local_updated']:
                    print(f"Last updated: {status['local_updated']}")
            else:
                print("\n[!] No local data found")
            
            # Show status
            print()
            if status['update_available']:
                print(f"[!] Update available: {status['reason']}")
                print("    Run 'python -m src.fetcher_spl_docs' to update.")
            else:
                print("[✓] Already up to date.")
        
        asyncio.run(run_check())
    
    elif command == "force":
        # Force re-download
        asyncio.run(smart_update(force=True, delay=0.5))
    
    elif command == "stats":
        # Show local statistics
        print_stats()
    
    elif command == "update":
        # Smart update with optional args
        delay = 0.5
        for i, arg in enumerate(args):
            if arg == "--delay" and i + 1 < len(args):
                delay = float(args[i + 1])
        asyncio.run(smart_update(delay=delay))
    
    elif command == "crawl":
        # Legacy crawl command with options
        config = CrawlConfig()
        config.save_html = False
        config.save_markdown = False
        config.delay_between_pages = 0.5
        
        i = 1
        seed_url = None
        
        while i < len(args):
            arg = args[i]
            
            if arg == "--output-dir" and i + 1 < len(args):
                config.output_dir = args[i + 1]
                i += 2
            elif arg == "--max-pages" and i + 1 < len(args):
                config.max_pages = int(args[i + 1])
                i += 2
            elif arg == "--max-depth" and i + 1 < len(args):
                config.max_depth = int(args[i + 1])
                i += 2
            elif arg == "--delay" and i + 1 < len(args):
                config.delay_between_pages = float(args[i + 1])
                i += 2
            elif arg == "--version" and i + 1 < len(args):
                config.version = args[i + 1]
                config.allowed_path_prefixes = get_allowed_paths(config.version)
                i += 2
            elif arg == "--no-html":
                config.save_html = False
                i += 1
            elif arg == "--no-markdown":
                config.save_markdown = False
                i += 1
            elif arg == "--save-html":
                config.save_html = True
                i += 1
            elif arg.startswith("http"):
                seed_url = arg
                i += 1
            else:
                i += 1
        
        async def run_crawl():
            async with SplunkCrawler(config) as crawler:
                seeds = [seed_url] if seed_url else get_seed_urls(config.version)
                await crawler.crawl(seeds)
        
        asyncio.run(run_crawl())
    
    else:
        print(f"Unknown command: {command}")
        print("Run 'python -m src.fetcher_spl_docs help' for usage.")
        sys.exit(1)


if __name__ == "__main__":
    main()
