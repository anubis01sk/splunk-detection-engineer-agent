#!/usr/bin/env python3
"""
Splunk Documentation Scraper
============================

BeautifulSoup-based parser for extracting structured content from Splunk
documentation HTML files. Designed for RAG-based agents with chunked output.

This module can parse local HTML files without requiring a browser. For
recursive crawling of live pages, use fetcher_spl_docs.py.

Usage:
    from src.parser_spl_docs import SplunkDocScraper
    
    scraper = SplunkDocScraper()
    doc = scraper.parse_file("Search_command_primer_Splunk_Docs.html")
    
    chunks = doc.to_chunks()  # RAG-ready chunks
    markdown = doc.to_markdown()  # Human-readable format

Dependencies:
    pip install beautifulsoup4 lxml
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from bs4 import BeautifulSoup, Tag


# =============================================================================
# CONFIGURATION
# =============================================================================

MAX_CHUNK_CHARS = 4000
MIN_CHUNK_CHARS = 200
BASE_URL = "https://help.splunk.com"


# =============================================================================
# CSS SELECTORS
# =============================================================================

@dataclass(frozen=True)
class Selectors:
    """CSS selectors for Splunk documentation elements."""
    CONTENT: str = "render-html"
    CONTENT_WRAPPER: str = ".ezd-portal_content-page_main-wrapper"
    TITLE: str = 'i18n-message[id="message.chunked.title"]'
    SECTIONS: str = "article.topic.nested1"
    SECTION_HEADING: str = "h2.title.topictitle2"
    SECTION_BODY: str = "div.body"
    INNER_SECTION: str = "section.section"
    CODE_BLOCKS: str = "code-format.codeblock"
    CODE_WRAPPER: str = ".codeblock-search-wrapper"
    TABLES: str = "table.table"
    TABLE_HEADER: str = "thead.thead"
    TABLE_BODY: str = "tbody.tbody"
    TABLE_ROW: str = "tr.row"
    INTERNAL_LINKS: str = 'a.xref[href^="/en/"]'
    ALL_XREF_LINKS: str = "a.xref"
    BREADCRUMBS: str = ".ezd-portal_portal-breadcrumb_href"
    FALLBACK_CONTENT: str = "main"
    FALLBACK_SECTIONS: str = 'article[id$="--en"]'
    FALLBACK_CODE: str = "pre.codeblock"


SELECTORS = Selectors()


# =============================================================================
# URL PATTERNS
# =============================================================================

class URLPatterns:
    """URL pattern matching and parsing for Splunk documentation links."""
    BASE_URL = BASE_URL
    INTERNAL_DOC_PATTERN = re.compile(r"^/en/(?:splunk-[a-z-]+|[?]resourceId=)")
    FULL_PATH_PATTERN = re.compile(
        r"^/en/(?P<product>splunk-[a-z-]+)/"
        r"(?P<category>[^/]+)/"
        r"(?P<manual>[^/]+)/"
        r"(?P<version>[\d.]+)/"
        r"(?P<section>[^/]+)/"
        r"(?P<page>[^#?]+)"
        r"(?:\?[^#]*)?"
        r"(?:#(?P<anchor>.+))?"
    )
    RESOURCE_ID_PATTERN = re.compile(r"^/en/\?resourceId=(?P<resource_id>[A-Za-z0-9_]+)")
    EXCLUDE_PATTERNS = [
        re.compile(r"/en/(login|logout)$"),
        re.compile(r"^https?://docs\.splunk\.com/Splexicon:"),
        re.compile(r"^https?://(x\.com|twitter\.com|linkedin\.com|facebook\.com|www\.linkedin\.com)"),
        re.compile(r"^#$"),
        re.compile(r"^mailto:"),
        re.compile(r"^javascript:"),
    ]
    # Version-agnostic prefixes - version filtering is done by the crawler
    ALLOWED_PREFIXES = [
        "/en/splunk-enterprise/search/spl-search-reference/",
        "/en/splunk-enterprise/search/search-manual/",
    ]

    @classmethod
    def is_internal_doc_link(cls, href: str) -> bool:
        """Check if URL is an internal documentation link."""
        if not href:
            return False
        for pattern in cls.EXCLUDE_PATTERNS:
            if pattern.search(href):
                return False
        return bool(cls.INTERNAL_DOC_PATTERN.match(href))

    @classmethod
    def is_within_allowed_scope(cls, href: str) -> bool:
        """Check if URL falls within allowed crawl boundaries."""
        if not href:
            return False
        for pattern in cls.EXCLUDE_PATTERNS:
            if pattern.search(href):
                return False
        path = href.split("#")[0].split("?")[0]
        if path.startswith("http"):
            from urllib.parse import urlparse
            parsed = urlparse(path)
            if parsed.netloc and parsed.netloc != "help.splunk.com":
                return False
            path = parsed.path
        for prefix in cls.ALLOWED_PREFIXES:
            if path.startswith(prefix):
                return True
        if "?resourceId=" in href:
            resource_id = href.split("?resourceId=")[-1]
            if "SearchReference" in resource_id or "Search_" in resource_id:
                return True
        return False

    @classmethod
    def normalize_url(cls, href: str, base_url: str = None) -> str:
        """Normalize URL to absolute form without anchors."""
        if not href:
            return ""
        url = href.split("#")[0]
        if url.startswith("/"):
            url = (base_url or cls.BASE_URL) + url
        return url.rstrip("/")

    @classmethod
    def parse_doc_url(cls, href: str) -> dict:
        """Parse documentation URL into structured components."""
        result = {
            "type": None,
            "product": None,
            "category": None,
            "manual": None,
            "version": None,
            "section": None,
            "page": None,
            "anchor": None,
            "resource_id": None,
        }
        match = cls.FULL_PATH_PATTERN.match(href)
        if match:
            result.update(match.groupdict())
            result["type"] = "full_path"
            return result
        match = cls.RESOURCE_ID_PATTERN.match(href)
        if match:
            result["type"] = "resource_id"
            result["resource_id"] = match.group("resource_id")
            return result
        return result

    @classmethod
    def extract_manual_name(cls, url: str) -> str:
        """Extract manual name from URL path."""
        if "spl-search-reference" in url:
            return "spl-search-reference"
        if "search-manual" in url:
            return "search-manual"
        parsed = cls.parse_doc_url(url)
        return parsed.get("manual") or "unknown"


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class CodeBlock:
    """Represents an SPL code block."""
    content: str
    language: str = "spl"
    is_searchable: bool = False

    def to_dict(self) -> dict:
        return {"language": self.language, "code": self.content}

    def to_markdown(self) -> str:
        lang = self.language or "spl"
        return f"```{lang}\n{self.content}\n```"


@dataclass
class TableCell:
    """Represents a table cell."""
    content: str
    is_header: bool = False


@dataclass
class TableRow:
    """Represents a table row."""
    cells: list[TableCell] = field(default_factory=list)

    def to_list(self) -> list[str]:
        return [cell.content for cell in self.cells]


@dataclass
class Table:
    """Represents a documentation table."""
    id: Optional[str] = None
    caption: Optional[str] = None
    headers: list[str] = field(default_factory=list)
    rows: list[TableRow] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "headers": self.headers,
            "rows": [row.to_list() for row in self.rows],
        }

    def to_markdown(self) -> str:
        if not self.headers and not self.rows:
            return ""
        lines = []
        if self.caption:
            lines.append(f"**{self.caption}**\n")
        if self.headers:
            lines.append("| " + " | ".join(self.headers) + " |")
            lines.append("| " + " | ".join(["---"] * len(self.headers)) + " |")
        for row in self.rows:
            cells = row.to_list()
            if self.headers and len(cells) < len(self.headers):
                cells.extend([""] * (len(self.headers) - len(cells)))
            lines.append("| " + " | ".join(cells) + " |")
        return "\n".join(lines)


@dataclass
class InternalLink:
    """Represents an internal documentation link."""
    href: str
    text: str
    url_type: Optional[str] = None
    is_peer_link: bool = False
    parsed: dict = field(default_factory=dict)

    def get_absolute_url(self, base_url: str = BASE_URL) -> str:
        return URLPatterns.normalize_url(self.href, base_url)


@dataclass
class Section:
    """Represents a documentation section."""
    id: str
    title: str
    level: int = 2
    content: str = ""
    code_blocks: list[CodeBlock] = field(default_factory=list)
    tables: list[Table] = field(default_factory=list)
    links: list[InternalLink] = field(default_factory=list)

    def to_markdown(self) -> str:
        lines = []
        heading_prefix = "#" * self.level
        if self.title:
            lines.append(f"{heading_prefix} {self.title}\n")
        if self.content:
            lines.append(self.content + "\n")
        for code in self.code_blocks:
            lines.append(code.to_markdown() + "\n")
        for table in self.tables:
            md = table.to_markdown()
            if md:
                lines.append(md + "\n")
        return "\n".join(lines)

    def to_chunks(self, base_metadata: dict) -> list[dict]:
        """Split section into RAG-ready chunks with size limits."""
        chunks = []
        metadata = {
            **base_metadata,
            "section_heading": self.title,
            "section_id": self.id,
        }
        text_chunks = self._split_content(self.content) if self.content else [""]
        total_chunks = max(len(text_chunks), 1)
        for idx, text_chunk in enumerate(text_chunks if text_chunks else [""]):
            chunk_code = [cb.to_dict() for cb in self.code_blocks] if idx == 0 else []
            chunk_tables = [t.to_dict() for t in self.tables] if idx == 0 else []
            chunk_id = self._generate_chunk_id(text_chunk, metadata.get("url", ""), self.id, idx)
            chunk = {
                "id": chunk_id,
                "content": text_chunk,
                "code_examples": chunk_code,
                "tables": chunk_tables,
                "chunk_index": idx,
                "total_chunks": total_chunks,
                "metadata": metadata.copy(),
            }
            chunks.append(chunk)
        return chunks

    def _split_content(self, text: str) -> list[str]:
        """Split text into chunks at paragraph boundaries."""
        if len(text) <= MAX_CHUNK_CHARS:
            return [text] if len(text) >= MIN_CHUNK_CHARS else []
        chunks = []
        paragraphs = text.split("\n\n")
        current_chunk = ""
        for para in paragraphs:
            if len(current_chunk) + len(para) + 2 <= MAX_CHUNK_CHARS:
                current_chunk = f"{current_chunk}\n\n{para}" if current_chunk else para
            else:
                if current_chunk and len(current_chunk) >= MIN_CHUNK_CHARS:
                    chunks.append(current_chunk.strip())
                if len(para) > MAX_CHUNK_CHARS:
                    words = para.split()
                    current_chunk = ""
                    for word in words:
                        if len(current_chunk) + len(word) + 1 <= MAX_CHUNK_CHARS:
                            current_chunk = f"{current_chunk} {word}" if current_chunk else word
                        else:
                            if current_chunk and len(current_chunk) >= MIN_CHUNK_CHARS:
                                chunks.append(current_chunk.strip())
                            current_chunk = word
                else:
                    current_chunk = para
        if current_chunk and len(current_chunk) >= MIN_CHUNK_CHARS:
            chunks.append(current_chunk.strip())
        return chunks if chunks else ([text] if len(text) >= MIN_CHUNK_CHARS else [])

    @staticmethod
    def _generate_chunk_id(content: str, url: str, section_id: str, idx: int) -> str:
        data = f"{url}:{section_id}:{idx}:{content[:100]}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]


@dataclass
class SplunkDocument:
    """Represents a parsed Splunk documentation page."""
    title: str
    url: str = ""
    source_file: str = ""
    breadcrumbs: str = ""
    intro_content: str = ""
    sections: list[Section] = field(default_factory=list)
    all_code_blocks: list[CodeBlock] = field(default_factory=list)
    all_tables: list[Table] = field(default_factory=list)
    all_links: list[InternalLink] = field(default_factory=list)
    scraped_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def get_internal_urls(self, scoped: bool = True) -> list[str]:
        """Get unique internal documentation URLs for crawling."""
        urls = set()
        for link in self.all_links:
            href = link.href
            if scoped:
                if URLPatterns.is_within_allowed_scope(href):
                    urls.add(URLPatterns.normalize_url(href))
            else:
                if URLPatterns.is_internal_doc_link(href):
                    urls.add(URLPatterns.normalize_url(href))
        return sorted(urls)

    def to_markdown(self) -> str:
        """Convert document to Markdown format."""
        lines = [f"# {self.title}\n"]
        if self.breadcrumbs:
            lines.append(f"*{self.breadcrumbs}*\n")
        if self.intro_content:
            lines.append(self.intro_content + "\n")
        for section in self.sections:
            lines.append(section.to_markdown())
        return "\n".join(lines)

    def to_chunks(self) -> list[dict]:
        """Convert document to RAG-ready chunks."""
        chunks = []
        base_metadata = {
            "title": self.title,
            "url": self.url,
            "breadcrumb": self.breadcrumbs,
            "manual": URLPatterns.extract_manual_name(self.url),
            "scraped_at": self.scraped_at,
        }
        if self.intro_content and len(self.intro_content) >= MIN_CHUNK_CHARS:
            intro_section = Section(
                id="intro",
                title="",
                level=1,
                content=self.intro_content,
            )
            chunks.extend(intro_section.to_chunks(base_metadata))
        for section in self.sections:
            chunks.extend(section.to_chunks(base_metadata))
        if not chunks:
            chunk_id = hashlib.sha256(f"{self.url}:page".encode()).hexdigest()[:16]
            chunks.append({
                "id": chunk_id,
                "content": self.intro_content or self.title,
                "code_examples": [cb.to_dict() for cb in self.all_code_blocks],
                "tables": [t.to_dict() for t in self.all_tables],
                "chunk_index": 0,
                "total_chunks": 1,
                "metadata": base_metadata,
            })
        return chunks

    def to_json(self, indent: int = 2) -> str:
        """Convert document to JSON format."""
        data = {
            "url": self.url,
            "title": self.title,
            "breadcrumbs": self.breadcrumbs,
            "scraped_at": self.scraped_at,
            "chunks": self.to_chunks(),
            "internal_urls": self.get_internal_urls(),
        }
        return json.dumps(data, indent=indent, ensure_ascii=False)


# =============================================================================
# SCRAPER
# =============================================================================

class SplunkDocScraper:
    """Scraper for parsing Splunk documentation HTML files."""

    def __init__(self, selectors: Selectors = SELECTORS):
        self.selectors = selectors
        self.url_patterns = URLPatterns

    def parse_file(self, file_path: str) -> SplunkDocument:
        """Parse a local HTML file into a SplunkDocument."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        html_content = path.read_text(encoding="utf-8")
        doc = self.parse_html(html_content)
        doc.source_file = str(path.absolute())
        return doc

    def parse_html(self, html_content: str, url: str = "") -> SplunkDocument:
        """Parse HTML content into a SplunkDocument."""
        soup = BeautifulSoup(html_content, "lxml")
        title = self._extract_title(soup)
        breadcrumbs = self._extract_breadcrumbs(soup)
        content_container = self._get_content_container(soup)
        intro_content = self._extract_intro_content(content_container)
        sections = self._extract_sections(content_container)
        all_code_blocks = self._extract_all_code_blocks(content_container)
        all_tables = self._extract_all_tables(content_container)
        all_links = self._extract_all_links(content_container)
        return SplunkDocument(
            title=title,
            url=url,
            breadcrumbs=breadcrumbs,
            intro_content=intro_content,
            sections=sections,
            all_code_blocks=all_code_blocks,
            all_tables=all_tables,
            all_links=all_links,
        )

    def _extract_title(self, soup: BeautifulSoup) -> str:
        """Extract page title."""
        title_element = soup.select_one(self.selectors.TITLE)
        if title_element:
            data_values = title_element.get("data-values")
            if data_values:
                try:
                    data = json.loads(data_values)
                    title = data.get("content", {}).get("title")
                    if title:
                        return title
                except (json.JSONDecodeError, TypeError):
                    pass
        h1 = soup.find("h1")
        if h1:
            return h1.get_text(strip=True)
        title_tag = soup.find("title")
        if title_tag:
            text = title_tag.get_text(strip=True)
            if " | " in text:
                return text.split(" | ")[0]
            return text
        return "Untitled"

    def _extract_breadcrumbs(self, soup: BeautifulSoup) -> str:
        """Extract breadcrumb navigation."""
        elements = soup.select(self.selectors.BREADCRUMBS)
        crumbs = []
        for el in elements:
            text = el.get_text(strip=True)
            if text:
                crumbs.append(text)
        return " > ".join(crumbs)

    def _get_content_container(self, soup: BeautifulSoup) -> Optional[Tag]:
        """Get the main content container element."""
        container = soup.select_one(self.selectors.CONTENT)
        if container:
            return container
        container = soup.select_one(self.selectors.FALLBACK_CONTENT)
        if container:
            return container
        return soup.body

    def _extract_intro_content(self, container: Optional[Tag]) -> str:
        """Extract introductory content before first section."""
        if not container:
            return ""
        intro_parts = []
        for child in container.children:
            if isinstance(child, Tag):
                if child.name == "article" or child.select_one("article"):
                    break
                if child.name in ("p", "div", "ul", "ol"):
                    text = self._extract_text_content(child)
                    if text:
                        intro_parts.append(text)
        return "\n\n".join(intro_parts)

    def _extract_sections(self, container: Optional[Tag]) -> list[Section]:
        """Extract all sections from the content."""
        if not container:
            return []
        sections = []
        section_elements = container.select(self.selectors.SECTIONS)
        if not section_elements:
            section_elements = container.select(self.selectors.FALLBACK_SECTIONS)
        for article in section_elements:
            section = self._extract_section(article)
            if section:
                sections.append(section)
        return sections

    def _extract_section(self, article: Tag) -> Optional[Section]:
        """Extract a single section from an article element."""
        section_id = article.get("id", "")
        heading = article.select_one(self.selectors.SECTION_HEADING)
        title = heading.get_text(strip=True) if heading else ""
        level = 2
        if heading:
            classes = heading.get("class", [])
            for cls in classes:
                if isinstance(cls, str) and cls.startswith("h") and len(cls) == 2 and cls[1].isdigit():
                    level = int(cls[1])
                    break
        body = article.select_one(self.selectors.SECTION_BODY)
        content = self._extract_text_content(body) if body else ""
        code_blocks = self._extract_code_blocks_from_element(article)
        tables = self._extract_tables_from_element(article)
        links = self._extract_links_from_element(article)
        if not content and not code_blocks and not tables:
            return None
        return Section(
            id=section_id,
            title=title,
            level=level,
            content=content,
            code_blocks=code_blocks,
            tables=tables,
            links=links,
        )

    def _extract_text_content(self, element: Optional[Tag]) -> str:
        """Extract clean text content, excluding code blocks and tables."""
        if not element:
            return ""
        clone = BeautifulSoup(str(element), "lxml")
        for selector in [self.selectors.CODE_BLOCKS, self.selectors.CODE_WRAPPER, 
                         self.selectors.TABLES, "button", "script", "style"]:
            for tag in clone.select(selector):
                tag.decompose()
        text = clone.get_text(separator=" ", strip=True)
        text = re.sub(r"\s+", " ", text)
        lines = [line.strip() for line in text.split(". ") if line.strip()]
        return ". ".join(lines)

    def _extract_all_code_blocks(self, container: Optional[Tag]) -> list[CodeBlock]:
        """Extract all code blocks from the content."""
        if not container:
            return []
        return self._extract_code_blocks_from_element(container)

    def _extract_code_blocks_from_element(self, element: Tag) -> list[CodeBlock]:
        """Extract code blocks from a specific element."""
        code_blocks = []
        for code_elem in element.select(self.selectors.CODE_BLOCKS):
            content = code_elem.get_text(strip=True)
            if not content:
                continue
            classes = code_elem.get("class", [])
            language = "spl"
            is_searchable = False
            for cls in classes:
                if isinstance(cls, str):
                    if cls.startswith("language-"):
                        lang = cls.replace("language-", "")
                        language = "spl" if lang in ("sh", "bash", "shell") else lang
                    if cls == "search":
                        is_searchable = True
            code_blocks.append(CodeBlock(
                content=content,
                language=language,
                is_searchable=is_searchable,
            ))
        if not code_blocks:
            for code_elem in element.select(self.selectors.FALLBACK_CODE):
                content = code_elem.get_text(strip=True)
                if content:
                    code_blocks.append(CodeBlock(content=content, language="spl"))
        return code_blocks

    def _extract_all_tables(self, container: Optional[Tag]) -> list[Table]:
        """Extract all tables from the content."""
        if not container:
            return []
        return self._extract_tables_from_element(container)

    def _extract_tables_from_element(self, element: Tag) -> list[Table]:
        """Extract tables from a specific element."""
        tables = []
        for table_elem in element.select(self.selectors.TABLES):
            table_id = table_elem.get("id")
            caption_elem = table_elem.find("caption")
            caption = caption_elem.get_text(strip=True) if caption_elem else None
            headers = []
            thead = table_elem.select_one(self.selectors.TABLE_HEADER)
            if thead:
                for th in thead.select("th"):
                    headers.append(th.get_text(strip=True))
            rows = []
            tbody = table_elem.select_one(self.selectors.TABLE_BODY)
            if tbody:
                for tr in tbody.select(self.selectors.TABLE_ROW):
                    cells = []
                    for td in tr.select("td, th"):
                        is_header = td.name == "th"
                        cells.append(TableCell(
                            content=td.get_text(strip=True),
                            is_header=is_header,
                        ))
                    if cells:
                        rows.append(TableRow(cells=cells))
            if headers or rows:
                tables.append(Table(
                    id=table_id,
                    caption=caption,
                    headers=headers,
                    rows=rows,
                ))
        return tables

    def _extract_all_links(self, container: Optional[Tag]) -> list[InternalLink]:
        """Extract all internal links from the content."""
        if not container:
            return []
        return self._extract_links_from_element(container)

    def _extract_links_from_element(self, element: Tag) -> list[InternalLink]:
        """Extract internal links from a specific element."""
        links = []
        seen_hrefs = set()
        for a in element.select(self.selectors.ALL_XREF_LINKS):
            href = a.get("href", "")
            text = a.get_text(strip=True)
            if not href or href in seen_hrefs:
                continue
            if not self.url_patterns.is_internal_doc_link(href):
                continue
            seen_hrefs.add(href)
            classes = a.get("class", [])
            is_peer_link = "j-peer-link" in classes
            parsed = self.url_patterns.parse_doc_url(href)
            links.append(InternalLink(
                href=href,
                text=text,
                url_type=parsed.get("type"),
                is_peer_link=is_peer_link,
                parsed=parsed,
            ))
        return links


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def extract_urls_from_file(file_path: str, scoped: bool = True) -> list[str]:
    """Quick utility to extract all crawlable URLs from a file."""
    scraper = SplunkDocScraper()
    doc = scraper.parse_file(file_path)
    return doc.get_internal_urls(scoped=scoped)


def parse_to_chunks(file_path: str) -> list[dict]:
    """Parse a file and return RAG-ready chunks."""
    scraper = SplunkDocScraper()
    doc = scraper.parse_file(file_path)
    return doc.to_chunks()


def parse_to_jsonl(file_path: str, output_path: str) -> int:
    """Parse a file and write chunks to JSON Lines format."""
    chunks = parse_to_chunks(file_path)
    with open(output_path, "w", encoding="utf-8") as f:
        for chunk in chunks:
            f.write(json.dumps(chunk, ensure_ascii=False) + "\n")
    return len(chunks)


# =============================================================================
# CLI ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Splunk Documentation Scraper")
        print()
        print("Usage: python -m src.parser_spl_docs <html_file> [--urls|--chunks|--markdown|--json]")
        print()
        print("Options:")
        print("  --urls      List internal URLs for crawling")
        print("  --chunks    Output RAG-ready chunks")
        print("  --markdown  Output as Markdown")
        print("  --json      Output as JSON")
        print("  --jsonl     Output chunks as JSON Lines to stdout")
        print("  (default)   Show document info")
        sys.exit(1)
    file_path = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else "--info"
    scraper = SplunkDocScraper()
    try:
        doc = scraper.parse_file(file_path)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    if mode == "--urls":
        print("Internal URLs for crawling:")
        for url in doc.get_internal_urls():
            print(f"  {url}")
        print(f"\nTotal: {len(doc.get_internal_urls())} URLs")
    elif mode == "--chunks":
        chunks = doc.to_chunks()
        print(f"Generated {len(chunks)} chunks:\n")
        for i, chunk in enumerate(chunks):
            section = chunk.get("metadata", {}).get("section_heading", "")
            content_preview = chunk["content"][:150] + "..." if len(chunk["content"]) > 150 else chunk["content"]
            print(f"--- Chunk {i+1}: {section or '(intro)'} ---")
            print(content_preview)
            print()
    elif mode == "--markdown":
        print(doc.to_markdown())
    elif mode == "--json":
        print(doc.to_json())
    elif mode == "--jsonl":
        for chunk in doc.to_chunks():
            print(json.dumps(chunk, ensure_ascii=False))
    else:
        print(f"Document: {doc.title}")
        print(f"Source: {doc.source_file}")
        print(f"Breadcrumbs: {doc.breadcrumbs}")
        print(f"Sections: {len(doc.sections)}")
        print(f"Code blocks: {len(doc.all_code_blocks)}")
        print(f"Tables: {len(doc.all_tables)}")
        print(f"Internal links: {len(doc.all_links)}")
        print(f"Crawlable URLs (scoped): {len(doc.get_internal_urls())}")
        if doc.sections:
            print("\nSections:")
            for s in doc.sections:
                print(f"  - {s.title}")
