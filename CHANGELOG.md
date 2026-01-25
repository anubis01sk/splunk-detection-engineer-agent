# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-01-25

### Added

- **Web Interface** (`src/api/server.py`, `src/web/`)
  - FastAPI backend with REST API endpoints
  - Modern dark-themed dashboard UI
  - Real-time status indicators
  - Chat interface for query generation
  - RAG search across all knowledge bases
  - End-to-end IOC workflow automation

- **CIM Data Models RAG** (`src/rag_cim_docs.py`)
  - 244 chunks from 26 data models
  - Semantic search for CIM field lookups
  - Smart version detection for updates

- **Attack Data RAG** (`src/rag_attack_data.py`)
  - 1,174 attack datasets from splunk/attack_data
  - 237 MITRE ATT&CK techniques mapped
  - 51 data sources indexed

- **Grounding Validation** (`src/agent/grounding.py`)
  - Validates generated SPL queries against known fields
  - Prevents field hallucination
  - Distinguishes between created vs. used fields

- **Chain of Thought Reasoning**
  - `--reasoning` flag for detailed agent trace
  - Real-time streaming via SSE

### Changed

- **CLI Command Alignment** - All RAG modules now use `query` command:
  - `python -m src.rag_spl_docs query "<text>"`
  - `python -m src.rag_detections query "<text>"`
  - `python -m src.rag_cim_docs query "<text>"`
  - `python -m src.rag_attack_data query "<text>"` *(was `search`)*

- **Agent Modularization** - Split into `src/agent/` package:
  - `orchestrator.py` - Main SplunkAgent class
  - `handlers.py` - Input type handlers
  - `validation.py` - Query validation logic
  - `prompts.py` - Prompt template loader
  - `models.py` - Data models
  - `grounding.py` - Field grounding validation

- **Prompt Templates** - Enhanced with XML structure:
  - `prompts/PROMPT_query_generation.md` - Chain of thought reasoning
  - `prompts/PROMPT_ioc_hunting.md` - Advanced IOC hunting patterns
  - `prompts/PROMPT_refinement.md` - Iteration-aware refinement
  - `prompts/DIRECTIVE_spl_syntax.md` - SPL syntax constraints

### Fixed

- RAG search "All Sources" now returns results from all RAGs, not just top scorers
- Grounding validation no longer flags SPL-created fields (e.g., `count`, `avg`)
- Added `nodename` to CIM Authentication fields
- API version now uses single source of truth from `src/__init__.py`
- Removed duplicate `QueryStatus` enum definitions
- Standardized RAG stats key to `total_documents`
- Removed `logging.basicConfig()` from library modules

## [1.0.0] - 2026-01-20

### Added

- **Agent Orchestrator** (`splunk_agent.py`)
  - Main workflow engine for SPL query generation
  - Interactive CLI mode for real-time query development
  - Iterative refinement loop with automatic error fixing
  - Support for three input types: natural language, log source, IOC reports

- **Input Processing** (`input_processor.py`)
  - Natural language detection request classification
  - Log source specification parsing (index, sourcetype, host, source)
  - IOC report processing from URLs and PDF files
  - Automatic indicator extraction (IPs, domains, hashes, CVEs, MITRE ATT&CK)

- **Multi-LLM Provider Support** (`llm_provider.py`)
  - Groq (free tier: 14,400 requests/day)
  - Mistral (free tier: 1B tokens/month)
  - OpenRouter (free tier: 50 requests/day)
  - Claude (Anthropic)
  - OpenAI (GPT-4, GPT-3.5)
  - DeepSeek
  - Grok (xAI)
  - Qwen (Alibaba)

- **Splunk REST API Client** (`splunk_client.py`)
  - Token-based and username/password authentication
  - Index, sourcetype, and field discovery
  - Query validation and execution
  - SSL certificate verification control

- **SPL Documentation RAG** (`splunk_rag_ingest.py`)
  - ChromaDB vector storage with BGE-small-en-v1.5 embeddings
  - 920 SPL documentation chunks from Splunk 10.0
  - Semantic search with metadata filtering
  - Context retrieval for LLM prompting

- **Detection Rules RAG** (`detection_rag.py`)
  - 1,978 security detection rules from Splunk Security Content
  - MITRE ATT&CK technique mapping (340+ techniques)
  - 331 analytic stories
  - Data source filtering

- **Documentation Crawler** (`splunk_crawler.py`)
  - Playwright-based async web crawler
  - Recursive crawling with BFS and URL deduplication
  - Multiple output formats (HTML, JSON, Markdown, JSONL)

- **HTML Parser** (`splunk_scraper.py`)
  - BeautifulSoup-based content extraction
  - Code block and table preservation
  - RAG-ready chunk generation

- **Detection Parser** (`detection_downloader.py`)
  - YAML detection file parsing
  - Structured JSONL output for RAG ingestion
  - Metadata extraction (MITRE, data sources, analytic stories)

### Knowledge Base Statistics

| Collection | Documents | Source |
|------------|-----------|--------|
| SPL Documentation | 920 chunks | help.splunk.com (Splunk 10.0) |
| Detection Rules | 1,978 YAML files | Splunk Security Content |
| MITRE ATT&CK | 340+ techniques | Extracted from detections |
| Analytic Stories | 331 stories | Extracted from detections |

### Technical Stack

- **Vector Database**: ChromaDB (persistent, serverless)
- **Embedding Model**: BAAI/bge-small-en-v1.5 (133MB, CPU-optimized)
- **LLM Interface**: OpenAI SDK (compatible with multiple providers)
- **Web Scraping**: Playwright + BeautifulSoup
- **PDF Processing**: pdfplumber

---

## [1.1.0] - 2026-01-21

### Added

- **Smart Update System for Data Fetchers**
  - `fetcher_spl_docs.py`: Automatic Splunk version detection (10.0 → 10.1 → 10.2 → ...)
  - `fetcher_detections.py`: GitHub release version checking via API
  - Both fetchers only download when newer versions are available
  - Empty data detection triggers automatic re-download
  - Stats files track version, chunk count, and last update time

- **New CLI Commands**
  - `python -m src.fetcher_spl_docs check` - Check for SPL docs updates
  - `python -m src.fetcher_spl_docs force` - Force re-download
  - `python -m src.fetcher_detections check` - Check for detection updates  
  - `python -m src.fetcher_detections force` - Force re-download
  - `python -m src.fetcher_detections stats` - Show local statistics

### Changed

- Renamed core files for consistency:
  - `splunk_agent.py` → `agent.py`
  - `splunk_rag_ingest.py` → `rag_spl_docs.py`
  - `detection_rag.py` → `rag_detections.py`
  - `splunk_crawler.py` → `fetcher_spl_docs.py`
  - `detection_downloader.py` → `fetcher_detections.py`
  - `splunk_scraper.py` → `parser_spl_docs.py`

- Parser now supports all Splunk versions (version-agnostic URL patterns)
- Default output directory changed from `splunk_docs/` to `data/`
- Updated all documentation to reflect new file names and commands

### Fixed

- Parser attribute mapping (`heading` → `title`, `code_examples` → `code_blocks`, etc.)
- JSON serialization of TableRow objects
- Version detection for Splunk 10.2 documentation
- CLI default command now runs smart update instead of showing help

---

## [1.2.0] - 2026-01-22

### Added

- **CIM Data Models RAG** (`fetcher_cim_docs.py`, `parser_cim_docs.py`, `rag_cim_docs.py`)
  - 26 CIM data models with 1064 fields (v6.3)
  - Handles multi-section pages (e.g., Endpoint with 5 sub-models)
  - Smart version detection starting from 6.2
  - Correct URL slug mapping for all data models

- **Attack Data RAG** (`fetcher_attack_data.py`, `rag_attack_data.py`)
  - 1175 attack datasets from splunk/attack_data
  - 237 unique MITRE ATT&CK techniques
  - 51 unique data sources
  - GitHub commits/tags API for version checking

- **Sidebar Navigation Link Extraction**
  - SPL docs crawler now extracts links from `li[role="treeitem"]` sidebar
  - Discovers 4x more pages (254 vs 60 previously)
  - Complete SPL command reference coverage

- **AI Connection Test in Status**
  - `python -m src.agent status` now tests LLM API connectivity
  - Shows ✓ Connected or ✗ Error with details

- **Lazy Imports** (`src/__init__.py`)
  - Eliminates RuntimeWarning when running submodules with `python -m`
  - Uses `__getattr__` for deferred module loading

- **Code Modularization** (`src/agent/` package)
  - Split monolithic agent.py into orchestrator, handlers, validation, prompts, models, config
  - External prompt files in `prompts/` directory

- **Web Interface** (`src/api/`, `web/`)
  - FastAPI backend with REST API
  - Vanilla HTML/JS/CSS dashboard

### Changed

- **Default Versions Updated**
  - SPL Docs: 10.0 → **10.2**
  - CIM Docs: 6.2 → **6.3**

- **SPL Documentation RAG Improvements**
  - 1225 chunks (5x increase from 250)
  - 254 pages crawled (4x increase from 60)
  - All SPL commands now included (stats, eval, rex, etc.)

- **Folder Naming**
  - `spl_vector_db/` → `spl_docs_vector_db/`
  - `.gitignore` now uses `*_vector_db/` pattern

### Fixed

- CIM data model URL slugs (`dlp` → `data-loss-prevention`, `jvm` → `java-virtual-machines-jvm`)
- Endpoint sub-models parsing (Ports, Processes, Services, Filesystem, Registry)
- GitHub API for attack_data (uses commits API, not releases)
- MITRE technique extraction from attack data YAML files

### Knowledge Base Statistics (Updated)

| Collection | Documents | Source |
|------------|-----------|--------|
| SPL Documentation | **1225 chunks** | help.splunk.com (Splunk **10.2**) |
| Detection Rules | 1978 rules | Splunk Security Content |
| CIM Data Models | **1064 fields** | Splunk CIM **6.3** (26 models) |
| Attack Data | **1175 datasets** | splunk/attack_data (237 MITRE techniques) |

---

## [1.2.1] - 2026-01-23

### Fixed

- **CIM Parser Improvements**
  - Fixed field name extraction from CIM tables (was extracting data model names instead of actual field names)
  - Added hierarchical field name handling (e.g., "Alerts.action" → "action")
  - Skip invalid field names that match data model names
  - Better extraction of field names from description text

- **CIM RAG Output Enhancement**
  - `get_context_for_agent()` now extracts 70+ standard CIM field names from content
  - Improved regex patterns for field extraction from Expression patterns
  - Better formatted output for LLM consumption

- **Documentation Updates**
  - Added comprehensive Command Cheat Sheet to README.md
  - Updated all MD files with accurate statistics and commands
  - Added CIM and Attack Data troubleshooting sections

### Changed

- RAG CLI search commands now extract and display actual CIM field names
- Improved field pattern matching in CIM RAG output

---

## [1.2.2] - 2026-01-25

### Added

- **Chain of Thought (CoT) Reasoning Display**
  - New `src/agent/reasoning.py` module with `ReasoningTrace` and `ReasoningStep` classes
  - CLI `--reason` flag for single queries: `python -m src.agent run --reason "..."`
  - Interactive mode `reason on/off` commands
  - Web UI toggle and real-time reasoning panel
  - Server-Sent Events (SSE) endpoint for streaming: `POST /api/query/stream`
  - Step-by-step visualization: input classification → RAG retrieval → query generation → validation
  - RAG match counts and relevance scores displayed
  - Confidence scoring (0-100%) based on RAG results

- **End-to-End IOC → Detection → Validation Workflow**
  - New `src/agent/e2e_workflow.py` module
  - New API endpoint: `POST /api/workflow/e2e`
  - Complete 7-stage automated pipeline:
    1. Input Processing (URL or file)
    2. IOC Extraction (IPs, domains, hashes, file paths)
    3. Detection Building (generate SPL query using Detection RAG)
    4. Best Practices Check (validate against SPL Docs RAG)
    5. Metadata Validation (test syntax against Splunk)
    6. Attack Data Testing (find relevant datasets)
    7. Results with confidence score
  - Web UI tab for E2E workflow with results visualization
  - Automatic false positive filtering (vendor domains, system files)
  - Multi-field IOC search patterns (file_hash, MD5, file_path, Image)

- **Prompt Engineering Externalization**
  - All prompt content moved to `prompts/` directory:
    - `DIRECTIVE_spl_syntax.md` - Critical SPL syntax rules (no comments, tstats restrictions)
    - `PROMPT_query_generation.md` - Main query generation template
    - `PROMPT_refinement.md` - Query refinement template
    - `PROMPT_ioc_hunting.md` - IOC hunting query template
    - `PROMPT_log_source.md` - Log source exploration template
  - `src/agent/prompts.py` now loads from external files with fallbacks
  - Hot-reload support via `clear_prompt_cache()`

- **SPL Linting and Auto-Fix**
  - Extended `lint_spl_query()` in `src/agent/validation.py`:
    - RULE 6: Auto-add `search` prefix for queries starting with `(`
    - RULE 7: Remove empty `IN ("")` clauses
    - RULE 8: Clean orphaned OR operators
  - Splunk parser validation now normalizes queries with `search` prefix

- **Dashboard Enhancements**
  - All 6 RAGs now displayed in system status (SPL Docs, Detections, CIM, Attack Data)
  - Session token usage tracking (input/output/total tokens)
  - E2E Workflow tab with form submission and results visualization
  - Reasoning panel with collapsible steps and confidence bar

- **API Improvements**
  - `show_reasoning` parameter in `POST /api/query`
  - Token usage in `GET /api/status` response
  - Auto-open browser when server starts
  - `--local` and `--no-browser` CLI flags for server

### Changed

- `validate_query()` in `splunk_client.py` now adds `search` prefix (required by parser endpoint)
- CIM RAG query enhancement for better field matching
- IOC extraction with two-tier URL fetching (httpx + Playwright fallback)
- Expanded false positive filtering in IOC extraction

### Fixed

- Queries starting with `(` now auto-fixed with `search` prefix
- Empty `IN ("")` clauses removed automatically
- Splunk parser validation error "Unknown search command 'index'" resolved
- CIM RAG match counting now correctly handles multiple formats

---

## [1.2.3] - 2026-01-25

### Added

- **Token Usage Tracking in CLI**
  - Shows input/output/total tokens for each run
  - Format: `Tokens: 7,351 (in: 6,949, out: 402)`
  - Tracked per-run in `AgentResult.token_usage`

### Changed

- **RAG-Based Grounding Validation** (`src/agent/grounding.py`)
  - Removed all hardcoded CIM/Windows/Sysmon field lists (was 500+ fields)
  - Now dynamically loads fields from CIM RAG (563 fields from 26 data models)
  - Also queries Detection RAG for fields used in similar detections
  - Only minimal SPL built-ins remain hardcoded (`_time`, `_raw`, `count`, `sum`, etc.)
  - Field validation is now automatically updated when RAGs are refreshed

- **Fail-Fast Prompt Loading** (`src/agent/prompts.py`)
  - Removed all fallback prompts (was ~100 lines of inline prompts)
  - System now raises `PromptFileNotFoundError` if prompt files are missing
  - Ensures prompt files are always present and up-to-date
  - Skills and templates remain optional (won't crash if missing)

### Technical Details

The grounding validator now uses this hierarchy:
1. SPL indexed fields (`_time`, `_raw`, `host`, `source`, `sourcetype`, `index`)
2. SPL-generated fields (`count`, `sum`, `avg`, `min`, `max`, `nodename`, etc.)
3. CIM RAG fields (563 fields from all 26 data models)
4. Detection RAG fields (from similar detection rules)
5. User-specified fields (from the original request)
6. Fields in RAG context (trusted if mentioned in retrieved context)

---

## [1.2.4] - 2026-01-25

### Added

- **Input Quality Detection** (`src/agent/handlers.py`)
  - Rejects gibberish/unclear requests before LLM invocation
  - Uses keyword stem matching (90+ security-focused terms)
  - Supports CIM-specific terms: `cim`, `datamodel`, `tstats`, `endpoint`, `filesystem`, etc.
  - Handles dot-separated paths like `Endpoint.Processes`
  - Falls back to RAG similarity for borderline cases

- **Example Query Categories in Web UI** (`src/web/index.html`)
  - Split into "📋 Raw Log Queries" (blue accent) and "🎯 CIM Data Model Queries" (green accent)
  - 8 pre-built clickable example queries
  - Auto-fills input and submits on click

- **Session Token Tracking in Web UI**
  - Cumulative token counter persists across queries
  - Shows input/output breakdown in tooltip
  - Warning indicator when approaching 80K tokens

- **Supported Query Types Documentation** (`README.md`)
  - New section with examples of Raw Log and CIM queries
  - Full keyword table organized by category (Actions, Threats, Auth, Network, etc.)

### Fixed

- **Critical: Gibberish Detection Bug**
  - Was comparing unique chars against `len(text)` (with spaces)
  - Now correctly compares against `len(text_no_spaces)`
  - Fixed: CIM queries like "Detect brute force using CIM Authentication data model with tstats" were incorrectly rejected
  - Example: 19 unique chars / 82 total = 23% (FAIL) → 19 / 68 no-spaces = 28% (PASS)

- **Token Usage in API Response**
  - Added `token_usage` field to `QueryResponse` model
  - Now returns input_tokens, output_tokens, total_tokens per query

- **Copy SPL Button in Web UI**
  - Fixed by using `data-query-id` attribute and cache lookup
  - Previously failed due to template literal escaping issues

### Changed

- Lowered gibberish threshold from 25% to 20% unique chars (more lenient)
- Added 30+ new keyword stems for better CIM query recognition
- Debug logging now shows matched keywords: `keyword_matches=9, matched_stems={...}`

---

## [Unreleased]

### Planned

- Detection rule export to Splunk ES format
- Splunk metadata auto-discovery RAG
- Enhanced PDF Processing with OCR/Vision AI