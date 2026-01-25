# Splunk SPL Agent Project Summary

## Executive Overview

This document summarizes the design and implementation of an intelligent Splunk SPL Agent system. The agent assists security analysts in generating optimized, production-ready SPL queries by combining offline documentation knowledge, detection rule references, and real-time validation against a live Splunk Enterprise environment.

---

## Project Objectives

The primary goal is to create a Python library that serves as an intelligent assistant for building Splunk SPL queries. The system addresses three core needs: eliminating hallucination by grounding the agent in authoritative Splunk documentation, ensuring query validity by testing against actual Splunk data, and accelerating detection engineering by providing reference implementations from established security content repositories.

### Target Use Cases

The agent supports three input trigger types. The first is natural language descriptions, where users describe what they want to detect or search for in plain English. The second is log source specifications, where users specify a data source and the agent discovers available fields and suggests relevant queries. The third is IOC report processing, where users provide a URL or PDF containing indicators of compromise, and the agent extracts relevant information and generates detection queries.

---

## Project Status

**All five phases are complete.** The agent is fully functional and has been tested against a live Splunk Enterprise 10.0.2 instance.

| Phase | Component | Status |
|-------|-----------|--------|
| Foundation | Documentation Scraper, Crawler, RAG | ✅ Complete |
| 1 | Multi-LLM Provider Interface | ✅ Complete |
| 2 | Splunk REST API Client | ✅ Complete |
| 3 | Detection Rules Knowledge Base | ✅ Complete |
| 4 | Input Processor | ✅ Complete |
| 5 | Agent Orchestrator | ✅ Complete |

---

## Completed Components

### Component 1: Splunk Documentation Scraper and Crawler

**Status:** Complete

**Files Created:**
- `parser_spl_docs.py` — BeautifulSoup-based HTML parser with typed dataclasses
- `fetcher_spl_docs.py` — Playwright-based recursive web crawler with smart version detection
- `requirements.txt` — Dependencies for scraper and crawler

**Smart Update Features:**
- Automatic Splunk version detection (starts from 10.2, checks incrementally: 10.2 → 10.3 → ...)
- Stops after 2 consecutive 404s (no more versions)
- Version tracking via `data/splunk_spl_docs.stats.json`
- Only downloads when newer version is available or local data is empty
- Commands: `check`, `force`, `crawl`, default smart update

**Technical Details:**

| Attribute | Value |
|-----------|-------|
| Seed URLs | 9 (SPL Search Reference + Search Manual sections) |
| Pages crawled | **254** (includes all SPL commands) |
| Chunks created | **1225** (Splunk 10.2) |
| Output format | JSON Lines (`data/splunk_spl_docs.jsonl`) |
| Crawl duration | ~70 minutes (with sidebar link extraction) |
| Version detection | Auto-detect from help.splunk.com (10.2+) |
| Crawl boundary | `/en/splunk-enterprise/search/*/[version]/` |
| Sidebar extraction | `li[role="treeitem"] a` navigation links |

**Chunk Schema:**
```json
{
  "id": "sha256_hash_16chars",
  "content": "Plain text content of the section",
  "code_examples": [{"language": "spl", "code": "..."}],
  "tables": [{"headers": [...], "rows": [...]}],
  "chunk_index": 0,
  "total_chunks": 1,
  "metadata": {
    "title": "Page title",
    "section_heading": "Section heading",
    "section_id": "ariaid-titleN",
    "url": "https://help.splunk.com/...",
    "breadcrumb": "Navigation path",
    "manual": "search-manual or spl-search-reference",
    "scraped_at": "ISO timestamp"
  }
}
```

**CSS Selectors Used (Stable DITA-based):**

| Element | Selector |
|---------|----------|
| Main content | `render-html` |
| Sections | `article.topic.nested1` |
| Section headings | `h2.title.topictitle2` |
| Code blocks | `code-format.codeblock` |
| Tables | `table.table` |
| Internal links | `a.xref[href^="/en/"]` |
| Page title | `i18n-message[id="message.chunked.title"]` |

---

### Component 2: RAG Ingestion and Query System

**Status:** Complete

**Files Created:**
- `rag_spl_docs.py` — ChromaDB ingestion and query interface

**Technical Details:**

| Attribute | Value |
|-----------|-------|
| Vector database | ChromaDB (persistent, serverless) |
| Embedding model | BAAI/bge-small-en-v1.5 |
| Model size | 133 MB |
| Embedding dimensions | 384 |
| Distance metric | Cosine similarity |
| Documents indexed | ~242 (varies by version) |
| Ingestion time | ~292 seconds |
| Database location | `./vector_dbs/spl_docs/` |

**Query Performance:**
The system achieves sub-second query latency with similarity scores typically ranging from 0.7 to 0.85 for relevant results. Testing confirmed accurate retrieval for SPL syntax questions.

**Available Commands:**
```bash
python -m src.rag_spl_docs ingest                  # Ingest documentation (uses default data file)
python -m src.rag_spl_docs query "<text>"         # Single query
python -m src.rag_spl_docs context "<text>"       # LLM-ready context
python -m src.rag_spl_docs interactive            # Interactive mode
python -m src.rag_spl_docs stats                  # Database statistics
```

**Programmatic Interface:**
```python
from src.rag_spl_docs import SplunkRAG

rag = SplunkRAG()
context = rag.get_context_for_agent("How do I use stats?", top_k=5)
results = rag.query("calculate average by host", top_k=10)
```

---

### Component 3: Multi-LLM Provider Interface (Phase 1)

**Status:** Complete

**Files Created:**
- `llm_provider.py` — Unified interface with provider-specific implementations
- `config.yaml` — API key and provider configuration

**Supported Providers:**

| Provider | Library | Status | Notes |
|----------|---------|--------|-------|
| Groq | openai (compatible) | ✅ Tested | Primary provider, 14,400 req/day free |
| Mistral | openai (compatible) | ✅ Implemented | 1B tokens/month free |
| OpenRouter | openai (compatible) | ✅ Implemented | 50 req/day free tier |
| Claude | anthropic | ✅ Implemented | Paid API |
| OpenAI | openai | ✅ Implemented | Paid API |
| DeepSeek | openai (compatible) | ✅ Implemented | Low-cost option |

**Current Configuration:**
- Default provider: Groq
- Model: llama-3.3-70b-versatile
- Performance: ~1,252ms latency, 177 input tokens, 171 output tokens (test query)

**Key Features:**
- Common interface across all providers via abstract base class
- Automatic retry with exponential backoff
- Token usage tracking
- Free provider support for development/testing

**Available Commands:**
```bash
python llm_provider.py test <provider>    # Test a specific provider
python llm_provider.py list               # List all providers
python llm_provider.py free               # List free providers
```

---

### Component 4: Splunk REST API Client (Phase 2)

**Status:** Complete

**Files Created:**
- `splunk_client.py` — REST API client module

**Target Environment:**

| Attribute | Value |
|-----------|-------|
| Splunk Version | 10.0.2 |
| Architecture | Linux x86_64 |
| Host | your-splunk-host |
| API Port | 8089 |
| Authentication | Token-based (JWT) or username/password |
| SSL | Self-signed certificate (verification disabled) |

**Implemented Capabilities:**

| Capability | Method | API Endpoint |
|------------|--------|--------------|
| Test connection | `test_connection()` | `/services/server/info` |
| List indexes | `list_indexes()` | `/services/data/indexes` |
| List sourcetypes | `list_sourcetypes()` | `\| metadata type=sourcetypes` |
| Get field summary | `get_fields()` | `\| fieldsummary` |
| Run oneshot search | `run_oneshot()` | `/services/search/jobs/export` |
| Create search job | `create_job()` | `/services/search/jobs` |
| Get job status | `get_job_status()` | `/services/search/jobs/{sid}` |
| Get job results | `get_job_results()` | `/services/search/jobs/{sid}/results` |
| Validate query | `validate_query()` | `/services/search/parser` |
| Test query | `test_query()` | Limited execution with time range |

**Available Commands:**
```bash
python splunk_client.py test                        # Test connection
python splunk_client.py indexes                     # List indexes
python splunk_client.py sourcetypes [index]         # List sourcetypes
python splunk_client.py fields <index> [sourcetype] # Get fields
python splunk_client.py search "<spl>"              # Run search
python splunk_client.py validate "<spl>"            # Validate syntax
```

---

### Component 5: Detection Rules Knowledge Base (Phase 3)

**Status:** Complete

**Files Created:**
- `fetcher_detections.py` — YAML detection file parser with smart GitHub version detection
- `rag_detections.py` — ChromaDB ingestion and query interface

**Smart Update Features:**
- Automatic GitHub release version detection via API
- Version tracking via `data/splunk_spl_detections.stats.json`
- Auto-clone/update of security_content repository
- Only downloads when newer version is available
- Commands: `check`, `force`, `stats`, `show`, default smart update

**Data Source:**
- Repository: https://github.com/splunk/security_content/tree/develop/detections
- Branch: develop
- Format: YAML files

**Detection Statistics:**

| Metric | Value |
|--------|-------|
| Total detections parsed | 1,978 |
| Unique MITRE ATT&CK techniques | 340 |
| Unique analytic stories | 333 |
| Unique data sources | 278 |
| Ingestion time | ~17.5 minutes |
| Database location | `./vector_dbs/detections/` |

**Breakdown by Category:**

| Category | Count |
|----------|-------|
| Endpoint | 1,361 |
| Cloud | 321 |
| Application | 108 |
| Network | 100 |
| Web | 86 |

**Breakdown by Type:**

| Type | Count |
|------|-------|
| TTP | 1,035 |
| Anomaly | 722 |
| Hunting | 206 |
| Correlation | 15 |

**Detection Schema:**
```json
{
  "id": "uuid",
  "name": "Detection name",
  "description": "What it detects",
  "search": "SPL query",
  "data_source": ["Sysmon EventID 1", "Windows Event Log Security 4688"],
  "mitre_attack_id": ["T1003.001"],
  "analytic_story": ["Credential Dumping"],
  "type": "TTP|Anomaly|Hunting|Correlation",
  "status": "production|experimental|deprecated",
  "security_domain": "endpoint|network|threat|identity",
  "how_to_implement": "Implementation guidance",
  "known_false_positives": "Expected false positive scenarios"
}
```

**Available Commands:**
```bash
# Smart update (auto-detects GitHub version, downloads if needed)
python -m src.fetcher_detections             # Smart update
python -m src.fetcher_detections check       # Check for updates
python -m src.fetcher_detections force       # Force re-download
python -m src.fetcher_detections stats       # Show local statistics
python -m src.fetcher_detections show <id>   # Display specific detection

# Manual parsing (from existing directory)
python -m src.fetcher_detections parse <detections_dir>

# RAG operations
python -m src.rag_detections ingest                      # Ingest into ChromaDB (uses default data file)
python -m src.rag_detections query "<text>"              # Semantic search
python -m src.rag_detections mitre <technique_id>        # Search by MITRE ID
python -m src.rag_detections story "<story_name>"        # Search by analytic story
python -m src.rag_detections context "<query>"           # Get LLM context
python -m src.rag_detections interactive                 # Interactive mode
```

**Future Data Sources (Planned):**
- SigmaHQ: https://github.com/SigmaHQ/sigma/tree/master/rules
- Elastic: https://github.com/elastic/detection-rules
- Chronicle: https://github.com/chronicle/detection-rules
- Azure Sentinel: https://github.com/Azure/Azure-Sentinel/tree/master/Solutions

---

### Component 6: Input Processor (Phase 4)

**Status:** Complete

**Files Created:**
- `input_processor.py` — Unified input handling module

**Supported Input Types:**

| Type | Description | Handler |
|------|-------------|---------|
| Natural Language | Plain English detection descriptions | `NaturalLanguageHandler` |
| Log Source | Splunk search terms (index=, sourcetype=) | `LogSourceHandler` |
| IOC Report | URLs or PDF files with threat intelligence | `IOCReportHandler` |

**IOC Extraction Capabilities:**

| IOC Type | Pattern | Base Confidence |
|----------|---------|-----------------|
| SHA256 | 64 hex characters | 0.95 |
| SHA1 | 40 hex characters | 0.95 |
| MD5 | 32 hex characters | 0.90 |
| IPv4 | Valid octet pattern | 0.85 |
| IPv6 | Colon-separated hex | 0.85 |
| URL | http/https/ftp scheme | 0.90 |
| Domain | TLD-validated pattern | 0.75 |
| Email | Standard email format | 0.80 |
| File Name | Common extensions | 0.85 |
| Windows Path | Drive letter pattern | 0.80 |
| Registry Key | HKEY_ prefix pattern | 0.90 |
| CVE | CVE-YYYY-NNNNN format | 0.95 |
| MITRE ATT&CK | T/S followed by digits | 0.95 |

**URL Fetching:** Playwright-based (headless Chromium) for JavaScript-rendered pages

**PDF Processing:** pdfplumber library for text and table extraction

**Available Commands:**
```bash
python input_processor.py process "<input>"     # Process and classify
python input_processor.py classify "<input>"    # Just classify type
python input_processor.py extract "<file/url>"  # Extract IOCs
python input_processor.py interactive           # Interactive mode
```

**Test Results:**
```
Input: "Detect brute force login attempts against Active Directory"
Type: natural_language
Confidence: 0.80
Intent: detect brute force login attempts against active directory
Entities: attack_type:brute force, data_source:active directory
```

---

### Component 7: Agent Orchestrator (Phase 5)

**Status:** Complete

**Files Created:**
- `src/agent/` — Modularized agent package:
  - `orchestrator.py` — Main SplunkAgent class
  - `handlers.py` — Input type handlers (natural language, log source, IOC)
  - `validation.py` — Query validation, refinement, and SPL linting
  - `prompts.py` — Prompt template loading from external files (fail-fast, no fallbacks)
  - `models.py` — Data models (AgentResult, QueryStatus)
  - `config.py` — Configuration management
  - `cli.py` — Command-line interface (includes token usage display)
  - `reasoning.py` — Chain of Thought reasoning trace
  - `e2e_workflow.py` — End-to-end IOC workflow
  - `grounding.py` — RAG-based field validation (uses CIM RAG + Detection RAG)

**Workflow Steps:**

1. **Input Processing** — Parse and classify the input trigger
2. **Context Retrieval** — Query both RAG collections for relevant documentation and detection examples
3. **Initial Query Generation** — Use LLM to generate candidate SPL query
4. **Metadata Discovery** — Query Splunk API to verify indexes, sourcetypes, and fields exist
5. **Query Validation** — Execute query against Splunk (limited time range)
6. **Result Analysis** — Assess query quality based on results
7. **Iterative Refinement** — If errors occur, loop back with feedback (max 5 iterations)
8. **Output** — Return final query with documentation and explanation

**Key Features:**

| Feature | Description |
|---------|-------------|
| No-Macro Policy | LLM instructed to generate raw SPL without Enterprise Security macros |
| Iterative Refinement | Up to 5 iterations with error feedback |
| Dual RAG Context | Retrieves from both documentation and detection rule collections |
| Lazy Initialization | Components loaded on demand |
| Graceful Degradation | Operates without Splunk connection (partial validation) |

**Agent Configuration:**
```yaml
agent:
  max_iterations: 5
  validation_time_range: "-24h"
  validation_max_results: 100
  enable_splunk_validation: true
  enable_field_discovery: true
```

**Available Commands:**
```bash
python -m src.agent status                # Show component status
python -m src.agent run "<input>"         # Generate SPL query
python -m src.agent interactive           # Interactive mode
```

**Test Results:**
```
Input: "Detect brute force login attempts against Windows systems"
Status: SUCCESS
Iterations: 1
Total Time: 13.70s
Validated: Yes
Result Count: 0 (no matching data in test environment)
```

**Sample Generated Query:**
```spl
index=win_event_logs sourcetype=win_security
EventCode=4625 
Logon_Type=2 
| rex field=_raw "Account Name:\s+(?<Account_Name>[^,]+)"
| rex field=_raw "Computer Name:\s+(?<ComputerName>[^,]+)"
| rex field=_raw "Source Network Address:\s+(?<Source_Network_Address>[^,]+)"
| bucket span=2m _time 
| stats dc(Account_Name) AS unique_accounts values(Account_Name) as user 
  values(ComputerName) as dest values(Source_Network_Address) as src 
  by _time, ProcessName, ComputerName
| eventstats avg(unique_accounts) as comp_avg, stdev(unique_accounts) as comp_std 
  by ProcessName, ComputerName
| eval upperBound=(comp_avg+comp_std*3) 
| eval isOutlier=if(unique_accounts > 10 and unique_accounts >= upperBound, 1, 0)
| search isOutlier=1
```

---

## Technical Environment

### Hardware Specifications (Development Machine)

| Component | Specification |
|-----------|---------------|
| CPU | AMD Ryzen 7 5825U (8 cores, 16 threads) |
| RAM | 64 GB |
| Storage | 921 GB SSD (45+ GB available) |
| GPU | Integrated AMD Radeon (no dedicated GPU) |
| OS | Kali Linux (Debian-based) |

### Software Dependencies

**Installed:**
- Python 3.13
- Playwright + Chromium
- BeautifulSoup4 + lxml
- ChromaDB
- sentence-transformers (BAAI/bge-small-en-v1.5)
- PyTorch (CPU-only)
- httpx
- pyyaml
- pdfplumber
- openai (for Groq/Mistral/OpenRouter compatibility)

### Target Splunk Environment

| Attribute | Value |
|-----------|-------|
| Deployment | Splunk Enterprise |
| Version | 10.0.2 |
| OS | Linux x86_64 |
| API Access | REST API enabled (port 8089) |
| Authentication | JWT token or username/password |
| SSL | Self-signed certificate (verification disabled) |

---

## Architecture Decisions

### Decision 1: ChromaDB over Redis

ChromaDB was selected for vector storage due to zero server configuration requirements, simpler setup for the document scale, built-in persistence without external processes, and sufficient performance for the use case.

### Decision 2: BGE-small-en-v1.5 Embedding Model

This model was selected for its optimal balance of speed and quality on CPU, 384-dimensional output keeping storage requirements manageable, strong performance on technical documentation retrieval benchmarks, and fast inference at sub-10ms per query.

### Decision 3: Multi-Provider LLM Support

The system supports multiple providers to avoid vendor lock-in, allow cost optimization, enable fallback if one provider is unavailable, and allow comparison of output quality across models.

### Decision 4: Groq as Default Provider

Groq was selected as the default provider due to its generous free tier (14,400 requests/day), fast inference (300+ tokens/sec), access to Llama 3.3 70B model, and OpenAI-compatible API.

### Decision 5: Iterative Refinement Workflow

The agent uses an iterative approach rather than single-shot generation to validate queries against real data, catch errors before delivering to the user, and optimize based on actual field availability.

### Decision 6: No-Macro Policy

The agent explicitly instructs the LLM to avoid Splunk macros (backtick syntax) because the detection rules from Splunk Security Content reference macros that require Enterprise Security or additional apps. Generating raw SPL ensures compatibility with standalone Splunk installations.

### Decision 7: Separation of Knowledge Bases

SPL documentation and detection rules are stored in separate ChromaDB collections to allow independent updates, enable targeted retrieval depending on task type, and maintain clear separation of concerns.

### Decision 8: RAG-Based Grounding Validation

The grounding system validates generated SPL queries against known fields to prevent hallucination. Rather than maintaining hardcoded field lists (which become outdated), the system dynamically loads fields from:
1. CIM RAG (563 fields from 26 data models)
2. Detection RAG (fields used in similar detection rules)
3. Minimal SPL built-ins only (`_time`, `_raw`, `count`, `sum`, etc.)

This ensures field validation stays current with official Splunk documentation automatically.

### Decision 9: Fail-Fast Prompt Loading

The prompt system requires all prompt files to exist and raises `PromptFileNotFoundError` if any are missing. This fail-fast approach ensures:
- No silent degradation to inline fallback prompts
- Immediate awareness of missing configuration
- Prompt files are always the single source of truth

---

## File Inventory

### Complete File List

| File | Phase | Purpose | Status |
|------|-------|---------|--------|
| `parser_spl_docs.py` | Foundation | HTML parsing for Splunk docs | ✅ Complete |
| `fetcher_spl_docs.py` | Foundation | Recursive web crawler | ✅ Complete |
| `requirements.txt` | Foundation | Scraper/crawler dependencies | ✅ Complete |
| `rag_spl_docs.py` | Foundation | Documentation RAG system | ✅ Complete |
| `llm_provider.py` | 1 | Multi-LLM abstraction layer | ✅ Complete |
| `config.yaml` | 1 | API keys and configuration | ✅ Complete |
| `splunk_client.py` | 2 | Splunk REST API client | ✅ Complete |
| `fetcher_detections.py` | 3 | Detection YAML parser | ✅ Complete |
| `rag_detections.py` | 3 | Detection knowledge base | ✅ Complete |
| `input_processor.py` | 4 | Input trigger handlers | ✅ Complete |
| `src/agent/` | 5 | Main agent package (modularized) | ✅ Complete |
| `src/agent/grounding.py` | 5 | RAG-based field validation | ✅ Complete |
| `fetcher_cim_docs.py` | 6 | CIM data model crawler | ✅ Complete |
| `rag_cim_docs.py` | 6 | CIM RAG system | ✅ Complete |
| `fetcher_attack_data.py` | 6 | Attack data fetcher | ✅ Complete |
| `rag_attack_data.py` | 6 | Attack data RAG system | ✅ Complete |
| `src/api/` | 7 | FastAPI REST API | ✅ Complete |
| `src/web/` | 7 | Web dashboard UI | ✅ Complete |

### Data Directories

| Directory | Contents |
|-----------|----------|
| `data/` | Crawled documentation, detection rules, and datasets |
| `vector_dbs/` | ChromaDB vector databases |
| `vector_dbs/spl_docs/` | SPL documentation |
| `vector_dbs/detections/` | Detection rules |
| `vector_dbs/cim/` | CIM data models |
| `vector_dbs/attack_data/` | Attack datasets |
| `prompts/` | External prompt files (system prompt, skills, templates) |
| `security_content/` | Cloned Splunk security content repository (temporary) |

### Generated Data Files

| File | Description |
|------|-------------|
| `data/splunk_spl_docs.jsonl` | Parsed SPL documentation chunks |
| `data/splunk_spl_docs.stats.json` | SPL docs version and statistics |
| `data/splunk_spl_detections.jsonl` | Parsed detection rules |
| `data/splunk_spl_detections.stats.json` | Detection rules version and statistics |
| `data/splunk_cim_docs.jsonl` | Parsed CIM data model fields |
| `data/splunk_cim_docs.stats.json` | CIM docs version and statistics |
| `data/splunk_attack_data.jsonl` | Parsed attack datasets |
| `data/splunk_attack_data.stats.json` | Attack data version and statistics |
| `data/crawl_manifest.json` | Crawl metadata (can be deleted) |

---

## Usage Guide

### Complete Command Reference

| Module | Command | Description |
|--------|---------|-------------|
| **Agent** | `python -m src.agent status` | Show all component status |
| | `python -m src.agent run "<query>"` | Generate SPL query |
| | `python -m src.agent interactive` | Interactive mode |
| **Splunk** | `python -m src.splunk_client test` | Test connection |
| | `python -m src.splunk_client indexes` | List indexes |
| | `python -m src.splunk_client search "<spl>"` | Run search |
| **Fetchers** | `python -m src.fetcher_spl_docs` | Update SPL docs |
| | `python -m src.fetcher_detections` | Update detections |
| | `python -m src.fetcher_cim_docs` | Update CIM docs |
| | `python -m src.fetcher_attack_data` | Update attack data |
| **RAGs** | `python -m src.rag_spl_docs ingest` | Ingest SPL docs |
| | `python -m src.rag_detections ingest` | Ingest detections |
| | `python -m src.rag_cim_docs ingest` | Ingest CIM docs |
| | `python -m src.rag_attack_data ingest` | Ingest attack data |
| | `python -m src.rag_spl_docs query "<query>"` | Search SPL docs |
| | `python -m src.rag_detections query "<query>"` | Search detections |
| | `python -m src.rag_cim_docs query "<query>"` | Search CIM fields |
| | `python -m src.rag_attack_data query "<query>"` | Search attack data |

### Quick Start

```bash
# 1. Check agent status
python -m src.agent status

# 2. Generate a query from natural language
python -m src.agent run "Detect credential dumping from LSASS"

# 3. Explore a log source
python -m src.agent run "index=windows sourcetype=WinEventLog:Security"

# 4. Interactive mode
python -m src.agent interactive
```

### Configuration

Edit `config.yaml` to configure:
- LLM provider and API keys
- Splunk connection credentials
- Agent behavior (max iterations, time range)

### Updating Knowledge Bases

```bash
# Re-crawl documentation (if Splunk docs update)
python -m src.fetcher_spl_docs

# Smart update SPL documentation (auto-detects new Splunk versions)
python -m src.fetcher_spl_docs                # Check & download if needed
python -m src.fetcher_spl_docs force          # Force re-crawl
python -m src.rag_spl_docs ingest

# Smart update detection rules (auto-checks GitHub releases)
python -m src.fetcher_detections              # Check & download if needed
python -m src.fetcher_detections force        # Force re-download
python -m src.rag_detections reset
python -m src.rag_detections ingest
```

---

## Future Enhancements

### Planned Improvements

1. **Additional Detection Sources** — Integrate SigmaHQ, Elastic, Chronicle, and Azure Sentinel rules
2. **Local LLM Support** — Add support for local models when GPU hardware is available
3. **Web Interface** — Build a simple Flask/FastAPI frontend
4. **Query History** — Store and recall previously generated queries
5. **Correlation Search Generation** — Generate multi-stage correlation searches
6. **Alert Configuration** — Generate complete alert definitions with actions

---

## Document Metadata

| Attribute | Value |
|-----------|-------|
| Created | January 2025 |
| Last Updated | January 2025 |
| Status | Complete |
| Phases Complete | 5 of 5 |
