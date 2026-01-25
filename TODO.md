# Splunk Detection Engineer Agent - TODO & Roadmap

> **Single source of truth for all project improvements, features, and ideas.**
> 
> Each item includes description, rationale, subtasks, dependencies, and acceptance criteria.
> Complexity: 🟢 Small | 🟡 Medium | 🔴 Large

---

## Table of Contents

- [✅ Completed](#-completed)
- [🔴 High Priority](#-high-priority)
- [🟡 Medium Priority](#-medium-priority)
- [🟢 Lower Priority](#-lower-priority)
- [🔬 Research Needed](#-research-needed)
- [📋 Documentation & Presentation](#-documentation--presentation)

---

## ✅ Completed

### Smart Version Detection for Data Fetchers
- **Status**: ✅ Done (v1.1.0)
- **Description**: Fetchers automatically check for newer versions and only download when needed
- **Implementation**:
  - `fetcher_spl_docs.py`: Checks Splunk versions starting from 10.2 (10.2 → 10.3 → ...)
  - `fetcher_detections.py`: Checks GitHub releases via API
  - Stats files track version, chunks, last update
  - Empty data detection triggers re-download

### File Renaming & Project Structure
- **Status**: ✅ Done (v1.1.0)
- **Files renamed**:
  - `splunk_agent.py` → `agent.py`
  - `splunk_rag_ingest.py` → `rag_spl_docs.py`
  - `detection_rag.py` → `rag_detections.py`
  - `splunk_crawler.py` → `fetcher_spl_docs.py`
  - `detection_downloader.py` → `fetcher_detections.py`
  - `splunk_scraper.py` → `parser_spl_docs.py`

### Code Modularization
- **Status**: ✅ Done (v1.2.0)
- **Description**: Split `agent.py` (1500+ lines) into modular package
- **Implementation**:
  ```
  src/agent/
  ├── __init__.py          # Package exports
  ├── config.py            # AgentConfig class
  ├── models.py            # QueryStatus, AgentResult
  ├── prompts.py           # Prompt templates and loader
  ├── handlers.py          # Input type handlers
  ├── validation.py        # Query validation logic
  ├── orchestrator.py      # Main SplunkAgent class
  └── cli.py               # CLI interface
  ```

### SPL Query Quality & Linting
- **Status**: ✅ Done (v1.2.1)
- **Description**: Added SPL syntax validation and auto-fixing to prevent common LLM errors
- **Implementation**:
  - Added `lint_spl_query()` function in `validation.py` to catch:
    - Hash comments (`#`) - automatically removed
    - Invalid `tstats from <index>` syntax - flagged as error
    - Non-indexed fields in tstats without datamodel - flagged as error
    - Backtick macros - flagged as error
    - Multi-valued field warnings (Account_Name)
  - Updated `SKILL_spl_syntax.md` with comprehensive SPL syntax rules
  - Updated `system_prompt.md` with critical syntax constraints
  - Enhanced `NO_MACRO_INSTRUCTION` with tstats and comment rules
  - LLM responses are auto-linted before validation
  - Validation feedback now includes lint issues for better refinement
- **Fixes issues**:
  - LLM generating `# comments` (invalid SPL)
  - LLM using `tstats from winlog_security` instead of `WHERE index=`
  - LLM using non-indexed fields with tstats without datamodel
  - Missing mvindex() for multi-valued Windows fields

### Input Quality Detection (Anti-Gibberish)
- **Status**: ✅ Done (v1.2.4)
- **Description**: Rejects gibberish/unclear requests before wasting LLM tokens
- **Implementation**:
  - `_check_input_quality()` in `src/agent/handlers.py`
  - 90+ security keyword stems for fast matching
  - CIM-specific terms: `cim`, `datamodel`, `tstats`, `endpoint`, `filesystem`
  - Dot-splitting for paths like `Endpoint.Processes`
  - Falls back to RAG similarity for borderline cases
  - Fixed bug: was comparing unique chars against text length WITH spaces
- **Fixes issues**:
  - CIM queries incorrectly rejected as "gibberish"
  - Random text like "asdfghjkl" no longer processed by LLM

### Web UI Example Queries & Session Tracking
- **Status**: ✅ Done (v1.2.4)
- **Description**: Added categorized example queries and session token tracking
- **Implementation**:
  - Split examples into "Raw Log" (blue) and "CIM Data Model" (green) categories
  - 8 clickable example buttons that auto-fill and submit
  - Session token counter (cumulative across queries)
  - Warning when approaching 80K tokens
  - Fixed copy button (was broken due to escaping)
  - Token usage now returned in API response

### System Prompt Externalization
- **Status**: ✅ Done (v1.2.0)
- **Description**: Moved prompts to external files for easier customization
- **Implementation**:
  ```
  prompts/
  ├── system_prompt.md              # Main agent instructions
  ├── SKILL_spl_syntax.md           # SPL syntax best practices
  ├── SKILL_detection_engineering.md # Detection patterns
  ├── SKILL_ioc_extraction.md       # IOC hunting
  └── templates/
      ├── detection_template.spl
      ├── hunting_template.spl
      └── exploration_template.spl
  ```

### CIM Data Models RAG
- **Status**: ✅ Done (v1.2.0)
- **Description**: RAG for Splunk Common Information Model field definitions
- **Source**: https://help.splunk.com/en/data-management/common-information-model/
- **Files**:
  - `src/fetcher_cim_docs.py` - Smart version detection crawler
  - `src/rag_cim_docs.py` - ChromaDB RAG for CIM fields
- **Data**: `data/splunk_cim_docs.jsonl`, `data/splunk_cim_docs.stats.json`

### Attack Data RAG Integration
- **Status**: ✅ Done (v1.2.0)
- **Description**: RAG for Splunk Attack Data repository
- **Source**: https://github.com/splunk/attack_data
- **Files**:
  - `src/fetcher_attack_data.py` - GitHub release checker + parser
  - `src/rag_attack_data.py` - ChromaDB RAG for attack datasets
- **Data**: `data/splunk_attack_data.jsonl`, `data/splunk_attack_data.stats.json`

### Web Interface (Dashboard)
- **Status**: ✅ Done (v1.2.0)
- **Description**: Web-based UI with FastAPI backend + vanilla HTML/JS/CSS frontend
- **Files**:
  - `src/api/server.py` - FastAPI backend with REST endpoints
  - `src/api/models.py` - Pydantic request/response models
  - `src/web/index.html` - Dashboard UI
  - `src/web/css/style.css` - Dark theme styling
  - `src/web/js/api.js` - API client

### CIM Parser Improvements
- **Status**: ✅ Done (v1.2.1)
- **Description**: Fixed CIM field name extraction from HTML tables
- **Changes**:
  - Fixed field name extraction (was extracting data model names instead of actual fields)
  - Added hierarchical field name handling (e.g., "Alerts.action" → "action")
  - Enhanced `get_context_for_agent()` to extract 70+ standard CIM field names
  - Improved regex patterns for field extraction

### Documentation Updates
- **Status**: ✅ Done (v1.2.1)
- **Description**: Comprehensive documentation update with command cheat sheet
- **Files Updated**:
  - `README.md` - Added complete command cheat sheet
  - `CHANGELOG.md` - Added v1.2.1 changes
  - `docs/TROUBLESHOOTING.md` - Added CIM and Attack Data troubleshooting
  - `docs/API_REFERENCE.md` - Added CIM and Attack Data APIs
  - `docs/PROJECT_STRUCTURE.md` - Added complete command reference table
  - `src/web/js/app.js` - Application logic
- **Features**:
  - Chat interface for natural language queries
  - IOC document upload (PDF/URL)
  - RAG search across all knowledge bases
  - Configuration settings panel
  - Real-time status indicators
- **Run**: `uvicorn src.api.server:app --reload`

### Dashboard Configuration Screen
- **Status**: ✅ Done (v1.2.0)
- **Description**: Settings panel in web UI for LLM and Splunk configuration
- **Features**:
  - LLM provider selection and API key input
  - Splunk connection settings
  - Test connection button
  - Save/load configuration

---

### Chain of Thought (CoT) Reasoning Display
- **Status**: ✅ Done (v1.2.1)
- **Description**: Show agent's reasoning process for transparency
- **Implementation**:
  - `src/agent/reasoning.py` - ReasoningTrace and ReasoningStep classes
  - CLI `--reason` flag and `reason on/off` interactive commands
  - Web UI toggle and real-time reasoning panel
  - SSE streaming for real-time updates (`/api/query/stream`)
- **Features**:
  - Step-by-step visualization of agent thinking
  - RAG retrieval scores and match counts
  - Confidence scoring based on RAG results
  - Progress indicators and timing information

### End-to-End IOC → Detection → Validation Workflow
- **Status**: ✅ Done (v1.2.2)
- **Description**: Complete automated pipeline from IOC report to validated detection
- **Endpoint**: `POST /api/workflow/e2e`
- **Files**:
  - `src/agent/e2e_workflow.py` - Main workflow orchestration
  - `prompts/PROMPT_ioc_hunting.md` - IOC query generation prompt
- **Workflow Stages**:
  1. **Input**: IOC report (PDF file or HTML URL)
  2. **IOC Extraction**: Parse IPs, domains, hashes, file paths
  3. **Detection Build**: Generate SPL query using Detection RAG
  4. **Best Practices**: Check query against SPL Docs RAG
  5. **Metadata Validation**: Validate syntax against Splunk
  6. **Attack Data Test**: Find relevant datasets for validation
  7. **Complete**: Return full results with confidence score
- **Features**:
  - Automatic false positive filtering (vendor domains, system files)
  - SPL linting and auto-fixing (empty IN clauses, missing search prefix)
  - Multi-field IOC search (file_hash, MD5, file_path, Image)
  - Confidence scoring (0-100%)
- **Example**:
  ```bash
  curl -X POST "http://localhost:8000/api/workflow/e2e" \
    -F "url=https://securelist.com/honeymyte-kernel-mode-rootkit/118590/" \
    -F "validate_splunk=true" \
    -F "test_attack_data=true"
  ```

### Prompt Engineering Externalization
- **Status**: ✅ Done (v1.2.2)
- **Description**: All prompt content externalized to `prompts/` folder
- **Files**:
  ```
  prompts/
  ├── DIRECTIVE_spl_syntax.md      # Critical SPL syntax rules
  ├── PROMPT_query_generation.md   # Main query generation prompt
  ├── PROMPT_refinement.md         # Query refinement prompt
  ├── PROMPT_ioc_hunting.md        # IOC hunting query prompt
  ├── PROMPT_log_source.md         # Log source exploration prompt
  └── (existing system_prompt.md and SKILL files)
  ```
- **Benefits**:
  - Easy prompt customization without code changes
  - Version control for prompt engineering
  - Clear separation of concerns

### Agent Grounding (Prevent Hallucination)
- **Status**: ✅ Done (v1.2.3)
- **Description**: Restrict agent to only use local data sources, validate all fields
- **Implementation**:
  - `src/agent/grounding.py` - RAG-based field validation (no hardcoded field lists)
  - Updated `prompts/system_prompt.md` with explicit grounding rules
  - Grounding validation added to all handlers
- **Features**:
  - **RAG-Based Validation**: Fields validated against CIM RAG (563 fields from 26 data models)
  - Also queries Detection RAG for fields used in similar detections
  - Unknown field detection with suggestions for alternatives
  - Grounding score (0-100%) based on field validation
  - Warnings for unverified fields in responses
  - Source attribution (CIM, detection RAG, SPL docs, etc.)
- **Minimal Hardcoded Fields** (only SPL built-ins that never change):
  - Splunk indexed fields (_time, _raw, host, source, sourcetype, index)
  - SPL-generated fields (count, sum, avg, values, nodename, etc.)
- **Dynamic Field Sources** (from RAGs):
  - CIM fields loaded from CIM RAG (auto-updated when RAG refreshes)
  - Detection fields extracted from similar detections in Detection RAG
  - User-specified fields from the original request
  - Fields mentioned in RAG context are trusted

### Token Usage Tracking
- **Status**: ✅ Done (v1.2.3)
- **Description**: Track and display LLM token usage per query generation run
- **Implementation**:
  - `src/llm_provider.py` - Token extraction from all provider responses
  - `src/agent/orchestrator.py` - Per-run token aggregation
  - `src/agent/cli.py` - Token display in output
- **Features**:
  - Shows input/output/total tokens in CLI output
  - Format: `Tokens: 7,351 (in: 6,949, out: 402)`
  - Available in `AgentResult.token_usage` dictionary

### Fail-Fast Prompt Loading
- **Status**: ✅ Done (v1.2.3)
- **Description**: Remove fallback prompts, require all prompt files to exist
- **Implementation**:
  - `src/agent/prompts.py` - Raises `PromptFileNotFoundError` if prompts missing
  - Removed ~100 lines of inline fallback prompts
- **Benefits**:
  - No silent degradation to inline prompts
  - Immediate awareness of missing configuration
  - Prompt files are the single source of truth

---

## 🟡 Medium Priority

### 2. Splunk Metadata RAG (Auto-Generated)
- **Complexity**: 🟡 Medium
- **Description**: Automatically extract and cache Splunk metadata on first connection
- **Why**: LLM needs to know what data actually exists in user's environment

#### Features:
- [ ] Extract indexes, sourcetypes, sources on first run
- [ ] Extract available fields per sourcetype
- [ ] Cache results locally (refresh on demand)
- [ ] RAG for "do I have this data?" queries

#### Metadata to Extract:
```
- Indexes: name, event count, size
- Sourcetypes: name, associated indexes, sample fields
- Fields: name, type, associated sourcetypes
- Data Models: accelerated data models available
```

#### SPL Approaches (from user research):

**Option A - REST API (Fast ~20s, fewer fields):**
```spl
| rest /services/data/indexes
| rest /services/data/props/calcfields
| rest /services/data/props/extractions
| rest /services/data/props/fieldaliases
| rest /services/data/props/lookups
```

**Option B - Map with Fieldsummary (Slow ~5-10min, comprehensive):**
```spl
| tstats latest(sourcetype) WHERE index=* BY index source 
| map search="search index=$index$ | fieldsummary | fields field"
```

**Option C - CIM Only (Recommended):**
Use CIM Data Models RAG instead of raw field extraction.

#### Subtasks:
1. Create `splunk_metadata.py` for extraction
2. Implement caching with TTL
3. Create refresh mechanism
4. Build RAG from cached metadata
5. Add "metadata freshness" indicator to UI

#### Dependencies:
- Splunk connection configured

#### Acceptance Criteria:
- [ ] On first Splunk connection, metadata is extracted
- [ ] Cached locally with timestamp
- [ ] Agent knows what indexes/sourcetypes are available
- [ ] User can trigger refresh from UI

---

### 4. Chain of Thought (CoT) Display + Real-Time Process Visualization
- **Complexity**: 🟡 Medium
- **Status**: ⚡ Core Implementation Done (v1.2.1)
- **Description**: Show the agent's reasoning process and source attribution with real-time visual updates in the dashboard
- **Why**: Users need to trust and verify the agent's decisions; transparency builds confidence

#### Implemented Features (v1.2.1):
- [x] Step-by-step reasoning display (`--reason` flag in CLI)
- [x] ReasoningTrace data structure with typed steps
- [x] Input classification tracking
- [x] RAG retrieval tracking with match counts and scores
- [x] Validation iteration tracking
- [x] Refinement step tracking
- [x] Confidence score based on RAG match quality
- [x] CLI flag `--reason` / `-r` for reasoning output
- [x] Interactive mode `reason on/off` toggle
- [x] API endpoint with reasoning in response (`show_reasoning: true`)
- [x] SSE streaming endpoint `/api/query/stream`

#### Still TODO:
- [x] Web UI visualization (progress indicators, collapsible sections) ✅ v1.2.1
- [ ] Decision explanations ("I chose this field because...")
- [ ] Technical details toggle in UI
- [x] Weighted scoring display in UI ✅ v1.2.1 (confidence bar)

#### Dashboard Integration:
```
┌─────────────────────────────────────────────────────┐
│ 🔄 Processing: "Detect brute force attacks"         │
├─────────────────────────────────────────────────────┤
│ ✓ Step 1: Input Classification                      │
│   └─ Type: Natural Language → Detection Request     │
│   └─ Confidence: 0.94                               │
│                                                     │
│ ✓ Step 2: RAG Retrieval                             │
│   └─ SPL Docs: 3 matches (best: 0.89)               │
│   └─ Detections: 2 matches (best: 0.91)             │
│   └─ CIM Fields: process_name, user, dest           │
│                                                     │
│ ⏳ Step 3: Query Generation...                      │
│   └─ Using template: detection_template.spl         │
│   └─ Applying CIM field mapping                     │
└─────────────────────────────────────────────────────┘
```

#### Implementation:
- WebSocket connection for real-time updates
- Server-Sent Events (SSE) as simpler alternative
- Structured logging that feeds the UI
- Progress callback system in agent orchestrator

#### Output Format:
```
🔍 REASONING PROCESS:

1. Input Classification: Natural language → Detection request
   
2. RAG Lookups:
   - SPL Docs: Found 3 relevant documents
     • "stats command" (similarity: 0.89)
     • "eval functions" (similarity: 0.76)
   - Detections: Found 2 similar rules
     • "Windows Process Creation" (similarity: 0.91)
   
3. Field Selection:
   - Using CIM fields: process_name, parent_process, user
   - Source: Endpoint.Processes data model
   
4. Query Construction:
   - Base: index=* sourcetype=*
   - Filter: process_name=cmd.exe
   - Stats: count by user, dest

📊 CONFIDENCE: 87% (based on RAG match quality)
```

#### Subtasks:
1. Instrument RAG queries to return metadata
2. Create reasoning trace data structure
3. Build UI component for reasoning display
4. Add confidence calculation
5. Implement source citation links

#### Dependencies:
- Web Interface ✅

#### Acceptance Criteria:
- [ ] Every response includes reasoning trace
- [ ] Sources are cited with similarity scores
- [ ] Users can see why specific fields were chosen
- [ ] Confidence score is displayed

---

### 5. Enhanced PDF Processing with OCR/Vision AI
- **Complexity**: 🟡 Medium
- **Description**: Improve PDF to text extraction with AI-powered OCR for images and complex layouts
- **Why**: Many IOC reports contain indicators in images, tables, or complex formatting that simple text extraction misses

#### Current Limitations:
- pdfplumber only extracts embedded text
- Images with text (screenshots, diagrams) are ignored
- Complex tables may not parse correctly
- Scanned PDFs are completely unreadable

#### Proposed Solutions:

**Option A - Local OCR (Privacy-Focused):**
```python
# Tesseract OCR + pdf2image
from pdf2image import convert_from_path
import pytesseract

images = convert_from_path('report.pdf')
for img in images:
    text = pytesseract.image_to_string(img)
```
- Pros: Free, private, works offline
- Cons: Lower accuracy, no layout understanding

**Option B - Vision LLM (Higher Accuracy):**
```python
# Use vision-capable LLM (GPT-4V, Claude 3, Llama 3.2 Vision)
from openai import OpenAI

response = client.chat.completions.create(
    model="gpt-4-vision-preview",
    messages=[{
        "role": "user",
        "content": [
            {"type": "text", "text": "Extract all IOCs from this image"},
            {"type": "image_url", "image_url": {"url": base64_image}}
        ]
    }]
)
```
- Pros: High accuracy, understands context, extracts structured data
- Cons: API costs, privacy concerns, requires internet

**Option C - Hybrid Approach (Recommended):**
1. First pass: pdfplumber for embedded text
2. Second pass: Convert pages to images
3. Third pass: Local OCR (Tesseract) for basic text
4. Fourth pass: Vision LLM for complex/unclear sections (optional, user-enabled)

#### Subtasks:
1. [ ] Add pdf2image and pytesseract to requirements
2. [ ] Create `pdf_processor.py` with multi-stage extraction
3. [ ] Add OCR toggle in config (enable/disable)
4. [ ] Add Vision LLM option (opt-in, requires API key)
5. [ ] Integrate with existing IOC extraction pipeline
6. [ ] Add confidence scoring for extracted text
7. [ ] Handle multi-page PDFs efficiently

#### Dependencies:
- System: `tesseract-ocr` package
- Python: `pdf2image`, `pytesseract`, `Pillow`
- Optional: Vision-capable LLM API

#### Acceptance Criteria:
- [ ] Can extract text from scanned PDFs
- [ ] Can read IOCs from screenshots/images in reports
- [ ] Works offline with local OCR
- [ ] Optional Vision LLM for higher accuracy
- [ ] Graceful fallback if OCR unavailable

---

## 🟢 Lower Priority

### 6. Dashboard Startup Flow & Graceful Degradation
- **Complexity**: 🟡 Medium
- **Description**: Smart initialization with feature toggles and fallback modes
- **Why**: System should work even with partial configuration

#### Startup Sequence:
```
1. Load configuration
2. Check local data sources (SPL docs, detections, CIM)
   → Missing? Show download option
3. Check AI connection
   → Missing? Disable AI features, show warning
4. Check Splunk connection
   → Missing? Disable validation, show warning
5. If Splunk connected: Extract metadata (first time only)
6. Launch dashboard with appropriate feature flags
```

#### Feature Toggles (checkboxes in UI):
- [ ] Enable SPL Docs RAG
- [ ] Enable Detection RAG
- [ ] Enable CIM RAG
- [ ] Enable Splunk Validation
- [ ] Enable Splunk Metadata
- [ ] Enable Attack Data Validation

#### Degraded Modes:
| Missing | Impact | Fallback |
|---------|--------|----------|
| SPL Docs RAG | No syntax help | Show warning, continue |
| Detection RAG | No rule examples | Show warning, continue |
| Splunk Connection | No validation | Skip validation step |
| AI Connection | Core feature | Show error, require config |

#### Subtasks:
1. Create startup health check system
2. Implement feature flag storage
3. Build status indicator UI component
4. Create "fix it" buttons for missing dependencies
5. Add graceful error handling throughout

#### Dependencies:
- Web Interface ✅
- Configuration Screen ✅

#### Acceptance Criteria:
- [ ] Dashboard loads even with missing components
- [ ] Clear indicators of what's working/missing
- [ ] User can enable/disable features via toggles
- [ ] First-run wizard guides setup

---

### 7. Detection Rule Export
- **Complexity**: 🟢 Small
- **Description**: Export generated queries in various formats
- **Why**: Users need to deploy detections to their SIEM

#### Export Formats:
- [ ] Splunk Saved Search (savedsearches.conf format)
- [ ] Splunk Alert (with trigger conditions)
- [ ] Splunk ES Correlation Search
- [ ] JSON (for API integration)
- [ ] YAML (Splunk Security Content format)

#### Subtasks:
1. Create export templates for each format
2. Add export buttons to UI
3. Implement file download
4. Add scheduling options for alerts

#### Dependencies:
- Web Interface ✅

#### Acceptance Criteria:
- [ ] User can export in at least 3 formats
- [ ] Exported files are valid and importable
- [ ] Alert exports include scheduling options

---

### 8. Multi-Tenant Support
- **Complexity**: 🔴 Large
- **Description**: Support multiple Splunk instances/environments
- **Why**: Enterprises have dev/staging/prod environments

#### Features:
- [ ] Named Splunk connections
- [ ] Environment switching in UI
- [ ] Per-environment metadata cache
- [ ] Query targeting specific environment

#### Subtasks:
1. Extend config to support multiple connections
2. Add environment selector to UI
3. Namespace metadata cache by environment
4. Add environment badge to queries

#### Dependencies:
- Web Interface ✅
- Configuration Screen ✅

#### Acceptance Criteria:
- [ ] User can define multiple Splunk connections
- [ ] Easy switching between environments
- [ ] Metadata cached per environment

---

## 🔬 Research Needed

### Splunk Metadata Extraction - Best Approach

**Problem**: Need comprehensive field information without long query times.

**Options Evaluated**:

| Approach | Pros | Cons | Time |
|----------|------|------|------|
| REST API (`/services/data/props/*`) | Fast | Limited fields | ~20s |
| `\| map` + `fieldsummary` | Comprehensive | Very slow | 5-10min |
| CIM Data Models | Standardized, fast | Only CIM-compliant data | <1s |

**Recommendation**: Use CIM Data Models RAG as primary source, with optional REST API fallback for non-CIM data.

**User's SPL Queries for Reference**:

<details>
<summary>REST API Approach (Fast)</summary>

```spl
| tstats values(sourcetype) as sourcetype WHERE earliest=-24h latest=now index=* BY index 
| append 
    [| rest /services/data/props/calcfields search=eai:acl.sharing=global search=stanza!="source::*" f=stanza f=attribute 
    | eval sourcetype=stanza,field_name=replace(attribute, "EVAL-", "")]
| append 
    [| rest /services/data/props/extractions search=eai:acl.sharing=global search=stanza!="source::*" f=stanza f=attribute search=attribute!=REPORT* 
    | eval sourcetype=stanza 
    | rex max_match=0 field=value "\<(?<field_name>[a-zA-Z0-9\-\_]+)\>"]
| append 
    [| rest /services/data/props/fieldaliases search=eai:acl.sharing=global search=stanza!="source::*" f=stanza f=value 
    | eval sourcetype=stanza,field_name=replace(value, ".*\s+(ASNEW|AS|as)\s+", "")]
| append 
    [| rest /services/data/props/lookups search=eai:acl.sharing=global search=stanza!="source::*" f=stanza f=value 
    | eval sourcetype=stanza 
    | rex max_match=0 field=value "(\s+(OUTPUT|OUTPUTNEW)|(ASNEW|AS|as))\s+(?<field_name>.*)" 
    | eval field_name=replace(field_name,"\s+(OUTPUT|OUTPUTNEW)\s+","") 
    | makemv delim="," field_name]
| stats values(field_name) as field_name values(index) as index by sourcetype 
| search index=* field_name=*
```

</details>

<details>
<summary>Map + Fieldsummary Approach (Comprehensive)</summary>

```spl
| tstats latest(sourcetype) as sourcetype WHERE earliest=-60m latest=now index=* sourcetype IN (XmlWinEventLog:Security WinEventLog:Security WinEventLog:Microsoft-Windows-Sysmon/Operational XmlWinEventLog:Microsoft-Windows-Sysmon/Operational) OR source IN (XmlWinEventLog:Security WinEventLog:Security WinEventLog:Microsoft-Windows-Sysmon/Operational XmlWinEventLog:Microsoft-Windows-Sysmon/Operational) BY index source 
| map maxsearches=100 search="search earliest=-60m latest=now index=$index$ sourcetype=$sourcetype$ source=$source$ | fieldsummary | search count>1 | eval index=\"$index$\", sourcetype=\"$source$\", source=\"$source$\" | fields index sourcetype source field" 
| search NOT field IN (eventtype host index linecount punct source sourcetype splunk_server splunk_server_group tag tag::eventtype tag::sourcetype timestamp uppercase values date_hour date_mday date_minute date_second date_month date_wday date_year date_zone timeendpos timestamp timestartpos)
```

</details>

---

## 📋 Documentation & Presentation

### Value Proposition Document
- **Complexity**: 🟢 Small
- **Description**: Document for sharing in internal WhatsApp groups / presentations
- **Why**: Explain the project's value to stakeholders

#### Content to Include:
- [ ] Problem statement (manual SPL writing is slow, error-prone)
- [ ] Solution overview (AI-assisted detection engineering)
- [ ] Key features and benefits
- [ ] Demo screenshots/GIFs
- [ ] Time savings estimation
- [ ] Security benefits (grounded in authoritative sources)
- [ ] Roadmap highlights

#### Subtasks:
1. Write problem/solution narrative
2. Create demo screenshots
3. Record short demo GIF
4. Gather metrics (time savings, accuracy)
5. Format for easy sharing

#### Acceptance Criteria:
- [ ] Single-page summary exists
- [ ] Includes visuals
- [ ] Can be shared in chat/email
- [ ] Non-technical stakeholders can understand value

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01-21 | Initial TODO.md created |
| 1.1 | 2026-01-22 | Updated with completed items, corrected stats |
| 1.2 | 2026-01-23 | Added: Enhanced PDF OCR (#5), Real-time process visualization (#4) |
| 1.3 | 2026-01-25 | Updated: RAG-based grounding (removed hardcoded fields), token usage tracking, fail-fast prompts |

---

## Contributing

When adding new TODOs:
1. Choose appropriate priority section
2. Include all fields (complexity, description, why, subtasks, dependencies, acceptance criteria)
3. Update table of contents if adding new sections
4. Mark completed items with ✅ and move to Completed section
