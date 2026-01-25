# API Reference

This document provides detailed API documentation for using the Splunk Detection Engineer Agent as a Python library.

## Quick Start

```python
from src.agent import SplunkAgent

agent = SplunkAgent()
result = agent.run("Detect brute force login attempts on Windows")

print(result.spl_query)
print(result.explanation)
```

---

## Core Classes

### SplunkAgent

The main orchestrator for SPL query generation.

```python
from src.agent import SplunkAgent, AgentConfig
```

#### Constructor

```python
SplunkAgent(
    config_path: Path = DEFAULT_CONFIG_PATH,
    llm_provider: Optional[LLMProvider] = None,
    splunk_client: Optional[SplunkClient] = None,
    doc_rag: Optional[SplunkRAG] = None,
    detection_rag: Optional[DetectionRAG] = None,
)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `config_path` | `Path` | Path to configuration file |
| `llm_provider` | `LLMProvider` | Pre-configured LLM provider (optional) |
| `splunk_client` | `SplunkClient` | Pre-configured Splunk client (optional) |
| `doc_rag` | `SplunkRAG` | Pre-configured documentation RAG (optional) |
| `detection_rag` | `DetectionRAG` | Pre-configured detection RAG (optional) |

#### Methods

##### `run(user_input: str, show_reasoning: bool = False, reasoning_callback: Callable = None) -> AgentResult`

Process user input and generate an SPL query.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `user_input` | `str` | Required | The query or input to process |
| `show_reasoning` | `bool` | `False` | Enable Chain of Thought reasoning trace |
| `reasoning_callback` | `Callable` | `None` | Callback for real-time reasoning updates |

```python
# Natural language
result = agent.run("Detect credential dumping from LSASS memory")

# Log source specification
result = agent.run("index=windows sourcetype=WinEventLog:Security")

# IOC report URL
result = agent.run("https://example.com/threat-report.pdf")

# With reasoning trace
result = agent.run("Detect brute force attacks", show_reasoning=True)
if result.reasoning_trace:
    print(result.reasoning_trace.format_cli_output())
```

##### `get_status() -> dict`

Get status of all agent components.

```python
status = agent.get_status()
# Returns:
# {
#     "llm_provider": "groq/llama-3.3-70b-versatile",
#     "splunk_connected": True,
#     "doc_rag_documents": 1225,
#     "detection_rag_documents": 1978
# }
```

---

### AgentResult

Result object returned by `SplunkAgent.run()`.

```python
from src.agent import AgentResult, QueryStatus
```

#### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `status` | `QueryStatus` | SUCCESS, PARTIAL, or FAILED |
| `spl_query` | `str` | Generated SPL query |
| `explanation` | `str` | Explanation of the query |
| `input_type` | `InputType` | NATURAL_LANGUAGE, LOG_SOURCE, or IOC_REPORT |
| `iterations` | `int` | Number of refinement iterations |
| `total_time` | `float` | Total processing time in seconds |
| `validated` | `bool` | Whether query was validated against Splunk |
| `result_count` | `int` | Number of results from validation |
| `fields_discovered` | `list[str]` | Fields found in results |
| `warnings` | `list[str]` | Warning messages |
| `errors` | `list[str]` | Error messages |
| `reasoning_trace` | `ReasoningTrace` | Chain of Thought trace (if enabled) |
| `ioc_summary` | `str` | Summary of extracted IOCs (for IOC reports) |
| `grounding_result` | `GroundingResult` | Field validation result (uses RAG-based validation) |
| `token_usage` | `dict` | Token counts: `{total_tokens, total_input_tokens, total_output_tokens}` |

#### Methods

##### `to_dict() -> dict`

Convert result to dictionary.

##### `format_output() -> str`

Format result for display.

```python
print(result.format_output())
```

---

### LLMProvider

Multi-provider LLM interface.

```python
from src.llm_provider import get_provider, LLMProvider
```

#### Factory Function

```python
get_provider(
    provider_name: Optional[str] = None,
    config_path: Path = DEFAULT_CONFIG_PATH,
) -> LLMProvider
```

```python
# Load from config
provider = get_provider()

# Specify provider
provider = get_provider(provider_name="groq")
```

#### Methods

##### `generate(prompt: str, system_prompt: Optional[str] = None) -> LLMResponse`

Generate a response from the LLM.

```python
response = provider.generate("What is the stats command in SPL?")
print(response.content)
```

##### `generate_with_context(query: str, context: str) -> LLMResponse`

Generate with RAG context injected.

```python
response = provider.generate_with_context(
    query="How do I calculate average?",
    context="[Retrieved documentation here]"
)
```

---

### SplunkClient

REST API client for Splunk Enterprise.

```python
from src.splunk_client import SplunkClient
```

#### Constructor

```python
SplunkClient(
    host: str,
    port: int = 8089,
    username: str = "",
    password: str = "",
    token: str = "",
    verify_ssl: bool = False,
    timeout: int = 120,
)
```

#### Factory Method

```python
client = SplunkClient.from_config(config_path=Path("config/config.yaml"))
```

#### Methods

##### `test_connection() -> dict`

Test connection to Splunk.

```python
result = client.test_connection()
# {"connected": True, "server_name": "splunk-host", "version": "10.0.2"}
```

##### `run_oneshot(search: str, ...) -> SearchResult`

Run a synchronous (oneshot) search.

```python
result = client.run_oneshot(
    search="index=main | head 10",
    earliest_time="-24h",
    latest_time="now"
)
```

##### `list_indexes() -> list[dict]`

List available indexes.

##### `get_fields(index: str, sourcetype: Optional[str] = None, ...) -> list[dict]`

Get fields for an index/sourcetype.

---

### SplunkRAG

Documentation knowledge base.

```python
from src.rag_spl_docs import SplunkRAG
```

#### Constructor

```python
SplunkRAG(
    db_path: str = DEFAULT_DB_PATH,
    collection_name: str = DEFAULT_COLLECTION_NAME,
)
```

#### Methods

##### `search(query: str, top_k: int = 5) -> list[QueryResult]`

Search documentation.

```python
results = rag.search("stats command syntax", top_k=5)
for r in results:
    print(f"{r.title}: {r.similarity:.2f}")
```

##### `get_context_for_agent(query: str, top_k: int = 5) -> str`

Get formatted context for LLM.

##### `get_stats() -> dict`

Get database statistics.

---

### DetectionRAG

Security detection rules knowledge base.

```python
from src.rag_detections import DetectionRAG
```

#### Constructor

```python
DetectionRAG(
    db_path: str = DEFAULT_DB_PATH,
    collection_name: str = DEFAULT_COLLECTION_NAME,
)
```

#### Methods

##### `search(query: str, top_k: int = 5) -> list[DetectionResult]`

Semantic search for detections.

##### `search_by_mitre(technique_id: str, top_k: int = 10) -> list[DetectionResult]`

Search by MITRE ATT&CK technique.

```python
results = rag.search_by_mitre("T1003.001")  # LSASS Memory
```

##### `search_by_data_source(data_source: str, top_k: int = 10) -> list[DetectionResult]`

Search by data source.

```python
results = rag.search_by_data_source("Sysmon EventID 1")
```

##### `get_context_for_agent(query: str, top_k: int = 5) -> str`

Get formatted context for LLM.

---

### CIMRAG

CIM Data Models knowledge base.

```python
from src.rag_cim_docs import CIMRAG
```

#### Constructor

```python
CIMRAG(
    db_path: str = DEFAULT_DB_PATH,
    collection_name: str = DEFAULT_COLLECTION_NAME,
)
```

#### Methods

##### `search(query: str, top_k: int = 5, data_model: Optional[str] = None) -> list[CIMResult]`

Search for relevant CIM fields.

```python
results = rag.search("process execution fields", top_k=5)
for r in results:
    print(f"{r.data_model}: {r.field_names}")
```

##### `get_context_for_agent(query: str, top_k: int = 3) -> str`

Get formatted CIM field context for LLM.

##### `list_data_models() -> list[str]`

List all available CIM data models.

##### `get_fields_for_model(data_model: str) -> list[str]`

Get all field names for a specific data model.

```python
fields = rag.get_fields_for_model("authentication")
```

**CLI Commands:**
```bash
python -m src.rag_cim_docs stats              # Show statistics
python -m src.rag_cim_docs query "<query>"    # Search CIM fields
python -m src.rag_cim_docs ingest             # Ingest from data/
python -m src.rag_cim_docs models             # List data models
python -m src.rag_cim_docs fields <model>     # Show fields for a model
```

---

### AttackDataRAG

Attack datasets knowledge base.

```python
from src.rag_attack_data import AttackDataRAG
```

#### Constructor

```python
AttackDataRAG(
    db_path: str = DEFAULT_DB_PATH,
    collection_name: str = DEFAULT_COLLECTION_NAME,
)
```

#### Methods

##### `search(query: str, top_k: int = 5) -> list[AttackDataResult]`

Semantic search for attack datasets.

##### `search_by_mitre(technique_id: str, top_k: int = 10) -> list[AttackDataResult]`

Search by MITRE ATT&CK technique.

```python
results = rag.search_by_mitre("T1003")  # Credential Dumping
```

##### `get_context_for_agent(query: str, top_k: int = 3) -> str`

Get formatted context for LLM.

**CLI Commands:**
```bash
python -m src.rag_attack_data stats           # Show statistics
python -m src.rag_attack_data query "<text>"  # Semantic search
python -m src.rag_attack_data mitre T1003     # Search by MITRE ID
python -m src.rag_attack_data ingest          # Ingest from data/
```

---

### InputProcessor

Input classification and processing.

```python
from src.input_processor import InputProcessor, ProcessedInput, InputType
```

#### Methods

##### `process(user_input: str) -> ProcessedInput`

Process and classify input.

```python
processor = InputProcessor()

# Natural language
result = processor.process("Detect brute force attacks")
assert result.input_type == InputType.NATURAL_LANGUAGE

# Log source
result = processor.process("index=windows sourcetype=WinEventLog:Security")
assert result.input_type == InputType.LOG_SOURCE

# IOC report
result = processor.process("https://example.com/report.pdf")
assert result.input_type == InputType.IOC_REPORT
```

---

### GroundingValidator

RAG-based field validation for SPL queries.

```python
from src.agent.grounding import GroundingValidator, GroundingResult, validate_query_grounding
from src.rag_cim_docs import CIMRAG
from src.rag_detections import DetectionRAG
```

#### Constructor

```python
GroundingValidator(
    cim_rag: Optional[CIMRAG] = None,
    detection_rag: Optional[DetectionRAG] = None,
)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `cim_rag` | `CIMRAG` | CIM RAG instance for field validation (563 fields from 26 models) |
| `detection_rag` | `DetectionRAG` | Detection RAG for similar query patterns |

#### Methods

##### `validate_query(spl_query: str, rag_context: str = "", user_specified_fields: Set[str] = None) -> GroundingResult`

Validate all fields in an SPL query against known sources.

```python
validator = GroundingValidator(cim_rag=cim_rag, detection_rag=detection_rag)
result = validator.validate_query(
    "index=* | stats count by src_ip, dest_ip, fake_field"
)

print(result.is_grounded)      # False (fake_field is unknown)
print(result.grounding_score)   # 0.67 (2/3 fields known)
print(result.unknown_fields)    # [FieldValidation(field_name='fake_field', ...)]
```

##### `get_cim_fields() -> Set[str]`

Get all known CIM fields from the CIM RAG (cached after first call).

```python
fields = validator.get_cim_fields()
print(len(fields))  # 563
```

#### Convenience Function

```python
# Standalone function (uses global validator)
result = validate_query_grounding(
    spl_query="index=* | stats count by user, src_ip",
    rag_context="user authentication fields...",
    cim_rag=cim_rag,
    detection_rag=detection_rag,
)
```

#### GroundingResult Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `is_grounded` | `bool` | True if query uses known fields |
| `grounding_score` | `float` | 0.0 to 1.0, proportion of known fields |
| `known_fields` | `list[FieldValidation]` | Fields that were validated |
| `unknown_fields` | `list[FieldValidation]` | Fields that could not be validated |
| `warnings` | `list[str]` | Warning messages |
| `sources_used` | `set[str]` | RAG sources used (cim, detection, spl_docs) |

---

## Enums

### QueryStatus

```python
from src.agent import QueryStatus

QueryStatus.SUCCESS   # Query generated and validated
QueryStatus.PARTIAL   # Query generated but not fully validated
QueryStatus.FAILED    # Query generation failed
```

### InputType

```python
from src.input_processor import InputType

InputType.NATURAL_LANGUAGE  # Plain English description
InputType.LOG_SOURCE        # Index/sourcetype specification
InputType.IOC_REPORT        # URL or PDF with IOCs
InputType.UNKNOWN           # Could not classify
```

### IOCType

```python
from src.input_processor import IOCType

IOCType.IP_ADDRESS
IOCType.DOMAIN
IOCType.URL
IOCType.MD5
IOCType.SHA1
IOCType.SHA256
IOCType.EMAIL
IOCType.FILE_NAME
IOCType.FILE_PATH
IOCType.REGISTRY_KEY
IOCType.CVE
IOCType.MITRE_ATTACK
```

---

## Configuration

Configuration is loaded from `config/config.yaml`:

```yaml
# LLM Configuration
provider: groq
settings:
  temperature: 0.2
  max_tokens: 2000

# Splunk Configuration
splunk:
  host: your-splunk-host
  port: 8089
  token: your-jwt-token
  ssl_verify: true

# Agent Behavior
agent:
  max_iterations: 5
  validation_time_range: "-24h"
  enable_splunk_validation: true
```

---

## Examples

### Basic Query Generation

```python
from src.agent import SplunkAgent

agent = SplunkAgent()
result = agent.run("Detect PowerShell downloading files from internet")

if result.status.value == "success":
    print("Query:", result.spl_query)
    print("Results:", result.result_count)
else:
    print("Warnings:", result.warnings)
```

### Custom LLM Provider

```python
from src.agent import SplunkAgent
from src.llm_provider import get_provider

provider = get_provider(provider_name="mistral")
agent = SplunkAgent(llm_provider=provider)
```

### Without Splunk Validation

```python
from src.agent import SplunkAgent, AgentConfig
from pathlib import Path

# Modify config programmatically
config = AgentConfig(enable_splunk_validation=False)
agent = SplunkAgent()
agent.config = config
```

### Processing IOC Reports

```python
from src.input_processor import InputProcessor

processor = InputProcessor()
result = processor.process("https://example.com/threat-intel.pdf")

print(f"Extracted {len(result.iocs)} IOCs")
for ioc in result.iocs[:5]:
    print(f"  {ioc.ioc_type.value}: {ioc.value}")
```

---

## Smart Fetchers CLI

Both data fetchers support smart update functionality via command line.

### SPL Documentation Fetcher

```bash
# Check for updates (no download)
python -m src.fetcher_spl_docs check

# Smart update (downloads only if newer version available)
python -m src.fetcher_spl_docs

# Force re-download
python -m src.fetcher_spl_docs force

# Manual crawl with options
python -m src.fetcher_spl_docs crawl --delay 0.5 --version 10.2
```

**Version Detection:**
- Checks incrementally starting from 10.2: 10.2 → 10.3 → 10.4 → ...
- Stops after 2 consecutive 404 responses
- Returns highest available version

**Stats File:** `data/splunk_spl_docs.stats.json`
```json
{
  "version": "10.2",
  "total_pages": 60,
  "total_chunks": 1225,
  "last_updated": "2026-01-21T...",
  "source": "help.splunk.com"
}
```

### Detection Rules Fetcher

```bash
# Check for updates (no download)
python -m src.fetcher_detections check

# Smart update (downloads only if newer version available)
python -m src.fetcher_detections

# Force re-download
python -m src.fetcher_detections force

# Keep cloned repository
python -m src.fetcher_detections force --keep-clone

# Show statistics
python -m src.fetcher_detections stats

# Show specific detection
python -m src.fetcher_detections show <detection-id>
```

**Version Detection:**
- Queries GitHub API for latest release
- Compares with local `version` in stats file
- Auto-clones, parses, and cleans up repository

**Stats File:** `data/splunk_spl_detections.stats.json`
```json
{
  "version": "v5.20.0",
  "published_at": "2026-01-20T...",
  "total_detections": 1978,
  "last_updated": "2026-01-21T...",
  "source": "https://github.com/splunk/security_content"
}
```

### CIM Documentation Fetcher

```bash
# Check for updates (no download)
python -m src.fetcher_cim_docs check

# Smart update (downloads only if newer version available)
python -m src.fetcher_cim_docs

# Force re-download
python -m src.fetcher_cim_docs force

# Download specific version
python -m src.fetcher_cim_docs version 6.3

# Show statistics
python -m src.fetcher_cim_docs stats
```

**Version Detection:**
- Checks incrementally starting from 6.3: 6.3 → 6.4 → 6.5 → ...
- Stops after 2 consecutive 404 responses

**Stats File:** `data/splunk_cim_docs.stats.json`
```json
{
  "version": "6.3",
  "total_data_models": 26,
  "total_fields": 1064,
  "total_chunks": 250,
  "last_updated": "2026-01-22T..."
}
```

### Attack Data Fetcher

```bash
# Check for updates (no download)
python -m src.fetcher_attack_data check

# Smart update (downloads only if newer version available)
python -m src.fetcher_attack_data

# Force re-download
python -m src.fetcher_attack_data force

# Show statistics
python -m src.fetcher_attack_data stats
```

**Version Detection:**
- Uses GitHub Commits API to check latest commit on main branch
- Compares commit SHA with local version

**Stats File:** `data/splunk_attack_data.stats.json`
```json
{
  "version": "commit_sha",
  "total_datasets": 1175,
  "mitre_techniques": 237,
  "data_sources": 51,
  "last_updated": "2026-01-22T..."
}
```

---

## Chain of Thought (CoT) Reasoning

### ReasoningTrace

Track the agent's reasoning process step-by-step.

```python
from src.agent import SplunkAgent, ReasoningTrace, ReasoningStepType
```

#### Usage

```python
agent = SplunkAgent()

# Enable reasoning
result = agent.run("Detect brute force attacks", show_reasoning=True)

# Access reasoning trace
if result.reasoning_trace:
    # Format for CLI display
    print(result.reasoning_trace.format_cli_output())
    
    # Access individual steps
    for step in result.reasoning_trace.steps:
        print(f"{step.step_type.value}: {step.title} ({step.status.value})")
        print(f"  Details: {step.details}")
    
    # Get confidence score
    print(f"Confidence: {result.reasoning_trace.get_confidence_score():.0%}")
```

#### ReasoningStepType

```python
from src.agent.reasoning import ReasoningStepType

ReasoningStepType.INPUT_CLASSIFICATION  # Classifying user input
ReasoningStepType.RAG_RETRIEVAL         # Querying knowledge bases
ReasoningStepType.CONTEXT_BUILDING      # Building LLM context
ReasoningStepType.QUERY_GENERATION      # Generating SPL query
ReasoningStepType.VALIDATION            # Validating query
ReasoningStepType.REFINEMENT            # Refining query
ReasoningStepType.COMPLETE              # Workflow complete
ReasoningStepType.ERROR                 # Error occurred
```

---

## End-to-End IOC Workflow

### API Endpoint

**POST /api/workflow/e2e**

Run the complete IOC → Detection → Validation pipeline.

#### Request Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `url` | `string` | One of url/file | URL to IOC report |
| `file` | `file` | One of url/file | Uploaded PDF file |
| `validate_splunk` | `boolean` | No (default: true) | Validate query against Splunk |
| `test_attack_data` | `boolean` | No (default: true) | Test against attack datasets |

#### Example Request

```bash
curl -X POST "http://localhost:8000/api/workflow/e2e" \
  -F "url=https://securelist.com/honeymyte-kernel-mode-rootkit/118590/" \
  -F "validate_splunk=true" \
  -F "test_attack_data=true"
```

#### Response Structure

```json
{
  "success": true,
  "confidence_score": 0.52,
  "stages": [
    {
      "stage": "input",
      "status": "success",
      "title": "Processing IOC source",
      "details": {"source": "...", "report_title": "...", "content_length": 74},
      "duration_ms": 2034.89,
      "warnings": [],
      "errors": []
    },
    {
      "stage": "ioc_extraction",
      "status": "success",
      "title": "Extracting IOCs from report",
      "details": {"total_iocs": 4, "ioc_types": {"md5": 3, "file_path": 1}, "ttps": []},
      "duration_ms": 0.03
    },
    {
      "stage": "detection_build",
      "status": "success",
      "title": "Building detection query",
      "details": {"query_length": 664, "uses_tstats": false},
      "duration_ms": 3986.42
    },
    {
      "stage": "best_practices",
      "status": "warning",
      "title": "Checking best practices",
      "details": {"checks_passed": 1, "checks_warning": 1},
      "warnings": ["No time range specified"]
    },
    {
      "stage": "metadata_validation",
      "status": "success",
      "title": "Validating query against Splunk",
      "details": {"valid": true, "result_count": 0}
    },
    {
      "stage": "attack_data_test",
      "status": "success",
      "title": "Testing against attack data",
      "details": {"datasets_found": 2, "top_dataset": "linux_auditd_hidden_file"}
    },
    {
      "stage": "complete",
      "status": "success",
      "title": "Workflow complete",
      "details": {"success": true, "confidence": "52%"}
    }
  ],
  "ioc_summary": "Report: The HoneyMyte APT...\nTotal IOCs: 4\n  - md5: 3\n  - file_path: 1",
  "ioc_count": 4,
  "ioc_types": {"md5": 3, "file_path": 1},
  "ttps_detected": [],
  "spl_query": "index=* | search file_hash IN (...) | eval ioc_type=case(...)",
  "explanation": "The provided SPL query is designed to detect...",
  "query_validated": true,
  "validation_result_count": 0,
  "attack_data_matches": [
    {
      "dataset_name": "linux_auditd_hidden_file",
      "mitre_id": "T1564.001",
      "relevance_score": 0.67
    }
  ],
  "total_time_ms": 8164.82,
  "warnings": ["IOC queries should be reviewed before production use"],
  "errors": []
}
```

### Python Usage

```python
from src.agent import SplunkAgent
from src.agent.e2e_workflow import run_e2e_workflow

agent = SplunkAgent()

result = run_e2e_workflow(
    agent=agent,
    ioc_source="https://example.com/threat-report.html",
    validate_with_splunk=True,
    test_with_attack_data=True
)

print(f"Success: {result.success}")
print(f"Confidence: {result.confidence_score:.0%}")
print(f"IOCs found: {result.ioc_count}")
print(f"Query validated: {result.query_validated}")
print(f"\nGenerated SPL:\n{result.spl_query}")
```

---

## REST API Endpoints

### Query Generation

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/query` | POST | Generate SPL query (with optional reasoning) |
| `/api/query/stream` | POST | Stream query generation with real-time reasoning |
| `/api/workflow/e2e` | POST | Run end-to-end IOC workflow |

### System Status

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check |
| `/api/status` | GET | Component status (includes token usage) |

### Configuration

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/config` | GET | Get current configuration |
| `/api/config` | POST | Update configuration |

### RAG Search

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/search` | POST | Search across RAG systems |

### Starting the Server

```bash
# Default (opens browser, accessible externally)
python -m src.api.server

# Local only (127.0.0.1)
python -m src.api.server --local

# Without auto-opening browser
python -m src.api.server --no-browser

# Custom port
uvicorn src.api.server:app --reload --port 8080
```
