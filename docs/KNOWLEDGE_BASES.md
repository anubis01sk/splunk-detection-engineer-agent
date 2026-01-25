# Knowledge Bases

The Splunk Detection Engineer Agent is grounded in four knowledge bases that provide accurate, up-to-date information for query generation.

---

## Overview

| Knowledge Base | Documents | Source | Description |
|----------------|-----------|--------|-------------|
| **SPL Documentation** | 1,225+ chunks | help.splunk.com (Splunk 10.2) | Official SPL command reference |
| **Detection Rules** | 1,978 rules | Splunk Security Content (GitHub) | Production security detections |
| **CIM Data Models** | 1,064 fields | Splunk CIM 6.3 (26 models) | Normalized field definitions |
| **Attack Data** | 1,175 datasets | splunk/attack_data (GitHub) | Attack simulation samples |

Additional metadata:
- **MITRE ATT&CK**: 237+ techniques (mapped from Attack Data)
- **Analytic Stories**: 333 stories (from detection rules)

---

## Pre-Included Data

The project includes pre-crawled data files in the `data/` directory:

```
data/
├── splunk_spl_docs.jsonl           # SPL documentation
├── splunk_spl_docs.stats.json      # Version/stats info
├── splunk_spl_detections.jsonl     # Detection rules
├── splunk_spl_detections.stats.json
├── splunk_cim_docs.jsonl           # CIM field definitions
├── splunk_cim_docs.stats.json
├── splunk_attack_data.jsonl        # Attack datasets
└── splunk_attack_data.stats.json
```

**These files are sufficient for most use cases.** You only need to update them if you want the latest content.

---

## Updating Knowledge Bases

### Check for Updates

See if newer versions are available without downloading:

```bash
python -m src.fetcher_spl_docs check
python -m src.fetcher_detections check
python -m src.fetcher_cim_docs check
python -m src.fetcher_attack_data check
```

### Smart Update

Downloads only if a newer version is available:

```bash
python -m src.fetcher_spl_docs
python -m src.fetcher_detections
python -m src.fetcher_cim_docs
python -m src.fetcher_attack_data
```

### Force Re-download

Ignores version check and re-downloads everything:

```bash
python -m src.fetcher_spl_docs force
python -m src.fetcher_detections force
python -m src.fetcher_cim_docs force
python -m src.fetcher_attack_data force
```

### Re-ingest After Update

After downloading new data, re-ingest into the vector databases:

```bash
python -m src.rag_spl_docs ingest
python -m src.rag_detections ingest
python -m src.rag_cim_docs ingest
python -m src.rag_attack_data ingest
```

Or all at once:
```bash
python -m src.rag_spl_docs ingest; python -m src.rag_detections ingest; python -m src.rag_cim_docs ingest; python -m src.rag_attack_data ingest
```

---

## View Current Versions

```bash
# View stats files directly
cat data/splunk_spl_docs.stats.json
cat data/splunk_spl_detections.stats.json
cat data/splunk_cim_docs.stats.json
cat data/splunk_attack_data.stats.json

# Or use the stats command
python -m src.fetcher_detections stats
```

---

## Manual Update Process

### SPL Documentation

Re-crawl the official Splunk documentation:

```bash
# Install Playwright browser (required for crawling)
playwright install chromium

# Crawl with default settings (auto-detects latest version)
python -m src.fetcher_spl_docs

# Or specify options
python -m src.fetcher_spl_docs crawl --delay 0.5 --version 10.2

# Re-ingest into vector database
python -m src.rag_spl_docs ingest
```

### Detection Rules

Download from [Splunk Security Content](https://github.com/splunk/security_content):

```bash
# Smart update (clones repo, parses, cleans up)
python -m src.fetcher_detections

# Keep the cloned repository
python -m src.fetcher_detections force --keep-clone

# Re-ingest
python -m src.rag_detections ingest
```

### CIM Data Models

Crawl from Splunk CIM documentation:

```bash
python -m src.fetcher_cim_docs
python -m src.rag_cim_docs ingest
```

### Attack Data

Clone from [splunk/attack_data](https://github.com/splunk/attack_data):

```bash
python -m src.fetcher_attack_data
python -m src.rag_attack_data ingest
```

---

## Vector Database Storage

After ingestion, vector databases are stored in:

```
vector_dbs/
├── spl_docs/       # SPL documentation (ChromaDB)
├── detections/     # Detection rules (ChromaDB)
├── cim/            # CIM data models (ChromaDB)
└── attack_data/    # Attack datasets (ChromaDB)
```

### Reset Vector Databases

If databases become corrupted:

```bash
# Remove all vector databases
rm -rf vector_dbs/

# Re-ingest everything
python -m src.rag_spl_docs ingest
python -m src.rag_detections ingest
python -m src.rag_cim_docs ingest
python -m src.rag_attack_data ingest
```

### Reset Single Database

```bash
python -m src.rag_detections reset
python -m src.rag_detections ingest
```

---

## Verify Setup

After any updates, verify everything is working:

```bash
python -m src.agent status
```

Expected output:
```
Splunk SPL Agent Status
========================================
LLM Provider: groq/llama-3.3-70b-versatile
Splunk Connected: Yes
Documentation RAG: 1225 documents
Detection RAG: 1978 detections
CIM RAG: 1064 fields
Attack Data RAG: 1175 datasets
========================================
```

---

## Searching Knowledge Bases

You can search the knowledge bases directly:

```bash
# SPL documentation
python -m src.rag_spl_docs query "how to use stats command"

# Detection rules
python -m src.rag_detections query "credential dumping LSASS"

# CIM fields
python -m src.rag_cim_docs query "authentication fields"

# Attack data
python -m src.rag_attack_data query "T1003 credential access"
```

---

## Disk Space Requirements

| Component | Size |
|-----------|------|
| Data files (data/*.jsonl) | ~50 MB |
| Vector databases (vector_dbs/) | ~500 MB |
| Embedding model (cached) | ~130 MB |
| **Total** | ~700 MB |
