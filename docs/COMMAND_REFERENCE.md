# Command Reference

Complete command reference for the Splunk Detection Engineer Agent.

---

## Quick Reference

### Initial Setup
```bash
cd ~/splunk-detection-engineer-agent
python -m venv venv
source venv/bin/activate                    # Linux/Mac
# venv\Scripts\activate                     # Windows

pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -r requirements.txt
playwright install chromium
cp config/config.yaml.example config/config.yaml
```

### Ingest All RAG Databases (One-liner)
```bash
python -m src.rag_spl_docs ingest; python -m src.rag_detections ingest; python -m src.rag_cim_docs ingest; python -m src.rag_attack_data ingest
```

---

## Agent Commands

### Check Status
```bash
python -m src.agent status
```

### Run a Single Query
```bash
# Natural language
python -m src.agent run "Detect credential dumping from LSASS memory"
python -m src.agent run "Find PowerShell commands downloading files from internet"

# With reasoning trace
python -m src.agent run --reason "Detect brute force login attempts"

# Log source exploration
python -m src.agent run "index=windows sourcetype=WinEventLog:Security"

# IOC report (URL or PDF)
python -m src.agent run "https://example.com/threat-report.html"
```

### Interactive Mode
```bash
python -m src.agent interactive

# Inside interactive mode:
> reason on                    # Enable reasoning display
> reason off                   # Disable reasoning display
> Detect credential dumping    # Run query
> quit                         # Exit
```

---

## Splunk Client Commands

```bash
# Test Splunk connection
python -m src.splunk_client test

# List available indexes
python -m src.splunk_client indexes

# Run a search query
python -m src.splunk_client search "index=main earliest=0 | head 10"

# Get field list from an index
python -m src.splunk_client search "index=main earliest=0 | fieldsummary | table field"

# Validate query syntax only (no execution)
python -m src.splunk_client validate "index=* | stats count by sourcetype"
```

---

## RAG Commands

### Search Knowledge Bases
```bash
python -m src.rag_spl_docs query "stats count by"
python -m src.rag_detections query "credential dumping LSASS"
python -m src.rag_cim_docs query "process execution fields"
python -m src.rag_attack_data query "T1003"
```

### Ingest Data (Individual)
```bash
python -m src.rag_spl_docs ingest
python -m src.rag_detections ingest
python -m src.rag_cim_docs ingest
python -m src.rag_attack_data ingest
```

### Check RAG Statistics
```bash
python -m src.rag_spl_docs stats
python -m src.rag_detections stats
python -m src.rag_cim_docs stats
python -m src.rag_attack_data stats
```

### Reset RAG Database
```bash
python -m src.rag_detections reset    # Reset single RAG

# Reset all RAGs (then re-ingest)
rm -rf vector_dbs/
```

---

## Fetcher Commands (Update Knowledge Bases)

### Check for Updates
```bash
python -m src.fetcher_spl_docs check
python -m src.fetcher_detections check
python -m src.fetcher_cim_docs check
python -m src.fetcher_attack_data check
```

### Smart Update (Downloads Only If Newer)
```bash
python -m src.fetcher_spl_docs
python -m src.fetcher_detections
python -m src.fetcher_cim_docs
python -m src.fetcher_attack_data
```

### Force Re-download
```bash
python -m src.fetcher_spl_docs force
python -m src.fetcher_detections force
python -m src.fetcher_cim_docs force
python -m src.fetcher_attack_data force
```

### View Version Info
```bash
cat data/splunk_spl_docs.stats.json
cat data/splunk_spl_detections.stats.json
python -m src.fetcher_detections stats
```

---

## Web Server Commands

```bash
# Start web server (accessible externally on 0.0.0.0:8000)
python -m src.api.server

# Start web server (local only on 127.0.0.1:8000)
python -m src.api.server --local

# Alternative using uvicorn directly
uvicorn src.api.server:app --reload --port 8000
uvicorn src.api.server:app --reload --port 8000 --host 0.0.0.0
```

---

## Environment Notes

- **Always run from project root:** All `python -m src.*` commands must be run from the project root directory
- **Virtual environment:** Always activate your venv before running commands
- **Module syntax:** Use `python -m src.module_name` not `python src/module_name.py`
