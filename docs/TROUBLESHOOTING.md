# Troubleshooting Guide

This guide covers common issues and their solutions when using the Splunk Detection Engineer Agent.

## Table of Contents

- [Installation Issues](#installation-issues)
- [Configuration Issues](#configuration-issues)
- [LLM Provider Issues](#llm-provider-issues)
- [Splunk Connection Issues](#splunk-connection-issues)
- [Data Fetcher Issues](#data-fetcher-issues)
- [RAG System Issues](#rag-system-issues)
- [Query Generation Issues](#query-generation-issues)
- [Performance Issues](#performance-issues)

---

## Installation Issues

### Playwright Browser Not Found

**Symptom:**
```
Error: Playwright chromium browser not installed
```

**Solution:**
```bash
playwright install chromium
```

If you encounter permission issues:
```bash
# Linux/macOS
sudo playwright install chromium

# Windows (run as Administrator)
playwright install chromium
```

### ChromaDB Installation Fails

**Symptom:**
```
ERROR: Could not build wheels for chromadb
```

**Solution:**
```bash
# Ensure you have the latest pip
pip install --upgrade pip setuptools wheel

# Install with specific version
pip install "chromadb>=0.4.22,<0.6"
```

### Torch Installation Issues

**Symptom:**
```
ERROR: No matching distribution found for torch
```

**Solution:**
```bash
# CPU-only version (recommended for this project)
pip install torch --index-url https://download.pytorch.org/whl/cpu

# Or with CUDA support
pip install torch --index-url https://download.pytorch.org/whl/cu121
```

---

## Configuration Issues

### Config File Not Found

**Symptom:**
```
FileNotFoundError: config/config.yaml not found
```

**Solution:**
```bash
# Copy the example config
cp config/config.yaml.example config/config.yaml

# Edit with your settings
nano config/config.yaml  # or your preferred editor
```

### Invalid YAML Syntax

**Symptom:**
```
yaml.scanner.ScannerError: mapping values are not allowed here
```

**Solution:**
- Check for proper indentation (use spaces, not tabs)
- Ensure colons are followed by a space
- Validate YAML at https://yamlvalidator.com/

Example correct format:
```yaml
provider: groq
settings:
  temperature: 0.2
  max_tokens: 2000
```

---

## LLM Provider Issues

### API Key Invalid

**Symptom:**
```
Error: Invalid API key or authentication failed
```

**Solution:**
1. Verify the API key in `config/config.yaml`
2. Ensure the key is active (not expired)
3. Check for extra whitespace around the key

### Rate Limit Exceeded

**Symptom:**
```
Error: Rate limit exceeded. Please try again later.
```

**Solution:**
- **Groq**: 14,400 requests/day limit. Wait or switch providers.
- **Mistral**: 1B tokens/month. Check usage at console.mistral.ai.
- **OpenRouter**: 50 requests/day on free tier.

Switch provider in config:
```yaml
provider: mistral  # Try a different provider
```

### Model Not Available

**Symptom:**
```
Error: Model 'xyz' not found
```

**Solution:**
Check available models for your provider:
- Groq: llama-3.3-70b-versatile, mixtral-8x7b-32768
- Mistral: mistral-large-latest, mistral-small-latest
- OpenAI: gpt-4o, gpt-4o-mini

Update config:
```yaml
provider: groq
model: llama-3.3-70b-versatile
```

### Connection Timeout

**Symptom:**
```
httpx.ConnectTimeout: timed out
```

**Solution:**
1. Check internet connectivity
2. Try a different provider
3. Increase timeout in provider settings

---

## Splunk Connection Issues

### Connection Refused

**Symptom:**
```
Error: Connection refused to splunk-host:8089
```

**Solution:**
1. Verify Splunk is running
2. Check host and port in config:
   ```yaml
   splunk:
     host: your-actual-splunk-host
     port: 8089
   ```
3. Ensure the Splunk management port (8089) is accessible
4. Check firewall rules

### SSL Certificate Error

**Symptom:**
```
ssl.SSLCertVerificationError: certificate verify failed
```

**Solution:**
Disable SSL verification (for testing only):
```yaml
splunk:
  ssl_verify: false
```

For production, use proper certificates or add your CA:
```yaml
splunk:
  ssl_verify: true
  ca_cert: /path/to/ca-bundle.crt
```

### Authentication Failed

**Symptom:**
```
Error: 401 Unauthorized
```

**Solution:**

**For token authentication:**
1. Generate a new token in Splunk (Settings > Tokens)
2. Ensure token has proper permissions
3. Update config:
   ```yaml
   splunk:
     token: your-new-token
   ```

**For username/password:**
```yaml
splunk:
  username: your-username
  password: your-password
  token: ""  # Leave empty
```

### Insufficient Permissions

**Symptom:**
```
Error: 403 Forbidden - User does not have permission
```

**Solution:**
The Splunk user needs these capabilities:
- `search`
- `list_inputs`
- `get_metadata`

Contact your Splunk administrator to grant permissions.

---

## Data Fetcher Issues

### Fetcher Shows Help Instead of Running

**Symptom:**
```
Running `python -m src.fetcher_spl_docs` shows help menu instead of updating
```

**Solution:**
This was fixed in recent versions. Ensure you have the latest code. The default command now runs smart update.

### Version Detection Fails (SPL Docs)

**Symptom:**
```
[!] Could not detect latest version, using default: 10.2
```

**Solution:**
1. Check internet connectivity
2. Splunk may be redirecting requests - the fetcher uses browser headers to avoid this
3. Run with force: `python -m src.fetcher_spl_docs force`

### GitHub API Rate Limit (Detections)

**Symptom:**
```
Error: 403 rate limit exceeded
```

**Solution:**
1. Wait for rate limit to reset (usually 60 requests/hour for unauthenticated)
2. Or set `GITHUB_TOKEN` environment variable for higher limits

### Git Clone Fails

**Symptom:**
```
[✗] Failed to clone/update repository
```

**Solution:**
1. Ensure `git` is installed: `git --version`
2. Check internet connectivity
3. Try manual clone:
   ```bash
   git clone --depth 1 https://github.com/splunk/security_content.git
   python -m src.fetcher_detections parse ./security_content/detections
   ```

### Empty Data Files Considered Up-to-Date

**Symptom:**
```
Local version: 10.2 (0 chunks)
[✓] Already up to date
```

**Solution:**
This was fixed in recent versions - 0 chunks now triggers re-download. Use force:
```bash
python -m src.fetcher_spl_docs force
```

---

## RAG System Issues

### ChromaDB Not Found / Empty

**Symptom:**
```
Error: ChromaDB collection not found
Warning: Documentation RAG: 0 documents
```

**Solution:**
First ensure you have data files, then regenerate the vector databases:
```bash
# Check if data files exist
ls -la data/*.jsonl

# If empty, re-fetch data
python -m src.fetcher_spl_docs force
python -m src.fetcher_detections force

# Then ingest into RAG
python -m src.rag_spl_docs ingest
python -m src.rag_detections ingest
```

### Vector Database Corruption

**Symptom:**
```
Error: ChromaDB integrity check failed
```
or
```
RuntimeError: Cannot return the results in a contigious 2D array. Probably ef or M is too small
```

**Solution:**
Delete and regenerate:
```bash
# Remove corrupted databases
rm -rf vector_dbs/

# Regenerate all
python -m src.rag_spl_docs ingest
python -m src.rag_detections ingest
python -m src.rag_cim_docs ingest
python -m src.rag_attack_data ingest
```

### CIM RAG Shows 0 Documents

**Symptom:**
```
CIM RAG: 0 documents (0 data models)
```

**Solution:**
1. Fetch CIM data first:
   ```bash
   python -m src.fetcher_cim_docs
   ```

2. Then ingest:
   ```bash
   python -m src.rag_cim_docs ingest
   ```

### Attack Data RAG Shows 0 Documents

**Symptom:**
```
Attack Data RAG: 0 datasets
```

**Solution:**
1. Fetch attack data first:
   ```bash
   python -m src.fetcher_attack_data
   ```

2. Then ingest:
   ```bash
   python -m src.rag_attack_data ingest
   ```

### CIM Field Names Incorrect

**Symptom:**
CIM search results show data model names (e.g., "Processes") instead of actual field names.

**Solution:**
This was fixed in v1.2.1. Re-crawl and re-ingest:
```bash
python -m src.fetcher_cim_docs force
python -m src.rag_cim_docs ingest
```

### Attack Data Duplicate ID Error

**Symptom:**
```
chromadb.errors.DuplicateIDError: Expected IDs to be unique, found duplicates
```

**Solution:**
This was fixed in v1.2.0 (IDs now have suffixes for duplicates). Delete and re-ingest:
```bash
rm -rf vector_dbs/attack_data
python -m src.rag_attack_data ingest
```

### Embedding Model Download Failed

**Symptom:**
```
Error: Unable to download BAAI/bge-small-en-v1.5
```

**Solution:**
1. Check internet connectivity
2. Manually download:
   ```python
   from sentence_transformers import SentenceTransformer
   model = SentenceTransformer("BAAI/bge-small-en-v1.5")
   ```
3. Check Hugging Face status: https://status.huggingface.co/

---

## Query Generation Issues

### Query Contains Macros

**Symptom:**
Generated query contains backtick macros like `` `security_content_summariesonly` ``

**Solution:**
This is a known issue when detection rules context contains macros. The agent is instructed to avoid macros, but occasionally the LLM includes them.

Workarounds:
1. Re-run the query (LLM responses vary)
2. Manually remove macros from the output
3. Report the issue if it happens frequently

### Query Returns No Results

**Symptom:**
```
Warning: Query validated but returned 0 results
```

**Possible causes:**
1. **Time range too narrow**: The default is -24h. Expand if needed:
   ```yaml
   agent:
     validation_time_range: "-7d"
   ```

2. **Data doesn't exist**: The index/sourcetype may not have matching data.

3. **Query too specific**: Try broadening search criteria.

### Failed After Max Iterations

**Symptom:**
```
Warning: Query could not be fully validated after 5 iterations
```

**Solution:**
1. Check if Splunk is properly connected
2. Verify the data source exists
3. Increase max iterations (temporary):
   ```yaml
   agent:
     max_iterations: 10
   ```
4. Try a simpler query first

---

## Performance Issues

### Slow Query Generation

**Symptom:**
Query generation takes > 30 seconds

**Possible causes:**
1. **LLM latency**: Try a faster provider (Groq is usually fastest)
2. **RAG retrieval**: Check vector database size
3. **Splunk validation**: Each iteration queries Splunk

**Solution:**
Disable validation for faster (but unvalidated) results:
```yaml
agent:
  enable_splunk_validation: false
```

### High Memory Usage

**Symptom:**
Python process uses > 2GB RAM

**Possible causes:**
- Embedding model loaded in memory (~500MB)
- Large ChromaDB collections

**Solution:**
1. Use CPU-only torch (smaller footprint)
2. Reduce `top_k` in RAG queries
3. Close and reopen the agent between sessions

### Slow First Query

**Symptom:**
First query takes 30+ seconds, subsequent queries are fast

**This is expected.** On first run:
1. Embedding model is loaded
2. ChromaDB collections are initialized
3. LLM provider is authenticated

Subsequent queries reuse these components.

---

## Getting Help

If your issue isn't covered here:

1. **Check existing issues**: https://github.com/yourusername/splunk-detection-engineer-agent/issues

2. **Open a new issue** with:
   - Python version (`python --version`)
   - OS and version
   - Full error message and stack trace
   - Steps to reproduce
   - Configuration (redact sensitive info)

3. **Enable debug logging**:
   ```python
   import logging
   logging.basicConfig(level=logging.DEBUG)
   ```

4. **Run status check**:
   ```bash
   python -m src.agent status
   ```
