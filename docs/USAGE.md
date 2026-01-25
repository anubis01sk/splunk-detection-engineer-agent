# Usage Guide

Detailed guide for using the Splunk Detection Engineer Agent effectively.

---

## Supported Query Types

The agent understands a wide range of security-focused queries. For best results, use clear, descriptive language with security terminology.

### Raw Log Queries

Direct searches using native index/sourcetype fields:

```
"Detect brute force login attempts on Windows Security logs"
"Find PowerShell commands downloading files from the internet using Sysmon"
"Detect credential dumping from LSASS memory using Sysmon Event ID 10"
"Find executables created in Windows temp folders"
```

### CIM Data Model Queries

Accelerated tstats searches using normalized CIM fields (recommended for multi-source environments):

```
"Detect brute force login attempts using CIM Authentication data model with tstats"
"Find suspicious process executions using CIM Endpoint.Processes data model"
"Detect network connections to malicious ports using CIM Network Traffic data model"
"Find file modifications in sensitive directories using CIM Endpoint.Filesystem data model"
```

### IOC Report Processing

Process threat intelligence reports to generate detections:

```bash
# URL-based report
python -m src.agent run "https://example.com/threat-report.html"

# PDF file
python -m src.agent run "/path/to/threat-report.pdf"
```

### Log Source Exploration

Explore available data in your Splunk instance:

```bash
python -m src.agent run "index=windows sourcetype=WinEventLog:Security"
```

---

## Supported Keywords

The agent recognizes queries containing these security-focused terms:

| Category | Keywords |
|----------|----------|
| **Actions** | detect, find, search, query, monitor, alert, hunt, identify |
| **Threats** | attack, threat, malware, exploit, brute, suspicious, anomaly, malicious |
| **Authentication** | login, logon, auth, credential, password, access, failed, success |
| **Network** | network, traffic, connection, firewall, dns, http, port, inbound, outbound |
| **Execution** | process, command, powershell, script, execute, file, binary, executable |
| **System** | registry, service, user, admin, privilege, escalation, remote, local |
| **Splunk/CIM** | index, sourcetype, splunk, spl, stats, tstats, datamodel, cim, endpoint |
| **Platforms** | windows, linux, sysmon, eventcode, security |
| **IOC Types** | ioc, indicator, hash, domain, url, ip |
| **File Ops** | download, upload, create, delete, modify, write, read, directory, folder, path |
| **Tools** | lsass, mimikatz, psexec, wmi, rdp, dump, memory |

**Tip:** Queries with 2+ keywords from this list are processed immediately. For best results, be specific about what you want to detect and mention the data source (Sysmon, Windows Security, CIM data model, etc.).

---

## Example Output

When you run a query, you'll see output like this:

```
======================================================================
SPLUNK SPL AGENT - QUERY GENERATION RESULT
======================================================================

Status: SUCCESS
Input Type: natural_language
Iterations: 1
Total Time: 8.11s
Tokens: 6,801 (in: 6,337, out: 464)
Confidence: [███████░░░] 71.7%

--- GENERATED SPL QUERY ---

index=windows_security sourcetype=win_security 
EventCode=10 
TargetImage="*lsass.exe" 
GrantedAccess IN ("0x01000", "0x1010", "0x1038", "0x40", "0x1400")
| stats count min(_time) as firstTime max(_time) as lastTime 
  by CallTrace GrantedAccess SourceImage TargetImage dest user_id

--- EXPLANATION ---

This query detects potential credential dumping by identifying specific 
GrantedAccess permission requests targeting the LSASS process...

--- VALIDATION ---
Validated: Yes
Result Count: 0

--- GROUNDING ---
✅ Query is grounded (95% confidence)
   Sources: cim, detection
======================================================================
```

---

## Chain of Thought / Reasoning

Enable reasoning visualization to see exactly how the agent processes your request:

### CLI
```bash
python -m src.agent run --reason "Detect brute force login attempts"
```

### Interactive Mode
```bash
python -m src.agent interactive
> reason on
> Detect credential dumping
```

### What the Reasoning Shows

- 📋 **Input classification** - Natural language, log source, or IOC report
- 🔍 **RAG retrieval** - Scores and match counts from knowledge bases
- ⚙️ **Query generation** - Step-by-step construction process
- ✅ **Validation results** - Splunk syntax check outcomes
- 📊 **Confidence score** - 0-100% based on grounding quality

---

## End-to-End IOC Workflow

Complete automated pipeline from threat report to validated detection:

### Via CLI
```bash
python -m src.agent run "https://example.com/threat-report.html"
```

### Via API
```bash
curl -X POST "http://localhost:8000/api/workflow/e2e" \
  -F "url=https://example.com/threat-report.html" \
  -F "validate_splunk=true" \
  -F "test_attack_data=true"
```

### Workflow Stages

1. **Input** - Fetch and parse IOC report (URL or PDF)
2. **IOC Extraction** - Extract IPs, domains, hashes, file paths
3. **Detection Build** - Generate SPL query using Detection RAG
4. **Best Practices** - Validate against SPL Docs RAG
5. **Metadata Validation** - Test syntax against Splunk
6. **Attack Data Test** - Find relevant datasets for validation
7. **Complete** - Return results with confidence score

---

## Best Practices

1. **Be specific** - Include data source names (Sysmon, Windows Security, etc.)
2. **Use security terminology** - The agent is trained on security detection patterns
3. **Start broad, refine narrow** - Begin with general queries, add constraints
4. **Check grounding** - Higher confidence scores indicate better-grounded queries
5. **Review before production** - Always validate AI-generated queries manually
