# Web Interface

The Splunk Detection Engineer Agent includes a modern web dashboard built with vanilla HTML/JS/CSS and a FastAPI backend.

---

## Starting the Web Server

### Standard Method (Recommended)
```bash
python -m src.api.server
```
This starts the server on `0.0.0.0:8000` (accessible from other machines).

### Local Only
```bash
python -m src.api.server --local
```
This starts the server on `127.0.0.1:8000` (localhost only).

### Using Uvicorn Directly
```bash
# With auto-reload (development)
uvicorn src.api.server:app --reload --port 8000

# External access
uvicorn src.api.server:app --reload --port 8000 --host 0.0.0.0
```

Open http://localhost:8000 in your browser.

---

## Features

| Feature | Description |
|---------|-------------|
| **Chat Interface** | Natural language query generation with conversation history |
| **IOC Upload** | Process PDF files or URL-based IOC reports |
| **RAG Search** | Search across all 4 knowledge bases directly |
| **Settings Panel** | Configure LLM and Splunk connections in real-time |
| **Live Status** | Real-time component health indicators |
| **Chain of Thought** | Toggle reasoning visibility for query generation |

---

## Views

### Chat View
The main interface for generating SPL queries:
- Enter natural language descriptions
- Click example query buttons for quick starts
- Toggle "Show Reasoning" to see the agent's thought process
- Copy generated queries with one click

### Search View
Direct access to knowledge bases:
- Search SPL documentation
- Search detection rules
- Search CIM field definitions
- Search attack data samples

### Settings View
Configure connections without editing files:
- LLM provider selection and API keys
- Splunk host, port, and credentials
- Test connections in real-time

---

## UI Features

- **Dark theme** - Optimized for long security analysis sessions
- **Syntax highlighting** - SPL queries are highlighted for readability
- **Copy-to-clipboard** - One-click copy for all generated queries
- **Real-time status** - Component health shown in sidebar
- **Responsive design** - Works on various screen sizes

---

## API Endpoints

The web interface uses these REST API endpoints:

### Query Generation
```bash
POST /api/query
Content-Type: application/json

{
  "query": "Detect brute force login attempts",
  "show_reasoning": true
}
```

### RAG Search
```bash
POST /api/search
Content-Type: application/json

{
  "query": "credential dumping",
  "sources": ["detections", "spl_docs"]
}
```

### Status Check
```bash
GET /api/status
```

### E2E IOC Workflow
```bash
POST /api/workflow/e2e
Content-Type: multipart/form-data

url=https://example.com/threat-report.html
validate_splunk=true
test_attack_data=true
```

---

## Troubleshooting

### Server won't start
- Check if port 8000 is already in use
- Verify all dependencies are installed: `pip install fastapi uvicorn python-multipart`

### Can't access from other machines
- Use `python -m src.api.server` (binds to 0.0.0.0)
- Check firewall rules for port 8000

### Copy button doesn't work
- This happens when accessing via HTTP from a non-localhost address
- The clipboard API requires HTTPS or localhost
- A fallback method is included for HTTP access

### Settings don't persist
- Settings configured in the web UI are stored in `config/config.yaml`
- Ensure the file is writable

---

## Screenshots

See the main [README](../README.md) for screenshots of the web interface.
