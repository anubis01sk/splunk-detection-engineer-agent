# Configuration

Complete guide to configuring the Splunk Detection Engineer Agent.

---

## Configuration File

The main configuration file is `config/config.yaml`. Copy the example file to get started:

```bash
cp config/config.yaml.example config/config.yaml
```

---

## LLM Providers

The agent supports multiple LLM providers. Choose based on your needs:

| Provider | Free Tier | Speed | Get API Key |
|----------|-----------|-------|-------------|
| **Groq** (recommended) | 14,400 req/day | Very Fast | https://console.groq.com |
| **Mistral** | 1B tokens/month | Fast | https://console.mistral.ai |
| **OpenRouter** | 50 req/day | Varies | https://openrouter.ai |
| **Claude** | Paid only | Fast | https://console.anthropic.com |
| **OpenAI** | Paid only | Fast | https://platform.openai.com |
| **DeepSeek** | Low cost | Fast | https://platform.deepseek.com |

### Groq Configuration (Recommended)
```yaml
provider: groq
groq:
  api_key: "your-groq-api-key"
  model: "llama-3.3-70b-versatile"
```

### Mistral Configuration
```yaml
provider: mistral
mistral:
  api_key: "your-mistral-api-key"
  model: "mistral-large-latest"
```

### OpenAI Configuration
```yaml
provider: openai
openai:
  api_key: "your-openai-api-key"
  model: "gpt-4o"
```

### Claude Configuration
```yaml
provider: anthropic
anthropic:
  api_key: "your-anthropic-api-key"
  model: "claude-sonnet-4-20250514"
```

### OpenRouter Configuration
```yaml
provider: openrouter
openrouter:
  api_key: "your-openrouter-api-key"
  model: "anthropic/claude-sonnet-4-20250514"
```

### DeepSeek Configuration
```yaml
provider: deepseek
deepseek:
  api_key: "your-deepseek-api-key"
  model: "deepseek-chat"
```

---

## Splunk Connection

The agent connects to Splunk via REST API (management port 8089) for:
- Query validation
- Field discovery
- Index/sourcetype verification

### Using JWT Token (Recommended)
```yaml
splunk:
  host: "your-splunk-host"
  port: 8089
  token: "your-jwt-token"
  ssl_verify: false
```

### Using Username/Password
```yaml
splunk:
  host: "your-splunk-host"
  port: 8089
  username: "admin"
  password: "your-password"
  ssl_verify: false
```

### SSL Verification
```yaml
splunk:
  ssl_verify: true    # Enable for production (requires valid cert)
  ssl_verify: false   # Disable for self-signed certs (dev/test)
```

### Testing Connection
```bash
python -m src.splunk_client test
```

---

## Complete Example Configuration

```yaml
# =============================================================================
# Splunk Detection Engineer Agent Configuration
# =============================================================================

# -----------------------------------------------------------------------------
# LLM Provider Configuration
# -----------------------------------------------------------------------------
provider: groq

groq:
  api_key: "gsk_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  model: "llama-3.3-70b-versatile"

# Alternative providers (uncomment to use):
# mistral:
#   api_key: "your-mistral-key"
#   model: "mistral-large-latest"
#
# openai:
#   api_key: "sk-xxxx"
#   model: "gpt-4o"

# -----------------------------------------------------------------------------
# Splunk Configuration
# -----------------------------------------------------------------------------
splunk:
  host: "splunk.example.com"
  port: 8089
  token: "eyJhbGciOiJIUzUxMiIs..."    # JWT token
  # username: "admin"                  # Alternative: username/password
  # password: "changeme"
  ssl_verify: false                    # Set true for production

# -----------------------------------------------------------------------------
# Agent Settings
# -----------------------------------------------------------------------------
agent:
  max_iterations: 3          # Max refinement attempts
  validation_timeout: 30     # Seconds to wait for Splunk validation
  default_earliest: "-24h"   # Default time range for queries

# -----------------------------------------------------------------------------
# RAG Settings
# -----------------------------------------------------------------------------
rag:
  top_k: 5                   # Number of results to retrieve
  similarity_threshold: 0.7  # Minimum similarity score
```

---

## Environment Variables

You can also use environment variables (override config file):

```bash
export GROQ_API_KEY="your-key"
export SPLUNK_HOST="splunk.example.com"
export SPLUNK_TOKEN="your-token"
```

---

## Verifying Configuration

After configuring, verify everything is connected:

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

## Troubleshooting Configuration

### LLM API Errors
- Verify API key is correct and active
- Check rate limits for your provider
- Try a different model or provider

### Splunk Connection Failed
- Verify host and port (default: 8089, not 8000)
- Check `ssl_verify` setting matches your cert setup
- Ensure token/credentials have sufficient permissions
- Test connectivity: `curl -k https://your-splunk:8089/services/server/info`

### Config File Not Found
- Ensure you're running from the project root directory
- Check file exists: `ls config/config.yaml`
- Copy from example: `cp config/config.yaml.example config/config.yaml`
