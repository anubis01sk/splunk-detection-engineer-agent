# Splunk SPL Agent - System Architecture Diagrams

This document contains Mermaid diagrams visualizing the technical architecture of the Splunk SPL Agent system.

**Project Status:** All 5 phases complete. Agent fully operational.

---

## Diagram 1: High-Level System Architecture

```mermaid
flowchart TB
    subgraph INPUTS["Input Layer"]
        NL["Natural Language<br/>Description"]
        LS["Log Source<br/>Specification"]
        IOC["IOC Report<br/>(URL/PDF)"]
    end

    subgraph PROCESSOR["Input Processor"]
        IP["input_processor.py<br/>✅ Complete"]
    end

    subgraph KNOWLEDGE["Knowledge Layer (ChromaDB)"]
        KB1[("SPL Documentation<br/>1225 documents<br/>BGE-small-en-v1.5<br/>✅ Complete")]
        KB2[("Detection Rules<br/>1,978 detections<br/>BGE-small-en-v1.5<br/>✅ Complete")]
        KB3[("CIM Data Models<br/>1,064 fields<br/>26 models<br/>✅ Complete")]
        KB4[("Attack Data<br/>1,175 datasets<br/>237 MITRE techniques<br/>✅ Complete")]
    end

    subgraph LLM["LLM Provider Layer"]
        LP["llm_provider.py<br/>✅ Complete"]
        subgraph PROVIDERS["Supported Providers"]
            GROQ["Groq<br/>(Default/Free)"]
            MISTRAL["Mistral<br/>(Free)"]
            OPENROUTER["OpenRouter<br/>(Free)"]
            CLAUDE["Claude"]
            GPT["OpenAI"]
            DEEPSEEK["DeepSeek"]
        end
    end

    subgraph SPLUNK["Splunk Integration"]
        SC["splunk_client.py<br/>✅ Complete"]
        subgraph SPLUNK_API["Splunk Enterprise 10.0.2"]
            META["Metadata Discovery<br/>indexes/sourcetypes/fields"]
            EXEC["Query Execution"]
            VAL["Result Validation"]
        end
    end

    subgraph AGENT["Agent Orchestrator"]
        SA["src/agent/<br/>✅ Complete"]
        GV["Grounding Validator<br/>(RAG-based)"]
        LOOP{{"Iterative<br/>Refinement<br/>Loop"}}
    end

    subgraph OUTPUT["Output Layer"]
        SPL["Production-Ready<br/>SPL Query"]
        DOC["Query Documentation<br/>& Explanation"]
    end

    NL --> IP
    LS --> IP
    IOC --> IP
    
    IP --> SA
    
    SA <--> KB1
    SA <--> KB2
    SA <--> KB3
    SA <--> KB4
    SA <--> LP
    SA <--> SC
    
    LP --> GROQ
    LP --> MISTRAL
    LP --> OPENROUTER
    LP --> CLAUDE
    LP --> GPT
    LP --> DEEPSEEK
    
    SC --> META
    SC --> EXEC
    SC --> VAL
    
    SA --> LOOP
    LOOP -->|"Query Invalid<br/>or Errors"| SA
    LOOP -->|"Query Valid<br/>& Optimized"| OUTPUT
    
    SPL --> OUTPUT
    DOC --> OUTPUT
```

---

## Diagram 2: Agent Workflow (Iterative Refinement Process)

```mermaid
flowchart TD
    START([User Input]) --> PARSE["1. Parse Input<br/>Classify trigger type<br/>(input_processor.py)"]
    
    PARSE --> CONTEXT["2. Retrieve Context<br/>Query both RAG collections<br/>(rag_spl_docs.py + rag_detections.py)"]
    
    CONTEXT --> GENERATE["3. Generate Initial Query<br/>LLM creates candidate SPL<br/>(llm_provider.py → Groq)"]
    
    GENERATE --> DISCOVER["4. Metadata Discovery<br/>Verify indexes/sourcetypes/fields<br/>(splunk_client.py)"]
    
    DISCOVER --> VALID_META{Fields Exist?}
    
    VALID_META -->|No| ADJUST["Adjust Query<br/>Use available fields"]
    ADJUST --> GENERATE
    
    VALID_META -->|Yes| EXECUTE["5. Execute Query<br/>Run against Splunk<br/>(limited time range: -24h)"]
    
    EXECUTE --> ANALYZE["6. Analyze Results<br/>Check for errors<br/>Inspect output"]
    
    ANALYZE --> QUALITY{Results OK?}
    
    QUALITY -->|"Errors<br/>(e.g., macro not found)"| ERROR_HANDLE["Parse Error Message<br/>Remove macros<br/>Use raw SPL"]
    ERROR_HANDLE --> GENERATE
    
    QUALITY -->|"No Results"| BROADEN["Broaden Search<br/>Check time range<br/>Verify data exists"]
    BROADEN --> GENERATE
    
    QUALITY -->|"Good"| OUTPUT["7. Output Final Query<br/>With documentation"]
    
    OUTPUT --> END([Return to User])
    
    subgraph ITERATION["Iteration Control (Max: 5)"]
        COUNTER["Iteration Counter"]
        COUNTER -.->|"Limit Reached"| FALLBACK["Return Best Attempt<br/>Status: PARTIAL<br/>With Warnings"]
        FALLBACK --> END
    end
```

---

## Diagram 3: Knowledge Base Architecture

```mermaid
flowchart LR
    subgraph SOURCES_DOC["Documentation Sources ✅"]
        SPLUNK_DOCS["help.splunk.com<br/>SPL Search Reference<br/>Search Manual<br/>191 pages crawled"]
    end
    
    subgraph SOURCES_DET["Detection Rule Sources ✅"]
        SECURITY["github.com/splunk/<br/>security_content<br/>1,978 detections"]
    end
    
    subgraph FUTURE["Future Sources (Planned)"]
        SIGMA["SigmaHQ Rules"]
        ELASTIC["Elastic Rules"]
        CHRONICLE["Chronicle Rules"]
        SENTINEL["Azure Sentinel"]
    end
    
    subgraph SCRAPERS["Scraping Layer ✅ (Smart Update)"]
        SC1["fetcher_spl_docs.py<br/>Playwright + BeautifulSoup<br/>Auto version: 10.2+<br/>Sidebar link extraction"]
        SC2["fetcher_detections.py<br/>YAML Parser + Git<br/>GitHub release check"]
    end
    
    subgraph PROCESSING["Processing Layer"]
        CHUNK1["Chunking<br/>~1225 chunks (v10.2)"]
        CHUNK2["Chunking<br/>1,978 detections"]
    end
    
    subgraph EMBEDDING["Embedding Layer"]
        EMB["BGE-small-en-v1.5<br/>384 dimensions<br/>CPU optimized"]
    end
    
    subgraph STORAGE["Vector Storage ✅"]
        DB1[("vector_dbs/spl_docs/<br/>1225 documents<br/>SPL Documentation")]
        DB2[("vector_dbs/detections/<br/>1,978 detections<br/>Security Content")]
        DB3[("vector_dbs/cim/<br/>250 chunks<br/>CIM Data Models")]
        DB4[("vector_dbs/attack_data/<br/>1,175 datasets<br/>Attack Data")]
    end
    
    subgraph QUERY["Query Interface ✅"]
        RAG1["rag_spl_docs.py<br/>Documentation queries"]
        RAG2["rag_detections.py<br/>Detection queries"]
    end
    
    SPLUNK_DOCS --> SC1
    SC1 --> CHUNK1
    CHUNK1 --> EMB
    EMB --> DB1
    DB1 --> RAG1
    
    SECURITY --> SC2
    SC2 --> CHUNK2
    CHUNK2 --> EMB
    EMB --> DB2
    DB2 --> RAG2
    
    FUTURE -.->|"Future Enhancement"| SC2
```

---

## Diagram 4: LLM Provider Interface

```mermaid
flowchart TB
    subgraph CONFIG["Configuration"]
        YAML["config.yaml<br/>API Keys<br/>Provider Settings<br/>Default: groq"]
    end
    
    subgraph INTERFACE["Unified Interface"]
        LLM_BASE["LLMProvider (Abstract Base)"]
        
        subgraph METHODS["Common Methods"]
            M1["generate(prompt) → response"]
            M2["count_tokens(text) → int"]
            M3["provider_name, model_name"]
        end
    end
    
    subgraph FREE_TIER["Free Tier Providers ✅"]
        GROQ_IMPL["GroqProvider<br/>llama-3.3-70b-versatile<br/>14,400 req/day"]
        MISTRAL_IMPL["MistralProvider<br/>mistral-small-latest<br/>1B tokens/month"]
        OPENROUTER_IMPL["OpenRouterProvider<br/>meta-llama/llama-3-8b<br/>50 req/day"]
    end
    
    subgraph PAID_TIER["Paid Providers ✅"]
        CLAUDE_IMPL["ClaudeProvider<br/>anthropic library"]
        GPT_IMPL["OpenAIProvider<br/>openai library"]
        DEEPSEEK_IMPL["DeepSeekProvider<br/>openai-compatible"]
    end
    
    subgraph FEATURES["Common Features"]
        RETRY["Automatic Retry<br/>Exponential Backoff"]
        USAGE["Token Usage<br/>Tracking"]
    end
    
    YAML --> LLM_BASE
    LLM_BASE --> METHODS
    
    LLM_BASE --> GROQ_IMPL
    LLM_BASE --> MISTRAL_IMPL
    LLM_BASE --> OPENROUTER_IMPL
    LLM_BASE --> CLAUDE_IMPL
    LLM_BASE --> GPT_IMPL
    LLM_BASE --> DEEPSEEK_IMPL
    
    FREE_TIER --> FEATURES
    PAID_TIER --> FEATURES
```

---

## Diagram 5: Splunk REST API Client

```mermaid
flowchart TB
    subgraph CLIENT["splunk_client.py ✅"]
        INIT["SplunkClient<br/>host: your-splunk-host<br/>port: 8089<br/>verify_ssl: False"]
    end
    
    subgraph AUTH["Authentication"]
        TOKEN["Token-based (JWT)<br/>Preferred method"]
        BASIC["Username/Password<br/>Fallback method"]
    end
    
    subgraph DISCOVERY["Metadata Discovery"]
        D1["list_indexes()<br/>/services/data/indexes"]
        D2["list_sourcetypes(index)<br/>| metadata type=sourcetypes"]
        D3["get_fields(index, sourcetype)<br/>| fieldsummary"]
    end
    
    subgraph SEARCH["Search Operations"]
        S1["run_oneshot(spl)<br/>Blocking search"]
        S2["create_job(spl)<br/>/services/search/jobs"]
        S3["get_job_status(sid)"]
        S4["get_job_results(sid)"]
        S5["wait_for_job(sid)"]
    end
    
    subgraph VALIDATION["Query Validation"]
        V1["validate_query(spl)<br/>Parse without execution"]
        V2["test_query(spl, time_range)<br/>Limited execution (-24h)"]
    end
    
    subgraph SPLUNK_ENV["Splunk Enterprise 10.0.2"]
        API["REST API<br/>:8089"]
    end
    
    CLIENT --> AUTH
    AUTH --> TOKEN
    AUTH --> BASIC
    TOKEN --> API
    BASIC --> API
    
    CLIENT --> DISCOVERY
    DISCOVERY --> API
    
    CLIENT --> SEARCH
    SEARCH --> API
    
    CLIENT --> VALIDATION
    VALIDATION --> SEARCH
```

---

## Diagram 6: Input Processing Flow

```mermaid
flowchart TD
    subgraph INPUT_TYPES["Input Types"]
        T1["Type 1: Natural Language<br/>'Detect brute force logins'"]
        T2["Type 2: Log Source<br/>'index=windows sourcetype=WinEventLog'"]
        T3["Type 3: IOC Report<br/>'https://report.pdf' or file.pdf"]
    end
    
    subgraph PROCESSOR["input_processor.py ✅"]
        CLASSIFY["classify_input(input)<br/>Determine type"]
        
        subgraph HANDLERS["Type Handlers"]
            H1["NaturalLanguageHandler<br/>Extract intent & entities<br/>Confidence scoring"]
            H2["LogSourceHandler<br/>Parse index/sourcetype<br/>Trigger metadata discovery"]
            H3["IOCReportHandler<br/>Playwright URL fetch<br/>pdfplumber PDF parsing"]
        end
    end
    
    subgraph IOC_EXTRACT["IOC Extraction"]
        FETCH["Fetch URL Content<br/>(Playwright headless)<br/>or Parse PDF<br/>(pdfplumber)"]
        EXTRACT["Extract Indicators:<br/>• IP addresses (IPv4/IPv6)<br/>• Domains<br/>• File hashes (MD5/SHA1/SHA256)<br/>• File names/paths<br/>• Registry keys<br/>• CVE IDs<br/>• MITRE ATT&CK IDs"]
        CONFIDENCE["Confidence Scoring<br/>0.0 - 1.0 per IOC"]
    end
    
    subgraph OUTPUT_PROC["Processed Input"]
        STRUCT["ProcessedInput Object<br/>type, entities, context,<br/>indicators, confidence"]
    end
    
    T1 --> CLASSIFY
    T2 --> CLASSIFY
    T3 --> CLASSIFY
    
    CLASSIFY -->|"natural_language"| H1
    CLASSIFY -->|"log_source"| H2
    CLASSIFY -->|"ioc_report"| H3
    
    H1 --> STRUCT
    H2 --> STRUCT
    
    H3 --> FETCH
    FETCH --> EXTRACT
    EXTRACT --> CONFIDENCE
    CONFIDENCE --> STRUCT
    
    STRUCT --> AGENT["To Agent Orchestrator"]
```

---

## Diagram 7: Complete Data Flow

```mermaid
sequenceDiagram
    participant U as User
    participant IP as Input Processor
    participant SA as Splunk Agent
    participant KB1 as SPL Docs RAG<br/>(1225 docs)
    participant KB2 as Detections RAG<br/>(1,978 rules)
    participant KB3 as CIM RAG<br/>(1,064 fields)
    participant KB4 as Attack Data RAG<br/>(1,175 datasets)
    participant LLM as Groq LLM<br/>(Llama 3.3 70B)
    participant SC as Splunk Client
    participant SE as Splunk 10.0.2
    
    U->>IP: Submit Input (NL/LogSource/IOC)
    IP->>IP: Classify & Parse
    IP->>SA: ProcessedInput object
    
    SA->>KB1: Query relevant SPL docs
    KB1-->>SA: Documentation context
    
    SA->>KB2: Query relevant detections
    KB2-->>SA: Detection examples<br/>(without macros warning)
    
    SA->>LLM: Generate SPL query<br/>(with NO_MACRO instruction)
    LLM-->>SA: Candidate query (raw SPL)
    
    SA->>SC: Test query validation
    SC->>SE: POST /services/search/jobs/export
    SE-->>SC: Results or error
    SC-->>SA: Validation result
    
    alt Query Has Errors
        SA->>LLM: Refine with error feedback
        LLM-->>SA: Revised query
        SA->>SC: Re-validate
    end
    
    alt Query Valid
        SA->>U: AgentResult<br/>status: SUCCESS<br/>spl_query + explanation
    end
    
    alt Max Iterations Reached
        SA->>U: AgentResult<br/>status: PARTIAL<br/>best attempt + warnings
    end
```

---

## Diagram 8: File Structure

```mermaid
flowchart TD
    subgraph ROOT["splunk-detection-engineer-agent/"]
        subgraph FOUNDATION["Foundation ✅"]
            F1["parser_spl_docs.py<br/>HTML Parser"]
            F2["fetcher_spl_docs.py<br/>Web Crawler"]
            F3["rag_spl_docs.py<br/>Documentation RAG"]
            F4["requirements.txt<br/>Dependencies"]
        end
        
        subgraph PHASE1["Phase 1 ✅"]
            F5["llm_provider.py<br/>Multi-LLM Interface<br/>Groq/Mistral/OpenRouter"]
            F6["config.yaml<br/>Configuration"]
        end
        
        subgraph PHASE2["Phase 2 ✅"]
            F7["splunk_client.py<br/>Splunk REST API"]
        end
        
        subgraph PHASE3["Phase 3 ✅"]
            F8["fetcher_detections.py<br/>YAML Parser"]
            F9["rag_detections.py<br/>Detection RAG"]
        end
        
        subgraph PHASE4["Phase 4 ✅"]
            F10["input_processor.py<br/>NL/LogSource/IOC Handlers"]
        end
        
        subgraph PHASE5["Phase 5 ✅"]
            F11["src/agent/<br/>Agent Package"]
        end
        
        subgraph DATA["Data Directories"]
            D1["data/<br/>Crawled docs & detections"]
            D2["vector_dbs/spl_docs/<br/>1225 documents"]
            D3["vector_dbs/detections/<br/>1,978 detections"]
            D4["vector_dbs/cim/<br/>250 chunks"]
            D5["vector_dbs/attack_data/<br/>1,175 datasets"]
            D4["security_content/<br/>Cloned repository"]
        end
        
        subgraph GENERATED["Generated Files"]
            G1["splunk_spl_docs.jsonl"]
            G2["crawl_manifest.json"]
            G3["splunk_spl_detections.jsonl"]
            G4["splunk_detections.stats.json"]
        end
    end
    
    FOUNDATION --> PHASE1
    PHASE1 --> PHASE2
    PHASE2 --> PHASE3
    PHASE3 --> PHASE4
    PHASE4 --> PHASE5
```

---

## Diagram 9: Detection Rules Statistics

```mermaid
pie title Detection Rules by Category (1,978 total)
    "Endpoint" : 1361
    "Cloud" : 321
    "Application" : 108
    "Network" : 100
    "Web" : 86
    "Deprecated" : 2
```

```mermaid
pie title Detection Rules by Type
    "TTP" : 1035
    "Anomaly" : 722
    "Hunting" : 206
    "Correlation" : 15
```

---

## How to Render These Diagrams

These Mermaid diagrams can be rendered using the following tools:

1. **VS Code** — Install the "Markdown Preview Mermaid Support" extension
2. **GitHub** — Paste directly into any .md file; GitHub renders Mermaid natively
3. **Mermaid Live Editor** — Visit https://mermaid.live and paste the diagram code
4. **Obsidian** — Native Mermaid support in notes
5. **Notion** — Use the /code block with "mermaid" language

---

## Document Metadata

| Attribute | Value |
|-----------|-------|
| Created | January 2025 |
| Last Updated | January 2025 |
| Diagrams | 9 |
| Format | Mermaid |
| Project Status | Complete (5/5 phases) |
