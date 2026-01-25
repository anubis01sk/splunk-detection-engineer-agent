"""
FastAPI Server
==============

Main FastAPI application for the Splunk Agent API.

Usage:
    # Run with uvicorn
    uvicorn src.api.server:app --reload --port 8000
    
    # Or run as module
    python -m src.api.server

API Endpoints:
    GET  /api/health          Health check
    GET  /api/status          Agent component status
    POST /api/query           Generate SPL query from natural language
    POST /api/query/ioc       Generate IOC hunting query from URL/file
    POST /api/query/stream    Stream query generation with SSE
    GET  /api/config          Get current configuration
    POST /api/config          Update configuration
    POST /api/config/test-splunk  Test Splunk connection
    POST /api/search          Search RAG knowledge bases
    POST /api/workflow/e2e    Run end-to-end detection workflow
"""

import logging
import time
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
import asyncio
import json

from src import __version__
from src.api.models import (
    QueryRequest,
    QueryResponse,
    QueryStatus,
    HealthResponse,
    StatusResponse,
    ConfigResponse,
    ConfigUpdateRequest,
    SearchRequest,
    RAGSearchResponse,
    RAGSearchResult,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    
    app = FastAPI(
        title="Splunk Detection Engineer Agent API",
        description="AI-powered SPL query generation from natural language",
        version=__version__,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )
    
    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Lazy-loaded agent
    _agent = None
    _cim_rag = None
    _attack_rag = None
    
    def get_agent():
        """Get or create agent instance."""
        nonlocal _agent
        if _agent is None:
            from src.agent import SplunkAgent
            _agent = SplunkAgent()
        return _agent
    
    def get_cim_rag():
        """Get or create CIM RAG instance."""
        nonlocal _cim_rag
        if _cim_rag is None:
            try:
                from src.rag_cim_docs import CIMRAG
                _cim_rag = CIMRAG()
            except Exception as e:
                logger.warning(f"Could not initialize CIM RAG: {e}")
        return _cim_rag
    
    def get_attack_rag():
        """Get or create Attack Data RAG instance."""
        nonlocal _attack_rag
        if _attack_rag is None:
            try:
                from src.rag_attack_data import AttackDataRAG
                _attack_rag = AttackDataRAG()
            except Exception as e:
                logger.warning(f"Could not initialize Attack Data RAG: {e}")
        return _attack_rag
    
    # =========================================================================
    # HEALTH & STATUS
    # =========================================================================
    
    @app.get("/api/health", response_model=HealthResponse, tags=["Health"])
    async def health_check():
        """Check API health status."""
        return HealthResponse(
            status="healthy",
            version=__version__,
            components={
                "api": "running",
                "agent": "available",
            }
        )
    
    @app.get("/api/status", response_model=StatusResponse, tags=["Status"])
    async def get_status():
        """Get status of all agent components."""
        try:
            agent = get_agent()
            status = agent.get_status()
            
            # Check additional RAGs
            cim_docs = 0
            attack_docs = 0
            
            cim_rag = get_cim_rag()
            if cim_rag:
                try:
                    cim_stats = cim_rag.get_stats()
                    cim_docs = cim_stats.get("total_documents", 0)
                except Exception:
                    pass
            
            attack_rag = get_attack_rag()
            if attack_rag:
                try:
                    attack_stats = attack_rag.get_stats()
                    attack_docs = attack_stats.get("total_documents", 0)
                except Exception:
                    pass
            
            # Get token usage
            token_usage_data = status.get("token_usage", {})
            token_usage = None
            if token_usage_data:
                from src.api.models import TokenUsage
                token_usage = TokenUsage(
                    total_input_tokens=token_usage_data.get("total_input_tokens", 0),
                    total_output_tokens=token_usage_data.get("total_output_tokens", 0),
                    total_tokens=token_usage_data.get("total_tokens", 0),
                    request_count=token_usage_data.get("request_count", 0),
                )
            
            return StatusResponse(
                llm_provider=status.get("llm_provider"),
                splunk_connected=status.get("splunk_connected", False),
                doc_rag_documents=status.get("doc_rag_documents", 0),
                detection_rag_documents=status.get("detection_rag_documents", 0),
                cim_rag_documents=cim_docs,
                attack_data_documents=attack_docs,
                token_usage=token_usage,
            )
        except Exception as e:
            logger.error(f"Status check failed: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    # =========================================================================
    # QUERY GENERATION
    # =========================================================================
    
    @app.post("/api/query", response_model=QueryResponse, tags=["Query"])
    async def generate_query(request: QueryRequest):
        """Generate SPL query from user input."""
        try:
            agent = get_agent()
            
            logger.info(f"Processing query: {request.input[:50]}...")
            start_time = time.time()
            
            # Enable reasoning if requested
            show_reasoning = getattr(request, 'show_reasoning', False)
            result = agent.run(request.input, show_reasoning=show_reasoning)
            
            # Build response
            response_data = QueryResponse(
                status=QueryStatus(result.status.value),
                spl_query=result.spl_query,
                explanation=result.explanation,
                input_type=result.input_type.value,
                iterations=result.iterations,
                total_time=result.total_time,
                validated=result.validated,
                result_count=result.result_count,
                fields_discovered=result.fields_discovered,
                ioc_summary=result.ioc_summary,
                warnings=result.warnings,
                errors=result.errors,
            )
            
            # Add reasoning trace if available
            if result.reasoning_trace:
                response_data.reasoning = result.reasoning_trace.to_dict()
                response_data.confidence_score = result.reasoning_trace.get_confidence_score()
            
            # Add token usage
            if result.token_usage:
                response_data.token_usage = result.token_usage
            
            return response_data
        except Exception as e:
            logger.error(f"Query generation failed: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/query/stream", tags=["Query"])
    async def generate_query_stream(request: QueryRequest):
        """
        Generate SPL query with real-time reasoning updates via Server-Sent Events.
        
        Returns a stream of JSON events as the agent processes the request.
        """
        async def event_generator():
            try:
                agent = get_agent()
                reasoning_queue = asyncio.Queue()
                
                # Callback to capture reasoning steps
                def reasoning_callback(step):
                    try:
                        asyncio.get_event_loop().call_soon_threadsafe(
                            reasoning_queue.put_nowait,
                            step.to_dict()
                        )
                    except Exception:
                        pass  # Ignore queue errors
                
                # Start query in background
                import threading
                result_holder = {}
                
                def run_query():
                    try:
                        result_holder['result'] = agent.run(
                            request.input,
                            show_reasoning=True,
                            reasoning_callback=reasoning_callback
                        )
                    except Exception as e:
                        result_holder['error'] = str(e)
                    finally:
                        # Signal completion
                        try:
                            asyncio.get_event_loop().call_soon_threadsafe(
                                reasoning_queue.put_nowait,
                                None
                            )
                        except Exception:
                            pass
                
                thread = threading.Thread(target=run_query)
                thread.start()
                
                # Stream reasoning steps
                while True:
                    try:
                        step = await asyncio.wait_for(reasoning_queue.get(), timeout=60)
                        if step is None:
                            break
                        yield f"data: {json.dumps({'type': 'step', 'data': step})}\n\n"
                    except asyncio.TimeoutError:
                        yield f"data: {json.dumps({'type': 'keepalive'})}\n\n"
                
                thread.join()
                
                # Send final result
                if 'error' in result_holder:
                    yield f"data: {json.dumps({'type': 'error', 'data': result_holder['error']})}\n\n"
                elif 'result' in result_holder:
                    result = result_holder['result']
                    final_data = {
                        'type': 'complete',
                        'data': {
                            'status': result.status.value,
                            'spl_query': result.spl_query,
                            'explanation': result.explanation,
                            'input_type': result.input_type.value,
                            'iterations': result.iterations,
                            'total_time': result.total_time,
                            'validated': result.validated,
                            'result_count': result.result_count,
                            'fields_discovered': result.fields_discovered,
                            'warnings': result.warnings,
                            'errors': result.errors,
                        }
                    }
                    if result.reasoning_trace:
                        final_data['data']['reasoning'] = result.reasoning_trace.to_dict()
                        final_data['data']['confidence_score'] = result.reasoning_trace.get_confidence_score()
                    yield f"data: {json.dumps(final_data)}\n\n"
            except Exception as e:
                yield f"data: {json.dumps({'type': 'error', 'data': str(e)})}\n\n"
        
        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
            }
        )
    
    @app.post("/api/workflow/e2e", tags=["Workflow"])
    async def run_e2e_workflow(
        url: str = Form(None),
        file: UploadFile = File(None),
        validate_splunk: bool = Form(True),
        test_attack_data: bool = Form(True),
    ):
        """
        Run End-to-End IOC → Detection → Validation workflow.
        
        Complete automated pipeline:
        1. Extract IOCs from report
        2. Build detection query
        3. Apply best practices
        4. Validate against Splunk (optional)
        5. Test against attack data (optional)
        """
        try:
            from src.agent.e2e_workflow import run_e2e_workflow as e2e_run
            
            agent = get_agent()
            
            if url:
                ioc_source = url
            elif file:
                # Save uploaded file temporarily
                import tempfile
                import os
                
                with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
                    content = await file.read()
                    tmp.write(content)
                    ioc_source = tmp.name
            else:
                raise HTTPException(status_code=400, detail="Either URL or file required")
            
            try:
                result = e2e_run(
                    agent=agent,
                    ioc_source=ioc_source,
                    validate_with_splunk=validate_splunk,
                    test_with_attack_data=test_attack_data,
                )
            finally:
                # Clean up temp file if created
                if file and 'ioc_source' in locals():
                    try:
                        os.unlink(ioc_source)
                    except Exception:
                        pass
            
            return result.to_dict()
            
        except Exception as e:
            logger.error(f"E2E workflow failed: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/query/ioc", response_model=QueryResponse, tags=["Query"])
    async def generate_ioc_query(
        url: str = Form(None),
        file: UploadFile = File(None),
    ):
        """Generate SPL query from IOC report (URL or PDF upload)."""
        try:
            agent = get_agent()
            
            if url:
                # Process URL
                logger.info(f"Processing IOC URL: {url}")
                result = agent.run(url)
            elif file:
                # Save uploaded file temporarily
                import tempfile
                import os
                
                with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
                    content = await file.read()
                    tmp.write(content)
                    tmp_path = tmp.name
                
                try:
                    logger.info(f"Processing IOC file: {file.filename}")
                    result = agent.run(tmp_path)
                finally:
                    os.unlink(tmp_path)
            else:
                raise HTTPException(status_code=400, detail="Either URL or file required")
            
            return QueryResponse(
                status=QueryStatus(result.status.value),
                spl_query=result.spl_query,
                explanation=result.explanation,
                input_type=result.input_type.value,
                iterations=result.iterations,
                total_time=result.total_time,
                validated=result.validated,
                result_count=result.result_count,
                fields_discovered=result.fields_discovered,
                ioc_summary=result.ioc_summary,
                warnings=result.warnings,
                errors=result.errors,
            )
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"IOC query generation failed: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    # =========================================================================
    # CONFIGURATION
    # =========================================================================
    
    @app.get("/api/config", response_model=ConfigResponse, tags=["Configuration"])
    async def get_config():
        """Get current configuration (sensitive values masked)."""
        try:
            import yaml
            config_path = Path(__file__).parent.parent.parent / "config" / "config.yaml"
            
            if not config_path.exists():
                return ConfigResponse(
                    llm_provider=None,
                    llm_model=None,
                    splunk_host=None,
                    splunk_port=None,
                    splunk_verify_ssl=True,
                    has_splunk_credentials=False,
                    has_llm_api_key=False,
                )
            
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f) or {}
            
            llm_config = config.get("llm", {})
            splunk_config = config.get("splunk", {})
            
            return ConfigResponse(
                llm_provider=llm_config.get("provider"),
                llm_model=llm_config.get("model"),
                splunk_host=splunk_config.get("host"),
                splunk_port=splunk_config.get("port"),
                splunk_verify_ssl=splunk_config.get("verify_ssl", True),
                has_splunk_credentials=bool(
                    splunk_config.get("token") or 
                    (splunk_config.get("username") and splunk_config.get("password"))
                ),
                has_llm_api_key=bool(llm_config.get("api_key")),
            )
        except Exception as e:
            logger.error(f"Get config failed: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/config", tags=["Configuration"])
    async def update_config(request: ConfigUpdateRequest):
        """Update configuration."""
        try:
            import yaml
            config_path = Path(__file__).parent.parent.parent / "config" / "config.yaml"
            
            # Load existing config
            config = {}
            if config_path.exists():
                with open(config_path, 'r') as f:
                    config = yaml.safe_load(f) or {}
            
            # Update LLM settings
            if any([request.llm_provider, request.llm_api_key, request.llm_model]):
                if "llm" not in config:
                    config["llm"] = {}
                if request.llm_provider:
                    config["llm"]["provider"] = request.llm_provider
                if request.llm_api_key:
                    config["llm"]["api_key"] = request.llm_api_key
                if request.llm_model:
                    config["llm"]["model"] = request.llm_model
            
            # Update Splunk settings
            splunk_fields = [
                request.splunk_host, request.splunk_port, request.splunk_token,
                request.splunk_username, request.splunk_password, request.splunk_verify_ssl
            ]
            if any(f is not None for f in splunk_fields):
                if "splunk" not in config:
                    config["splunk"] = {}
                if request.splunk_host:
                    config["splunk"]["host"] = request.splunk_host
                if request.splunk_port:
                    config["splunk"]["port"] = request.splunk_port
                if request.splunk_token:
                    config["splunk"]["token"] = request.splunk_token
                if request.splunk_username:
                    config["splunk"]["username"] = request.splunk_username
                if request.splunk_password:
                    config["splunk"]["password"] = request.splunk_password
                if request.splunk_verify_ssl is not None:
                    config["splunk"]["verify_ssl"] = request.splunk_verify_ssl
            
            # Save config
            config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(config_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
            
            # Reset agent to reload config
            nonlocal _agent
            _agent = None
            
            return {"status": "success", "message": "Configuration updated"}
        except Exception as e:
            logger.error(f"Update config failed: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/config/test-splunk", tags=["Configuration"])
    async def test_splunk_connection():
        """Test Splunk connection with current configuration."""
        try:
            from src.splunk_client import SplunkClient
            
            config_path = Path(__file__).parent.parent.parent / "config" / "config.yaml"
            client = SplunkClient.from_config(config_path)
            result = client.test_connection()
            
            return {
                "connected": result.get("connected", False),
                "server_name": result.get("server_name"),
                "version": result.get("version"),
                "error": result.get("error"),
            }
        except Exception as e:
            return {
                "connected": False,
                "error": str(e),
            }
    
    # =========================================================================
    # RAG SEARCH
    # =========================================================================
    
    @app.post("/api/search", response_model=RAGSearchResponse, tags=["Search"])
    async def search_rags(request: SearchRequest):
        """Search across RAG systems."""
        results = []
        
        try:
            agent = get_agent()
            
            # Search SPL docs (uses query() method, returns QueryResult)
            if request.rag_type in ("spl_docs", "all") and agent.doc_rag:
                doc_results = agent.doc_rag.query(request.query, top_k=request.top_k)
                for i, r in enumerate(doc_results):
                    results.append(RAGSearchResult(
                        id=f"spl_doc_{i}",
                        content=r.content[:500],
                        score=r.similarity,  # QueryResult uses 'similarity'
                        source="spl_docs",
                        metadata={"url": r.url, "title": r.title},
                    ))
            
            # Search detections (DetectionResult has description/search, not content)
            if request.rag_type in ("detections", "all") and agent.detection_rag:
                det_results = agent.detection_rag.search(request.query, top_k=request.top_k)
                for r in det_results:
                    # Use description + search snippet as content
                    content = f"{r.description[:200]}...\n\nSPL: {r.search[:200]}..." if r.search else r.description[:500]
                    results.append(RAGSearchResult(
                        id=r.id,
                        content=content,
                        score=r.score,
                        source="detections",
                        metadata={"name": r.name, "mitre": r.mitre_attack_id or []},
                    ))
            
            # Search CIM
            if request.rag_type in ("cim", "all"):
                cim_rag = get_cim_rag()
                if cim_rag:
                    try:
                        cim_results = cim_rag.search(request.query, top_k=request.top_k)
                        logger.info(f"CIM search returned {len(cim_results)} results")
                        for r in cim_results:
                            results.append(RAGSearchResult(
                                id=r.id,
                                content=r.content[:500],
                                score=r.score,
                                source="cim",
                                metadata={"data_model": r.data_model},
                            ))
                    except Exception as e:
                        logger.error(f"CIM search failed: {e}")
            
            # Search attack data
            if request.rag_type in ("attack_data", "all"):
                attack_rag = get_attack_rag()
                if attack_rag:
                    try:
                        attack_results = attack_rag.search(request.query, top_k=request.top_k)
                        logger.info(f"Attack Data search returned {len(attack_results)} results")
                        for r in attack_results:
                            results.append(RAGSearchResult(
                                id=r.id,
                                content=r.content[:500],
                                score=r.score,
                                source="attack_data",
                                metadata={"mitre_id": r.mitre_id, "file_path": r.file_path},
                            ))
                    except Exception as e:
                        logger.error(f"Attack Data search failed: {e}")
            
            # Group results by source to ensure diversity
            # Then interleave and sort within groups
            by_source = {}
            for r in results:
                if r.source not in by_source:
                    by_source[r.source] = []
                by_source[r.source].append(r)
            
            # Sort each source's results by score
            for source in by_source:
                by_source[source].sort(key=lambda x: x.score, reverse=True)
            
            # Take top results from each source, then combine
            # This ensures we get results from all RAGs that matched
            final_results = []
            results_per_source = max(3, request.top_k // max(1, len(by_source)))
            
            for source, source_results in by_source.items():
                final_results.extend(source_results[:results_per_source])
            
            # Sort final results by score and limit
            final_results.sort(key=lambda x: x.score, reverse=True)
            
            return RAGSearchResponse(
                results=final_results[:request.top_k * 3],  # Allow more total results
                total=len(results),
                query=request.query,
            )
        except Exception as e:
            logger.error(f"RAG search failed: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    # =========================================================================
    # STATIC FILES
    # =========================================================================
    
    # Serve web UI (located at src/web/)
    web_dir = Path(__file__).parent.parent / "web"
    if web_dir.exists():
        app.mount("/static", StaticFiles(directory=str(web_dir)), name="static")
        
        @app.get("/", tags=["UI"])
        async def serve_ui():
            """Serve the web UI."""
            return FileResponse(str(web_dir / "index.html"))
    
    return app


# Create app instance
app = create_app()


def main():
    """Run the server.
    
    Usage:
        python -m src.api.server              # Run on 0.0.0.0:8000 (external access)
        python -m src.api.server --local      # Run on 127.0.0.1:8000 (local only)
    """
    import sys
    import uvicorn
    
    # Parse simple args
    local_only = "--local" in sys.argv
    
    host = "127.0.0.1" if local_only else "0.0.0.0"
    port = 8000
    
    print(f"\n🚀 Starting Splunk Detection Agent Dashboard")
    print(f"   URL: http://{'localhost' if local_only else '0.0.0.0'}:{port}")
    if not local_only:
        # Get local IP for external access hint
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            print(f"   External: http://{local_ip}:{port}")
        except Exception:
            pass
    print()
    
    uvicorn.run(
        "src.api.server:app",
        host=host,
        port=port,
        reload=True,
    )


if __name__ == "__main__":
    main()
