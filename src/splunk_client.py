#!/usr/bin/env python3
"""
Splunk REST API Client
======================

A Python client for interacting with Splunk Enterprise REST API, enabling
metadata discovery, query execution, and validation for the Splunk SPL Agent.

Features:
    - Token-based and username/password authentication
    - Synchronous (oneshot) and asynchronous (job-based) search execution
    - Index, sourcetype, and field discovery
    - Query validation and testing
    - SSL certificate verification control

Usage:
    from splunk_client import SplunkClient, SplunkConfig
    
    # Load from config file
    client = SplunkClient.from_config()
    
    # Or create directly
    client = SplunkClient(
        host="your-splunk-host",
        port=8089,
        token="your-token-here",
        verify_ssl=False
    )
    
    # Run a quick search
    results = client.run_oneshot("| inputlookup geo_attr_countries.csv | head 5")
    
    # Discover available indexes
    indexes = client.list_indexes()
    
    # Get fields for a sourcetype
    fields = client.get_fields(index="main", sourcetype="syslog")

Dependencies:
    pip install httpx pyyaml

Author: Claude (Anthropic)
"""

import time
import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Any
from urllib.parse import urlencode
import logging

import httpx
import yaml

# Module-level logger - configuration is done by entry points (cli.py, server.py)
logger = logging.getLogger(__name__)


# =============================================================================
# CONFIGURATION
# =============================================================================

DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config" / "config.yaml"


@dataclass
class SplunkConfig:
    """Configuration for Splunk connection."""
    host: str = ""
    port: int = 8089
    username: str = ""
    password: str = ""
    token: str = ""
    verify_ssl: bool = False
    timeout: int = 120
    
    @classmethod
    def from_yaml(cls, path: Path = DEFAULT_CONFIG_PATH) -> "SplunkConfig":
        """Load configuration from YAML file."""
        if not path.exists():
            logger.warning(f"Config file not found at {path}, using defaults")
            return cls()
        
        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}
        
        splunk_data = data.get("splunk", {})
        
        return cls(
            host=splunk_data.get("host", ""),
            port=splunk_data.get("port", 8089),
            username=splunk_data.get("username", ""),
            password=splunk_data.get("password", ""),
            token=splunk_data.get("token", ""),
            verify_ssl=splunk_data.get("verify_ssl", False),
            timeout=data.get("settings", {}).get("timeout", 120),
        )
    
    def is_valid(self) -> bool:
        """Check if configuration has required fields."""
        if not self.host:
            return False
        # Need either token or username/password
        return bool(self.token) or (bool(self.username) and bool(self.password))


@dataclass
class SearchResult:
    """Standardized search result container."""
    results: list[dict] = field(default_factory=list)
    result_count: int = 0
    scan_count: int = 0
    run_duration: float = 0.0
    is_preview: bool = False
    messages: list[dict] = field(default_factory=list)
    fields: list[str] = field(default_factory=list)
    raw_response: Optional[Any] = None


@dataclass
class SearchJob:
    """Search job information for async searches."""
    sid: str
    status: str = "CREATED"
    is_done: bool = False
    is_failed: bool = False
    result_count: int = 0
    scan_count: int = 0
    run_duration: float = 0.0
    messages: list[dict] = field(default_factory=list)


# =============================================================================
# SPLUNK CLIENT
# =============================================================================

class SplunkClient:
    """
    Client for Splunk Enterprise REST API.
    
    Supports both token-based and username/password authentication.
    Provides methods for search execution, metadata discovery, and query validation.
    """
    
    def __init__(
        self,
        host: str,
        port: int = 8089,
        username: str = "",
        password: str = "",
        token: str = "",
        verify_ssl: bool = False,
        timeout: int = 120,
    ):
        """
        Initialize Splunk client.
        
        Args:
            host: Splunk server hostname or IP address
            port: Splunk management port (default 8089)
            username: Splunk username (if not using token)
            password: Splunk password (if not using token)
            token: Splunk authentication token (preferred)
            verify_ssl: Whether to verify SSL certificates
            timeout: Request timeout in seconds
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.token = token
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        
        self._base_url = f"https://{host}:{port}"
        self._client: Optional[httpx.Client] = None
        self._session_key: Optional[str] = None
    
    @classmethod
    def from_config(cls, config_path: Path = DEFAULT_CONFIG_PATH) -> "SplunkClient":
        """Create client from configuration file."""
        config = SplunkConfig.from_yaml(config_path)
        
        if not config.is_valid():
            raise ValueError(
                "Invalid Splunk configuration. Ensure host and either token or "
                "username/password are set in config.yaml"
            )
        
        return cls(
            host=config.host,
            port=config.port,
            username=config.username,
            password=config.password,
            token=config.token,
            verify_ssl=config.verify_ssl,
            timeout=config.timeout,
        )
    
    def _get_client(self) -> httpx.Client:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.Client(
                base_url=self._base_url,
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
        return self._client
    
    def _get_auth_headers(self) -> dict:
        """Get authentication headers."""
        if self.token:
            return {"Authorization": f"Bearer {self.token}"}
        elif self._session_key:
            return {"Authorization": f"Splunk {self._session_key}"}
        else:
            return {}
    
    def _authenticate(self) -> str:
        """
        Authenticate with username/password and get session key.
        
        Returns:
            Session key for subsequent requests.
        """
        if self.token:
            logger.info("Using token-based authentication")
            return self.token
        
        if not self.username or not self.password:
            raise ValueError("No authentication credentials provided")
        
        client = self._get_client()
        
        response = client.post(
            "/services/auth/login",
            data={"username": self.username, "password": self.password},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        
        if response.status_code != 200:
            raise RuntimeError(f"Authentication failed: {response.status_code}")
        
        # Parse XML response to get session key
        root = ET.fromstring(response.text)
        session_key = root.findtext("sessionKey")
        
        if not session_key:
            raise RuntimeError("Failed to extract session key from response")
        
        self._session_key = session_key
        logger.info("Successfully authenticated with username/password")
        return session_key
    
    def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        output_mode: str = "json",
    ) -> httpx.Response:
        """
        Make authenticated request to Splunk API.
        
        Args:
            method: HTTP method (GET, POST, DELETE)
            endpoint: API endpoint path
            params: Query parameters
            data: Form data for POST requests
            output_mode: Response format (json, xml, csv)
            
        Returns:
            HTTP response object.
        """
        # Ensure we have authentication
        if not self.token and not self._session_key:
            self._authenticate()
        
        client = self._get_client()
        headers = self._get_auth_headers()
        
        # Add output_mode to params
        params = params or {}
        params["output_mode"] = output_mode
        
        if method.upper() == "GET":
            response = client.get(endpoint, params=params, headers=headers)
        elif method.upper() == "POST":
            response = client.post(
                endpoint,
                params=params,
                data=data,
                headers=headers,
            )
        elif method.upper() == "DELETE":
            response = client.delete(endpoint, params=params, headers=headers)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")
        
        return response
    
    def _parse_json_response(self, response: httpx.Response) -> dict:
        """Parse JSON response and handle errors."""
        if response.status_code >= 400:
            try:
                error_data = response.json()
                messages = error_data.get("messages", [])
                error_text = "; ".join(m.get("text", "") for m in messages)
                raise RuntimeError(f"Splunk API error: {error_text}")
            except json.JSONDecodeError:
                raise RuntimeError(f"Splunk API error: HTTP {response.status_code}")
        
        try:
            return response.json()
        except json.JSONDecodeError:
            raise RuntimeError("Failed to parse JSON response from Splunk")
    
    # =========================================================================
    # CONNECTION TESTING
    # =========================================================================
    
    def test_connection(self) -> dict:
        """
        Test connection to Splunk server.
        
        Returns:
            Dictionary with connection status and server info.
        """
        try:
            response = self._request("GET", "/services/server/info")
            data = self._parse_json_response(response)
            
            entry = data.get("entry", [{}])[0]
            content = entry.get("content", {})
            
            return {
                "connected": True,
                "server_name": content.get("serverName", "Unknown"),
                "version": content.get("version", "Unknown"),
                "build": content.get("build", "Unknown"),
                "os_name": content.get("os_name", "Unknown"),
                "cpu_arch": content.get("cpu_arch", "Unknown"),
            }
        except Exception as e:
            return {
                "connected": False,
                "error": str(e),
            }
    
    # =========================================================================
    # METADATA DISCOVERY
    # =========================================================================
    
    def list_indexes(self, include_internal: bool = False) -> list[dict]:
        """
        List available indexes.
        
        Args:
            include_internal: Include internal indexes (those starting with _)
            
        Returns:
            List of index information dictionaries.
        """
        response = self._request("GET", "/services/data/indexes")
        data = self._parse_json_response(response)
        
        indexes = []
        for entry in data.get("entry", []):
            name = entry.get("name", "")
            
            # Skip internal indexes unless requested
            if not include_internal and name.startswith("_"):
                continue
            
            content = entry.get("content", {})
            indexes.append({
                "name": name,
                "totalEventCount": content.get("totalEventCount", 0),
                "currentDBSizeMB": content.get("currentDBSizeMB", 0),
                "minTime": content.get("minTime", ""),
                "maxTime": content.get("maxTime", ""),
                "disabled": content.get("disabled", False),
            })
        
        return indexes
    
    def list_sourcetypes(self, index: Optional[str] = None) -> list[dict]:
        """
        List available sourcetypes.
        
        Args:
            index: Optional index to filter sourcetypes
            
        Returns:
            List of sourcetype information dictionaries.
        """
        if index:
            # Use metadata search to get sourcetypes for specific index
            search = f"| metadata type=sourcetypes index={index}"
            result = self.run_oneshot(search, earliest_time="-24h")
            return [
                {
                    "name": r.get("sourcetype", ""),
                    "totalCount": int(r.get("totalCount", 0)),
                    "firstTime": r.get("firstTime", ""),
                    "lastTime": r.get("lastTime", ""),
                }
                for r in result.results
            ]
        else:
            # Get all saved sourcetypes
            response = self._request("GET", "/services/saved/sourcetypes")
            data = self._parse_json_response(response)
            
            sourcetypes = []
            for entry in data.get("entry", []):
                sourcetypes.append({
                    "name": entry.get("name", ""),
                })
            
            return sourcetypes
    
    def get_fields(
        self,
        index: str,
        sourcetype: Optional[str] = None,
        earliest_time: str = "-24h",
        max_results: int = 1000,
    ) -> list[dict]:
        """
        Get available fields for an index/sourcetype combination.
        
        Args:
            index: Index to search
            sourcetype: Optional sourcetype filter
            earliest_time: Time range for field discovery
            max_results: Maximum events to sample for field discovery
            
        Returns:
            List of field information dictionaries.
        """
        search = f"index={index}"
        if sourcetype:
            search += f" sourcetype={sourcetype}"
        search += f" | head {max_results} | fieldsummary"
        
        result = self.run_oneshot(search, earliest_time=earliest_time)
        
        fields = []
        for r in result.results:
            fields.append({
                "field": r.get("field", ""),
                "count": int(r.get("count", 0)),
                "distinct_count": int(r.get("distinct_count", 0)),
                "is_exact": r.get("is_exact", ""),
                "numeric_count": int(r.get("numeric_count", 0)),
                "values": r.get("values", ""),
            })
        
        return fields
    
    def get_metadata(
        self,
        metadata_type: str = "sourcetypes",
        index: Optional[str] = None,
        earliest_time: str = "-7d",
    ) -> list[dict]:
        """
        Get metadata about indexes, sourcetypes, sources, or hosts.
        
        Args:
            metadata_type: Type of metadata (sourcetypes, sources, hosts)
            index: Optional index filter
            earliest_time: Time range for metadata
            
        Returns:
            List of metadata dictionaries.
        """
        search = f"| metadata type={metadata_type}"
        if index:
            search += f" index={index}"
        
        result = self.run_oneshot(search, earliest_time=earliest_time)
        return result.results
    
    # =========================================================================
    # SYNCHRONOUS SEARCH (ONESHOT)
    # =========================================================================
    
    def run_oneshot(
        self,
        search: str,
        earliest_time: str = "-24h",
        latest_time: str = "now",
        max_results: int = 10000,
        output_mode: str = "json",
    ) -> SearchResult:
        """
        Run a synchronous (blocking) search and return results.
        
        Best for quick queries that complete in seconds.
        
        Args:
            search: SPL search query
            earliest_time: Start of time range
            latest_time: End of time range
            max_results: Maximum number of results to return
            output_mode: Output format (json, csv, xml)
            
        Returns:
            SearchResult object containing results and metadata.
        """
        # Ensure search starts with 'search' command if needed
        if not search.strip().startswith("|"):
            if not search.strip().lower().startswith("search "):
                search = f"search {search}"
        
        start_time = time.time()
        
        response = self._request(
            "POST",
            "/services/search/jobs/export",
            data={
                "search": search,
                "earliest_time": earliest_time,
                "latest_time": latest_time,
                "max_count": max_results,
            },
            output_mode=output_mode,
        )
        
        run_duration = time.time() - start_time
        
        if response.status_code >= 400:
            # Try to extract error message
            try:
                if output_mode == "json":
                    error_data = response.json()
                    messages = error_data.get("messages", [])
                    error_text = "; ".join(m.get("text", "") for m in messages)
                else:
                    error_text = response.text[:500]
                raise RuntimeError(f"Search failed: {error_text}")
            except json.JSONDecodeError:
                raise RuntimeError(f"Search failed: HTTP {response.status_code}")
        
        # Parse results based on output mode
        results = []
        fields = []
        messages = []
        
        if output_mode == "json":
            # JSON response is newline-delimited JSON objects
            for line in response.text.strip().split("\n"):
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if "result" in obj:
                        results.append(obj["result"])
                    if "fields" in obj and not fields:
                        fields = [f.get("name", "") for f in obj.get("fields", [])]
                    if "messages" in obj:
                        messages.extend(obj.get("messages", []))
                except json.JSONDecodeError:
                    continue
        
        return SearchResult(
            results=results,
            result_count=len(results),
            run_duration=run_duration,
            fields=fields,
            messages=messages,
            raw_response=response.text if len(response.text) < 10000 else None,
        )
    
    # =========================================================================
    # ASYNCHRONOUS SEARCH (JOB-BASED)
    # =========================================================================
    
    def create_job(
        self,
        search: str,
        earliest_time: str = "-24h",
        latest_time: str = "now",
        max_results: int = 10000,
    ) -> SearchJob:
        """
        Create an asynchronous search job.
        
        Use this for long-running searches. Poll with get_job_status() and
        retrieve results with get_job_results() when complete.
        
        Args:
            search: SPL search query
            earliest_time: Start of time range
            latest_time: End of time range
            max_results: Maximum number of results
            
        Returns:
            SearchJob object with job ID and initial status.
        """
        # Ensure search starts with 'search' command if needed
        if not search.strip().startswith("|"):
            if not search.strip().lower().startswith("search "):
                search = f"search {search}"
        
        response = self._request(
            "POST",
            "/services/search/jobs",
            data={
                "search": search,
                "earliest_time": earliest_time,
                "latest_time": latest_time,
                "max_count": max_results,
            },
        )
        
        data = self._parse_json_response(response)
        
        sid = data.get("sid", "")
        if not sid:
            raise RuntimeError("Failed to create search job: no SID returned")
        
        logger.info(f"Created search job: {sid}")
        
        return SearchJob(sid=sid, status="CREATED")
    
    def get_job_status(self, sid: str) -> SearchJob:
        """
        Get the status of a search job.
        
        Args:
            sid: Search job ID
            
        Returns:
            SearchJob object with current status.
        """
        response = self._request("GET", f"/services/search/jobs/{sid}")
        data = self._parse_json_response(response)
        
        entry = data.get("entry", [{}])[0]
        content = entry.get("content", {})
        
        messages = []
        for msg in content.get("messages", []):
            messages.append({
                "type": msg.get("type", ""),
                "text": msg.get("text", ""),
            })
        
        return SearchJob(
            sid=sid,
            status=content.get("dispatchState", "UNKNOWN"),
            is_done=content.get("isDone", False),
            is_failed=content.get("isFailed", False),
            result_count=content.get("resultCount", 0),
            scan_count=content.get("scanCount", 0),
            run_duration=content.get("runDuration", 0.0),
            messages=messages,
        )
    
    def get_job_results(
        self,
        sid: str,
        offset: int = 0,
        count: int = 10000,
    ) -> SearchResult:
        """
        Get results from a completed search job.
        
        Args:
            sid: Search job ID
            offset: Starting offset for pagination
            count: Number of results to retrieve
            
        Returns:
            SearchResult object containing results.
        """
        response = self._request(
            "GET",
            f"/services/search/jobs/{sid}/results",
            params={"offset": offset, "count": count},
        )
        
        data = self._parse_json_response(response)
        
        results = data.get("results", [])
        fields = [f.get("name", "") for f in data.get("fields", [])]
        messages = data.get("messages", [])
        
        return SearchResult(
            results=results,
            result_count=len(results),
            fields=fields,
            messages=messages,
        )
    
    def wait_for_job(
        self,
        sid: str,
        poll_interval: float = 1.0,
        timeout: Optional[float] = None,
    ) -> SearchJob:
        """
        Wait for a search job to complete.
        
        Args:
            sid: Search job ID
            poll_interval: Seconds between status checks
            timeout: Maximum seconds to wait (None for no timeout)
            
        Returns:
            Final SearchJob status.
        """
        start_time = time.time()
        
        while True:
            status = self.get_job_status(sid)
            
            if status.is_done or status.is_failed:
                return status
            
            if timeout and (time.time() - start_time) > timeout:
                raise TimeoutError(f"Search job {sid} did not complete within {timeout}s")
            
            time.sleep(poll_interval)
    
    def cancel_job(self, sid: str) -> bool:
        """
        Cancel a running search job.
        
        Args:
            sid: Search job ID
            
        Returns:
            True if cancellation was successful.
        """
        try:
            response = self._request(
                "POST",
                f"/services/search/jobs/{sid}/control",
                data={"action": "cancel"},
            )
            return response.status_code < 400
        except Exception:
            return False
    
    def run_search(
        self,
        search: str,
        earliest_time: str = "-24h",
        latest_time: str = "now",
        max_results: int = 10000,
        timeout: float = 300,
    ) -> SearchResult:
        """
        Run a search and wait for results (convenience method).
        
        Automatically uses async job for searches that might take long.
        
        Args:
            search: SPL search query
            earliest_time: Start of time range
            latest_time: End of time range
            max_results: Maximum number of results
            timeout: Maximum seconds to wait
            
        Returns:
            SearchResult object containing results.
        """
        job = self.create_job(
            search=search,
            earliest_time=earliest_time,
            latest_time=latest_time,
            max_results=max_results,
        )
        
        final_status = self.wait_for_job(job.sid, timeout=timeout)
        
        if final_status.is_failed:
            error_text = "; ".join(m.get("text", "") for m in final_status.messages)
            raise RuntimeError(f"Search failed: {error_text}")
        
        result = self.get_job_results(job.sid, count=max_results)
        result.run_duration = final_status.run_duration
        result.scan_count = final_status.scan_count
        
        return result
    
    # =========================================================================
    # QUERY VALIDATION
    # =========================================================================
    
    def validate_query(self, search: str) -> dict:
        """
        Validate SPL query syntax without executing.
        
        Args:
            search: SPL query to validate
            
        Returns:
            Dictionary with validation result and any error messages.
        """
        # Normalize query - Splunk parser requires 'search' prefix for base searches
        search = search.strip()
        if not search.startswith("|"):
            if not search.lower().startswith("search "):
                search = f"search {search}"
        
        # Use parse-only mode to validate without execution
        try:
            response = self._request(
                "POST",
                "/services/search/parser",
                data={"q": search, "parse_only": "true"},
            )
            
            if response.status_code == 200:
                # Return both keys for compatibility across consumers
                return {"valid": True, "success": True, "error": None}
            else:
                data = self._parse_json_response(response)
                messages = data.get("messages", [])
                error_text = "; ".join(m.get("text", "") for m in messages)
                return {"valid": False, "success": False, "error": error_text}
        except Exception as e:
            return {"valid": False, "success": False, "error": str(e)}
    
    def test_query(
        self,
        search: str,
        earliest_time: str = "-15m",
        max_results: int = 100,
    ) -> dict:
        """
        Test a query with limited scope to verify it works.
        
        Args:
            search: SPL query to test
            earliest_time: Short time range for testing
            max_results: Small result limit for testing
            
        Returns:
            Dictionary with test results and quality metrics.
        """
        try:
            result = self.run_oneshot(
                search=search,
                earliest_time=earliest_time,
                max_results=max_results,
            )
            
            # Return both keys for compatibility across consumers
            return {
                "valid": True,
                "success": True,
                "result_count": result.result_count,
                "fields": result.fields,
                "run_duration": result.run_duration,
                "sample_results": result.results[:5] if result.results else [],
                "messages": result.messages,
            }
        except Exception as e:
            return {
                "valid": False,
                "success": False,
                "error": str(e),
                "result_count": 0,
            }
    
    # =========================================================================
    # RESOURCE CLEANUP
    # =========================================================================
    
    def close(self):
        """Close the HTTP client and release resources."""
        if self._client:
            self._client.close()
            self._client = None
        self._session_key = None
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


# =============================================================================
# CLI INTERFACE
# =============================================================================

def main():
    """CLI entry point for testing Splunk client."""
    import sys
    
    if len(sys.argv) < 2:
        print("""
Splunk REST API Client
======================

Usage:
    python -m src.splunk_client test                    Test connection
    python -m src.splunk_client indexes                 List indexes
    python -m src.splunk_client sourcetypes [index]     List sourcetypes
    python -m src.splunk_client fields <index> [sourcetype]  Get fields
    python -m src.splunk_client search "<spl_query>"    Run search
    python -m src.splunk_client validate "<spl_query>"  Validate query

Examples:
    python -m src.splunk_client test
    python -m src.splunk_client indexes
    python -m src.splunk_client sourcetypes main
    python -m src.splunk_client fields main syslog
    python -m src.splunk_client search "index=_internal | head 5"
    python -m src.splunk_client validate "index=main | stats count"
""")
        sys.exit(0)
    
    command = sys.argv[1].lower()
    
    try:
        client = SplunkClient.from_config()
    except Exception as e:
        print(f"Error loading configuration: {e}")
        print("Ensure config.yaml has valid Splunk connection settings.")
        sys.exit(1)
    
    try:
        if command == "test":
            print("Testing Splunk connection...")
            result = client.test_connection()
            
            if result.get("connected"):
                print(f"\nConnection successful!")
                print(f"  Server: {result.get('server_name')}")
                print(f"  Version: {result.get('version')}")
                print(f"  Build: {result.get('build')}")
                print(f"  OS: {result.get('os_name')}")
                print(f"  Architecture: {result.get('cpu_arch')}")
            else:
                print(f"\nConnection failed: {result.get('error')}")
                sys.exit(1)
        
        elif command == "indexes":
            print("Fetching indexes...")
            indexes = client.list_indexes()
            
            print(f"\nFound {len(indexes)} indexes:")
            for idx in indexes:
                count = int(idx.get("totalEventCount", 0) or 0)
                size = float(idx.get("currentDBSizeMB", 0) or 0)
                print(f"  {idx['name']}: {count:,} events, {size:.1f} MB")
        
        elif command == "sourcetypes":
            index = sys.argv[2] if len(sys.argv) > 2 else None
            
            if index:
                print(f"Fetching sourcetypes for index '{index}'...")
            else:
                print("Fetching all sourcetypes...")
            
            sourcetypes = client.list_sourcetypes(index=index)
            
            print(f"\nFound {len(sourcetypes)} sourcetypes:")
            for st in sourcetypes:
                if "totalCount" in st:
                    count = int(st['totalCount'] or 0)
                    print(f"  {st['name']}: {count:,} events")
                else:
                    print(f"  {st['name']}")
        
        elif command == "fields":
            if len(sys.argv) < 3:
                print("Error: index required")
                print("Usage: python -m src.splunk_client fields <index> [sourcetype]")
                sys.exit(1)
            
            index = sys.argv[2]
            sourcetype = sys.argv[3] if len(sys.argv) > 3 else None
            
            print(f"Fetching fields for index='{index}'" + 
                  (f", sourcetype='{sourcetype}'" if sourcetype else "") + "...")
            
            fields = client.get_fields(index=index, sourcetype=sourcetype)
            
            print(f"\nFound {len(fields)} fields:")
            for f in sorted(fields, key=lambda x: int(x.get("count", 0) or 0), reverse=True)[:20]:
                count = int(f['count'] or 0)
                distinct = int(f['distinct_count'] or 0)
                print(f"  {f['field']}: {count:,} values, {distinct} distinct")
            
            if len(fields) > 20:
                print(f"  ... and {len(fields) - 20} more fields")
        
        elif command == "search":
            if len(sys.argv) < 3:
                print("Error: search query required")
                print('Usage: python -m src.splunk_client search "<spl_query>"')
                sys.exit(1)
            
            search = sys.argv[2]
            print(f"Running search: {search}")
            print("...")
            
            result = client.run_oneshot(search, earliest_time="-24h", max_results=100)
            
            print(f"\nResults: {result.result_count} events in {result.run_duration:.2f}s")
            
            if result.results:
                print("\nSample results:")
                for i, r in enumerate(result.results[:5]):
                    print(f"\n  [{i+1}]")
                    for k, v in list(r.items())[:5]:
                        print(f"    {k}: {str(v)[:80]}")
        
        elif command == "validate":
            if len(sys.argv) < 3:
                print("Error: query required")
                print('Usage: python -m src.splunk_client validate "<spl_query>"')
                sys.exit(1)
            
            query = sys.argv[2]
            print(f"Validating query: {query}")
            
            result = client.validate_query(query)
            
            if result.get("valid"):
                print("\nQuery is valid!")
            else:
                print(f"\nQuery is invalid: {result.get('error')}")
        
        else:
            print(f"Unknown command: {command}")
            sys.exit(1)
    
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
    finally:
        client.close()


if __name__ == "__main__":
    main()
