#!/usr/bin/env python3
"""
Splunk Security Content Detection Fetcher (Smart Update)
=========================================================

Smart fetcher for Splunk Security Content detection rules with automatic
version checking via GitHub API.

Features:
- Automatic GitHub release version detection
- Smart updates: only downloads when newer version available
- Auto-clone/update of security_content repository
- Local cache with version tracking
- JSONL output for RAG ingestion

Commands:
    python -m src.fetcher_detections              # Smart update (download if needed)
    python -m src.fetcher_detections check        # Check for updates
    python -m src.fetcher_detections force        # Force re-download
    python -m src.fetcher_detections parse <dir>  # Parse from existing directory

Dependencies:
    pip install pyyaml httpx

Source: https://github.com/splunk/security_content
"""

import json
import hashlib
import subprocess
import shutil
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone
import logging
import sys

try:
    import yaml
except ImportError:
    print("PyYAML not installed. Run: pip install pyyaml")
    raise

try:
    import httpx
except ImportError:
    httpx = None  # Optional for version checking

# Module-level logger - configuration is done by entry points (cli.py, server.py)
logger = logging.getLogger(__name__)


# =============================================================================
# VERSION CONFIGURATION
# =============================================================================

GITHUB_REPO = "splunk/security_content"
GITHUB_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
GITHUB_CLONE_URL = f"https://github.com/{GITHUB_REPO}.git"

# Local paths
DATA_DIR = Path(__file__).parent.parent / "data"
STATS_FILE = "splunk_spl_detections.stats.json"
DATA_FILE = "splunk_spl_detections.jsonl"
CLONE_DIR = "security_content"


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class Detection:
    """Structured representation of a Splunk detection rule."""
    id: str
    name: str
    description: str
    search: str
    type: str = ""
    status: str = ""
    author: str = ""
    date: str = ""
    version: int = 0
    data_source: list[str] = field(default_factory=list)
    how_to_implement: str = ""
    known_false_positives: str = ""
    references: list[str] = field(default_factory=list)
    mitre_attack_id: list[str] = field(default_factory=list)
    analytic_story: list[str] = field(default_factory=list)
    asset_type: str = ""
    security_domain: str = ""
    product: list[str] = field(default_factory=list)
    category: str = ""
    source_file: str = ""
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)
    
    def to_embedding_text(self) -> str:
        """Create text representation optimized for embedding."""
        parts = [
            f"Detection: {self.name}",
            f"Description: {self.description}",
            f"SPL Search: {self.search}",
        ]
        
        if self.data_source:
            parts.append(f"Data Sources: {', '.join(self.data_source)}")
        
        if self.mitre_attack_id:
            parts.append(f"MITRE ATT&CK: {', '.join(self.mitre_attack_id)}")
        
        if self.analytic_story:
            parts.append(f"Analytic Stories: {', '.join(self.analytic_story)}")
        
        if self.how_to_implement:
            parts.append(f"Implementation: {self.how_to_implement}")
        
        if self.known_false_positives:
            parts.append(f"False Positives: {self.known_false_positives}")
        
        return "\n\n".join(parts)


# =============================================================================
# VERSION DETECTION
# =============================================================================

def get_latest_github_release() -> Optional[dict]:
    """
    Get latest release info from GitHub API.
    
    Returns:
        Dict with tag_name, published_at, html_url or None if failed
    """
    if httpx is None:
        logger.warning("httpx not installed, cannot check GitHub releases")
        return None
    
    try:
        print("[*] Checking GitHub for latest release...")
        
        with httpx.Client(timeout=10.0) as client:
            # First try the releases endpoint
            response = client.get(GITHUB_API_URL, follow_redirects=True)
            
            if response.status_code == 200:
                data = response.json()
                print(f"[+] Latest release: {data.get('tag_name')} ({data.get('published_at', '')[:10]})")
                return {
                    "tag_name": data.get("tag_name"),
                    "published_at": data.get("published_at"),
                    "html_url": data.get("html_url"),
                }
            
            # If no releases, try to get latest commit
            commits_url = f"https://api.github.com/repos/{GITHUB_REPO}/commits/develop"
            response = client.get(commits_url, follow_redirects=True)
            
            if response.status_code == 200:
                data = response.json()
                commit_date = data.get("commit", {}).get("committer", {}).get("date", "")
                sha = data.get("sha", "")[:8]
                print(f"[+] Latest commit: {sha} ({commit_date[:10] if commit_date else 'unknown'})")
                return {
                    "tag_name": f"develop-{sha}",
                    "published_at": commit_date,
                    "html_url": f"https://github.com/{GITHUB_REPO}/commit/{sha}",
                }
    
    except Exception as e:
        logger.error(f"Failed to check GitHub releases: {e}")
    
    return None


def get_local_version(data_dir: Path) -> Optional[dict]:
    """
    Get local version info from stats file.
    
    Returns:
        Dict with version info or None if not found
    """
    stats_path = data_dir / STATS_FILE
    
    if not stats_path.exists():
        return None
    
    try:
        with open(stats_path, 'r') as f:
            return json.load(f)
    except Exception:
        return None


def save_stats(
    data_dir: Path,
    version: str,
    total_detections: int,
    stats: dict,
    published_at: str = ""
):
    """Save version and statistics to stats file."""
    stats_path = data_dir / STATS_FILE
    
    full_stats = {
        "version": version,
        "published_at": published_at,
        "total_detections": total_detections,
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "source": f"https://github.com/{GITHUB_REPO}",
        **stats
    }
    
    with open(stats_path, 'w') as f:
        json.dump(full_stats, f, indent=2)
    
    print(f"[+] Stats saved to {stats_path}")


def version_is_newer(local_version: Optional[str], remote_version: str, 
                     local_date: Optional[str], remote_date: Optional[str]) -> bool:
    """
    Check if remote version is newer than local.
    
    Compares by version tag first, then by date if tags match.
    """
    if not local_version:
        return True
    
    # Simple string comparison for version tags
    if local_version != remote_version:
        return True
    
    # If versions match, compare dates
    if local_date and remote_date:
        try:
            local_dt = datetime.fromisoformat(local_date.replace('Z', '+00:00'))
            remote_dt = datetime.fromisoformat(remote_date.replace('Z', '+00:00'))
            return remote_dt > local_dt
        except ValueError:
            pass
    
    return False


# =============================================================================
# GIT OPERATIONS
# =============================================================================

def clone_or_update_repo(target_dir: Path, branch: str = "develop") -> bool:
    """
    Clone or update the security_content repository.
    
    Args:
        target_dir: Directory to clone into
        branch: Git branch to use
        
    Returns:
        True if successful
    """
    if target_dir.exists():
        print(f"[*] Updating existing repository: {target_dir}")
        try:
            # Pull latest changes
            result = subprocess.run(
                ["git", "-C", str(target_dir), "pull", "--rebase"],
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.returncode == 0:
                print("[+] Repository updated successfully")
                return True
            else:
                logger.warning(f"Git pull failed: {result.stderr}")
                # Try to remove and re-clone
                print("[!] Pull failed, will re-clone...")
                shutil.rmtree(target_dir)
        except subprocess.TimeoutExpired:
            logger.error("Git pull timed out")
            return False
        except Exception as e:
            logger.error(f"Git pull failed: {e}")
            return False
    
    # Clone the repository
    print(f"[*] Cloning {GITHUB_REPO} (branch: {branch})...")
    print("    This may take a few minutes...")
    
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", branch, GITHUB_CLONE_URL, str(target_dir)],
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        if result.returncode == 0:
            print("[+] Repository cloned successfully")
            return True
        else:
            logger.error(f"Git clone failed: {result.stderr}")
            return False
    
    except subprocess.TimeoutExpired:
        logger.error("Git clone timed out")
        return False
    except FileNotFoundError:
        logger.error("Git not found. Please install git.")
        return False
    except Exception as e:
        logger.error(f"Git clone failed: {e}")
        return False


# =============================================================================
# PARSING FUNCTIONS
# =============================================================================

def parse_yaml_file(file_path: Path) -> Optional[Detection]:
    """Parse a single YAML detection file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            documents = list(yaml.safe_load_all(f))
        
        if not documents:
            return None
        
        data = documents[0]
        
        if not data:
            return None
        
        detection_id = data.get('id', '')
        name = data.get('name', '')
        search = data.get('search', '')
        
        if not detection_id or not name or not search:
            return None
        
        tags = data.get('tags', {}) or {}
        
        # Determine category from file path
        category = ""
        parts = file_path.parts
        if 'detections' in parts:
            idx = parts.index('detections')
            if idx + 1 < len(parts):
                category = parts[idx + 1]
        
        detection = Detection(
            id=detection_id,
            name=name,
            description=data.get('description', ''),
            search=search,
            type=data.get('type', ''),
            status=data.get('status', ''),
            author=data.get('author', ''),
            date=str(data.get('date', '')),
            version=data.get('version', 0),
            data_source=data.get('data_source', []) or [],
            how_to_implement=data.get('how_to_implement', ''),
            known_false_positives=data.get('known_false_positives', ''),
            references=data.get('references', []) or [],
            mitre_attack_id=tags.get('mitre_attack_id', []) or [],
            analytic_story=tags.get('analytic_story', []) or [],
            asset_type=tags.get('asset_type', ''),
            security_domain=tags.get('security_domain', ''),
            product=tags.get('product', []) or [],
            category=category,
            source_file=str(file_path),
        )
        
        return detection
        
    except Exception as e:
        return None


def scan_detections_directory(base_path: Path) -> list[Detection]:
    """Recursively scan a directory for YAML detection files."""
    detections = []
    yaml_files = list(base_path.rglob("*.yml")) + list(base_path.rglob("*.yaml"))
    
    logger.info(f"Found {len(yaml_files)} YAML files in {base_path}")
    
    for i, file_path in enumerate(yaml_files, 1):
        if i % 100 == 0:
            logger.info(f"Processing file {i}/{len(yaml_files)}...")
        
        detection = parse_yaml_file(file_path)
        if detection:
            detections.append(detection)
    
    logger.info(f"Successfully parsed {len(detections)} detections")
    return detections


def save_to_jsonl(detections: list[Detection], output_path: Path) -> None:
    """Save detections to a JSONL file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        for detection in detections:
            json_line = json.dumps(detection.to_dict(), ensure_ascii=False)
            f.write(json_line + '\n')
    
    logger.info(f"Saved {len(detections)} detections to {output_path}")


def generate_stats(detections: list[Detection]) -> dict:
    """Generate statistics about the parsed detections."""
    stats = {
        "by_category": {},
        "by_type": {},
        "by_status": {},
        "by_security_domain": {},
        "mitre_techniques": set(),
        "analytic_stories": set(),
        "data_sources": set(),
    }
    
    for d in detections:
        cat = d.category or "unknown"
        stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1
        
        dtype = d.type or "unknown"
        stats["by_type"][dtype] = stats["by_type"].get(dtype, 0) + 1
        
        status = d.status or "unknown"
        stats["by_status"][status] = stats["by_status"].get(status, 0) + 1
        
        domain = d.security_domain or "unknown"
        stats["by_security_domain"][domain] = stats["by_security_domain"].get(domain, 0) + 1
        
        stats["mitre_techniques"].update(d.mitre_attack_id)
        stats["analytic_stories"].update(d.analytic_story)
        stats["data_sources"].update(d.data_source)
    
    # Convert sets to counts
    result = {
        "by_category": stats["by_category"],
        "by_type": stats["by_type"],
        "by_status": stats["by_status"],
        "by_security_domain": stats["by_security_domain"],
        "unique_mitre_techniques": len(stats["mitre_techniques"]),
        "unique_analytic_stories": len(stats["analytic_stories"]),
        "unique_data_sources": len(stats["data_sources"]),
    }
    
    return result


def print_stats(total: int, stats: dict) -> None:
    """Print statistics in a formatted way."""
    print("\n" + "=" * 60)
    print("DETECTION PARSING STATISTICS")
    print("=" * 60)
    
    print(f"\nTotal Detections: {total}")
    
    print(f"\nUnique MITRE ATT&CK Techniques: {stats['unique_mitre_techniques']}")
    print(f"Unique Analytic Stories: {stats['unique_analytic_stories']}")
    print(f"Unique Data Sources: {stats['unique_data_sources']}")
    
    print("\nBy Category:")
    for cat, count in sorted(stats["by_category"].items(), key=lambda x: -x[1]):
        print(f"  {cat}: {count}")
    
    print("\nBy Type:")
    for dtype, count in sorted(stats["by_type"].items(), key=lambda x: -x[1]):
        print(f"  {dtype}: {count}")
    
    print("\nBy Status:")
    for status, count in sorted(stats["by_status"].items(), key=lambda x: -x[1]):
        print(f"  {status}: {count}")
    
    print("=" * 60)


# =============================================================================
# SMART UPDATE FUNCTIONS
# =============================================================================

def check_for_updates(data_dir: Path = DATA_DIR) -> dict:
    """
    Check if updates are available for detection rules.
    
    Returns:
        Dict with status information
    """
    jsonl_path = data_dir / DATA_FILE
    
    result = {
        "local_exists": jsonl_path.exists(),
        "local_version": None,
        "local_detections": 0,
        "local_updated": None,
        "remote_version": None,
        "remote_published_at": None,
        "update_available": False,
    }
    
    # Check local version
    local_info = get_local_version(data_dir)
    if local_info:
        result["local_version"] = local_info.get("version")
        result["local_detections"] = local_info.get("total_detections", 0)
        result["local_updated"] = local_info.get("last_updated")
        result["local_published_at"] = local_info.get("published_at")
    
    # Check remote version
    remote_info = get_latest_github_release()
    if remote_info:
        result["remote_version"] = remote_info.get("tag_name")
        result["remote_published_at"] = remote_info.get("published_at")
    
    # Determine if update needed
    if not result["local_exists"]:
        result["update_available"] = True
        result["reason"] = "No local data found"
    elif result["local_version"] is None:
        result["update_available"] = True
        result["reason"] = "Local version unknown"
    elif result["remote_version"] and version_is_newer(
        result["local_version"],
        result["remote_version"],
        result.get("local_published_at"),
        result["remote_published_at"]
    ):
        result["update_available"] = True
        result["reason"] = f"Newer version available: {result['local_version']} → {result['remote_version']}"
    else:
        result["reason"] = "Already up to date"
    
    return result


def smart_update(
    data_dir: Path = DATA_DIR,
    force: bool = False,
    keep_clone: bool = False,
) -> bool:
    """
    Smart update: download detection rules only if needed.
    
    Args:
        data_dir: Output directory
        force: Force download even if up to date
        keep_clone: Keep the cloned repository after parsing
        
    Returns:
        True if download was performed
    """
    print("=" * 70)
    print("SPLUNK SECURITY CONTENT - SMART UPDATE")
    print("=" * 70)
    print()
    
    # Check for updates
    status = check_for_updates(data_dir)
    
    print(f"Local file exists: {status['local_exists']}")
    if status['local_version']:
        print(f"Local version: {status['local_version']} ({status['local_detections']} detections)")
        print(f"Last updated: {status['local_updated']}")
    print(f"Remote version: {status['remote_version']}")
    print(f"Update available: {status['update_available']}")
    if status.get('reason'):
        print(f"Reason: {status['reason']}")
    print()
    
    if not force and not status['update_available']:
        print("[✓] No update needed. Use 'force' command to re-download.")
        return False
    
    if force:
        print("[!] Force mode: downloading regardless of version...")
    else:
        print(f"[*] Downloading version {status['remote_version']}...")
    
    print()
    
    # Clone/update repository
    clone_path = data_dir / CLONE_DIR
    if not clone_or_update_repo(clone_path):
        print("[✗] Failed to clone/update repository")
        return False
    
    # Parse detections
    detections_path = clone_path / "detections"
    if not detections_path.exists():
        print(f"[✗] Detections directory not found: {detections_path}")
        return False
    
    print(f"\n[*] Parsing detections from: {detections_path}")
    detections = scan_detections_directory(detections_path)
    
    if not detections:
        print("[✗] No detections found!")
        return False
    
    # Save to JSONL
    output_file = data_dir / DATA_FILE
    save_to_jsonl(detections, output_file)
    
    # Generate and save stats
    stats = generate_stats(detections)
    print_stats(len(detections), stats)
    
    save_stats(
        data_dir,
        status['remote_version'] or "unknown",
        len(detections),
        stats,
        status.get('remote_published_at', '')
    )
    
    # Cleanup
    if not keep_clone:
        print(f"\n[*] Cleaning up cloned repository...")
        try:
            shutil.rmtree(clone_path)
            print("[+] Cleanup complete")
        except Exception as e:
            logger.warning(f"Failed to remove clone directory: {e}")
    else:
        print(f"\n[i] Repository kept at: {clone_path}")
    
    print()
    print("=" * 70)
    print(f"[✓] Successfully updated to {status['remote_version']}")
    print(f"    Detections saved to: {output_file}")
    print("=" * 70)
    
    return True


# =============================================================================
# CLI INTERFACE
# =============================================================================

def print_usage():
    """Print CLI usage."""
    print("""
Splunk Security Content Detection Fetcher (Smart Update)
=========================================================

Commands:
    python -m src.fetcher_detections              Smart update (download if needed)
    python -m src.fetcher_detections check        Check for updates without downloading
    python -m src.fetcher_detections force        Force re-download even if up to date
    python -m src.fetcher_detections parse <dir>  Parse from existing directory
    python -m src.fetcher_detections stats        Show statistics from local data
    python -m src.fetcher_detections show <id>    Display a specific detection by ID

Options (for smart update):
    --keep-clone       Keep the cloned repository after parsing
    --output-dir DIR   Output directory (default: data)

Examples:
    python -m src.fetcher_detections                          # Smart update
    python -m src.fetcher_detections check                    # Check for updates
    python -m src.fetcher_detections force                    # Force re-download
    python -m src.fetcher_detections force --keep-clone       # Force and keep repo
    python -m src.fetcher_detections parse ./security_content/detections
    python -m src.fetcher_detections stats
    python -m src.fetcher_detections show fb4c31b0-13e8-4155-8aa5-24de4b8d6717

Source: https://github.com/splunk/security_content
""")


def main():
    """CLI entry point."""
    args = sys.argv[1:]
    
    # Show help only if explicitly requested
    if args and args[0] in ["-h", "--help", "help"]:
        print_usage()
        return
    
    # Parse common options
    output_dir = DATA_DIR
    keep_clone = False
    
    for i, arg in enumerate(args):
        if arg == "--output-dir" and i + 1 < len(args):
            output_dir = Path(args[i + 1])
        elif arg == "--keep-clone":
            keep_clone = True
    
    # Determine command - default to smart update if no command or starts with --
    if not args or args[0].startswith("--"):
        command = "update"  # Default: smart update
    else:
        command = args[0].lower()
    
    if command == "update":
        # Smart update (default)
        smart_update(output_dir, keep_clone=keep_clone)
    
    elif command == "check":
        # Check for updates
        status = check_for_updates(output_dir)
        
        # Show local info
        if status['local_exists'] and status['local_version']:
            print(f"\nLocal version: {status['local_version']}")
            print(f"Local detections: {status['local_detections']}")
            if status['local_updated']:
                print(f"Last updated: {status['local_updated']}")
        else:
            print("\n[!] No local data found")
        
        # Show status
        print()
        if status['update_available']:
            print(f"[!] Update available: {status['reason']}")
            print("    Run 'python -m src.fetcher_detections' to update.")
        else:
            print("[✓] Already up to date.")
    
    elif command == "force":
        # Force re-download
        smart_update(output_dir, force=True, keep_clone=keep_clone)
    
    elif command == "parse":
        # Legacy parse command
        if len(args) < 2:
            print("Error: detections directory required")
            print("Usage: python -m src.fetcher_detections parse <detections_dir> [output_file]")
            sys.exit(1)
        
        # Find the directory argument (skip flags)
        detections_dir = None
        output_file = None
        
        for i, arg in enumerate(args[1:], 1):
            if arg.startswith("--"):
                continue
            if detections_dir is None:
                detections_dir = Path(arg)
            elif output_file is None:
                output_file = Path(arg)
        
        if detections_dir is None:
            print("Error: detections directory required")
            sys.exit(1)
        
        if output_file is None:
            output_file = output_dir / DATA_FILE
        
        if not detections_dir.exists():
            print(f"Error: Directory not found: {detections_dir}")
            sys.exit(1)
        
        print(f"Parsing detections from: {detections_dir}")
        detections = scan_detections_directory(detections_dir)
        
        if not detections:
            print("No detections found!")
            sys.exit(1)
        
        save_to_jsonl(detections, output_file)
        
        stats = generate_stats(detections)
        print_stats(len(detections), stats)
        
        save_stats(output_dir, "manual-parse", len(detections), stats)
        
        print(f"\nDetections saved to: {output_file}")
    
    elif command == "stats":
        # Show statistics
        jsonl_file = output_dir / DATA_FILE
        
        if not jsonl_file.exists():
            print(f"Error: File not found: {jsonl_file}")
            print("Run 'python -m src.fetcher_detections' first to download.")
            sys.exit(1)
        
        # Load and show stats from stats file
        local_info = get_local_version(output_dir)
        if local_info:
            print("\n" + "=" * 60)
            print("DETECTION STATISTICS")
            print("=" * 60)
            print(f"\nVersion: {local_info.get('version', 'unknown')}")
            print(f"Total Detections: {local_info.get('total_detections', 'unknown')}")
            print(f"Last Updated: {local_info.get('last_updated', 'unknown')}")
            print(f"Source: {local_info.get('source', 'unknown')}")
            
            if 'by_category' in local_info:
                print("\nBy Category:")
                for cat, count in sorted(local_info["by_category"].items(), key=lambda x: -x[1]):
                    print(f"  {cat}: {count}")
            
            if 'by_type' in local_info:
                print("\nBy Type:")
                for dtype, count in sorted(local_info["by_type"].items(), key=lambda x: -x[1]):
                    print(f"  {dtype}: {count}")
            
            print("=" * 60)
        else:
            print("No statistics found. Run 'python -m src.fetcher_detections' to generate.")
    
    elif command == "show":
        # Show a specific detection
        if len(args) < 2:
            print("Error: detection ID required")
            print("Usage: python -m src.fetcher_detections show <detection_id>")
            sys.exit(1)
        
        # Find the ID argument (skip flags)
        detection_id = None
        for arg in args[1:]:
            if not arg.startswith("--"):
                detection_id = arg
                break
        
        if detection_id is None:
            print("Error: detection ID required")
            sys.exit(1)
        
        jsonl_file = output_dir / DATA_FILE
        
        if not jsonl_file.exists():
            print(f"Error: File not found: {jsonl_file}")
            print("Run 'python -m src.fetcher_detections' first to download.")
            sys.exit(1)
        
        found = None
        with open(jsonl_file, 'r') as f:
            for line in f:
                data = json.loads(line)
                if data.get('id') == detection_id or detection_id in data.get('name', ''):
                    found = Detection(**data)
                    break
        
        if not found:
            print(f"Detection not found: {detection_id}")
            sys.exit(1)
        
        print("\n" + "=" * 60)
        print(f"DETECTION: {found.name}")
        print("=" * 60)
        print(f"\nID: {found.id}")
        print(f"Type: {found.type}")
        print(f"Status: {found.status}")
        print(f"Category: {found.category}")
        print(f"Author: {found.author}")
        print(f"Date: {found.date}")
        print(f"\nDescription:\n{found.description}")
        print(f"\nSPL Search:\n{found.search}")
        print(f"\nData Sources: {', '.join(found.data_source) if found.data_source else 'N/A'}")
        print(f"MITRE ATT&CK: {', '.join(found.mitre_attack_id) if found.mitre_attack_id else 'N/A'}")
        print(f"Analytic Stories: {', '.join(found.analytic_story) if found.analytic_story else 'N/A'}")
        print(f"Security Domain: {found.security_domain}")
        print(f"\nHow to Implement:\n{found.how_to_implement}")
        print(f"\nKnown False Positives:\n{found.known_false_positives}")
        print(f"\nReferences:")
        for ref in found.references:
            print(f"  - {ref}")
        print("=" * 60)
    
    else:
        print(f"Unknown command: {command}")
        print("Run 'python -m src.fetcher_detections help' for usage.")
        sys.exit(1)


if __name__ == "__main__":
    main()
