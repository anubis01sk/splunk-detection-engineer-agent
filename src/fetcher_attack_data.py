#!/usr/bin/env python3
"""
Splunk Attack Data Fetcher (Smart Update)
==========================================

Smart fetcher for Splunk Attack Data repository - a collection of attack
datasets for testing security detections.

Source: https://github.com/splunk/attack_data

Features:
- GitHub release version checking
- Smart updates: only downloads when newer release available
- Parses attack data manifests and metadata
- JSON Lines output for RAG integration

Commands:
    python -m src.fetcher_attack_data              # Smart update (download if needed)
    python -m src.fetcher_attack_data check        # Check for updates
    python -m src.fetcher_attack_data force        # Force re-download
    python -m src.fetcher_attack_data stats        # Show local data statistics

Dependencies:
    pip install httpx pyyaml
    git (for cloning repository)
"""

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
import yaml


# =============================================================================
# CONFIGURATION
# =============================================================================

GITHUB_REPO = "splunk/attack_data"
# Use commits API since this repo doesn't have formal releases
GITHUB_COMMITS_API = f"https://api.github.com/repos/{GITHUB_REPO}/commits?per_page=1"
GITHUB_TAGS_API = f"https://api.github.com/repos/{GITHUB_REPO}/tags?per_page=1"
REPO_CLONE_URL = f"https://github.com/{GITHUB_REPO}.git"

STATS_FILE = "splunk_attack_data.stats.json"
DATA_FILE = "splunk_attack_data.jsonl"

# Directories within the repo that contain attack data
ATTACK_DATA_DIRS = [
    "datasets",
]


# =============================================================================
# DATA MODELS
# =============================================================================

@dataclass
class AttackDataset:
    """An attack dataset with metadata."""
    id: str
    name: str
    description: str
    attack_technique: str
    mitre_id: str
    data_source: str
    file_path: str
    file_format: str
    tags: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "attack_technique": self.attack_technique,
            "mitre_id": self.mitre_id,
            "data_source": self.data_source,
            "file_path": self.file_path,
            "file_format": self.file_format,
            "tags": self.tags,
        }
    
    def to_chunk(self) -> dict:
        """Convert to RAG-friendly chunk."""
        return {
            "id": self.id,
            "type": "attack_dataset",
            "name": self.name,
            "content": (
                f"Attack Dataset: {self.name}\n\n"
                f"MITRE ATT&CK: {self.mitre_id} - {self.attack_technique}\n"
                f"Data Source: {self.data_source}\n"
                f"Format: {self.file_format}\n\n"
                f"Description: {self.description}\n\n"
                f"Tags: {', '.join(self.tags)}"
            ),
            "mitre_id": self.mitre_id,
            "attack_technique": self.attack_technique,
            "data_source": self.data_source,
            "file_path": self.file_path,
            "tags": self.tags,
        }


# =============================================================================
# VERSION DETECTION
# =============================================================================

def get_latest_version() -> tuple[str, str, bool]:
    """
    Get the latest version from GitHub using commits API.
    
    This repo doesn't use formal releases, so we check the latest commit.
    
    Returns:
        Tuple of (version/commit_sha, date, success)
    """
    print("[*] Checking GitHub for latest version...")
    
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "Splunk-Detection-Agent/1.0",
    }
    
    try:
        with httpx.Client(timeout=10.0, headers=headers) as client:
            # First try tags
            response = client.get(GITHUB_TAGS_API)
            if response.status_code == 200:
                tags = response.json()
                if tags:
                    version = tags[0].get("name", "unknown")
                    print(f"[+] Latest tag: {version}")
                    return version, "", True
            
            # Fall back to latest commit
            response = client.get(GITHUB_COMMITS_API)
            if response.status_code == 200:
                commits = response.json()
                if commits:
                    commit = commits[0]
                    sha = commit.get("sha", "")[:7]
                    date = commit.get("commit", {}).get("author", {}).get("date", "")[:10]
                    print(f"[+] Latest commit: {sha} ({date})")
                    return sha, date, True
            
            print(f"[!] GitHub API returned status {response.status_code}")
            return "unknown", "", False
                
    except Exception as e:
        print(f"[!] Error checking GitHub: {e}")
        return "unknown", "", False


# =============================================================================
# REPOSITORY MANAGEMENT
# =============================================================================

def clone_or_update_repo(target_dir: Path) -> bool:
    """
    Clone or update the attack_data repository.
    
    Args:
        target_dir: Directory to clone into
        
    Returns:
        True if successful
    """
    target_dir = Path(target_dir)
    
    if target_dir.exists():
        # Update existing repo
        print(f"[*] Updating existing repository in {target_dir}...")
        try:
            result = subprocess.run(
                ["git", "-C", str(target_dir), "pull", "--ff-only"],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode == 0:
                print("[+] Repository updated successfully")
                return True
            else:
                print(f"[!] Git pull failed: {result.stderr}")
                # Try fresh clone
                shutil.rmtree(target_dir)
        except Exception as e:
            print(f"[!] Error updating repo: {e}")
            shutil.rmtree(target_dir)
    
    # Clone fresh
    print(f"[*] Cloning repository to {target_dir}...")
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", REPO_CLONE_URL, str(target_dir)],
            capture_output=True,
            text=True,
            timeout=600,
        )
        if result.returncode == 0:
            print("[+] Repository cloned successfully")
            return True
        else:
            print(f"[!] Git clone failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"[!] Error cloning repo: {e}")
        return False


def cleanup_repo(repo_dir: Path):
    """Remove the cloned repository to save space."""
    if repo_dir.exists():
        print(f"[*] Cleaning up repository...")
        shutil.rmtree(repo_dir)


# =============================================================================
# PARSER
# =============================================================================

def parse_attack_datasets(repo_dir: Path) -> list[AttackDataset]:
    """
    Parse attack datasets from the repository.
    
    Looks for:
    - YAML/JSON manifest files
    - Directory structure conventions
    - README files with metadata
    
    Args:
        repo_dir: Path to cloned repository
        
    Returns:
        List of AttackDataset objects
    """
    datasets = []
    repo_dir = Path(repo_dir)
    
    print("[*] Scanning for attack datasets...")
    
    # Look for datasets directory structure
    for data_dir_name in ATTACK_DATA_DIRS:
        data_dir = repo_dir / data_dir_name
        if not data_dir.exists():
            continue
        
        # Recursively find data files and metadata
        for item in data_dir.rglob("*"):
            if item.is_file():
                # Try to parse metadata files
                if item.suffix in ('.yml', '.yaml'):
                    try:
                        datasets.extend(parse_yaml_metadata(item, repo_dir))
                    except Exception as e:
                        print(f"    Warning: Could not parse {item}: {e}")
                
                elif item.suffix == '.json' and 'manifest' in item.name.lower():
                    try:
                        datasets.extend(parse_json_manifest(item, repo_dir))
                    except Exception as e:
                        print(f"    Warning: Could not parse {item}: {e}")
    
    # If no structured metadata found, parse from directory structure
    if not datasets:
        print("[*] No metadata files found, parsing from directory structure...")
        datasets = parse_from_directory_structure(repo_dir)
    
    print(f"[+] Found {len(datasets)} attack datasets")
    return datasets


def parse_yaml_metadata(yaml_path: Path, repo_dir: Path) -> list[AttackDataset]:
    """Parse attack dataset from YAML metadata file."""
    datasets = []
    
    with open(yaml_path, 'r', encoding='utf-8') as f:
        try:
            data = yaml.safe_load(f)
        except yaml.YAMLError:
            return []
    
    if not data:
        return []
    
    # Handle different YAML structures
    if isinstance(data, dict):
        # Single dataset or container
        if 'name' in data or 'attack_data' in data:
            datasets.append(create_dataset_from_dict(data, yaml_path, repo_dir))
        elif 'datasets' in data:
            for ds in data.get('datasets', []):
                if isinstance(ds, dict):
                    datasets.append(create_dataset_from_dict(ds, yaml_path, repo_dir))
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                datasets.append(create_dataset_from_dict(item, yaml_path, repo_dir))
    
    return [d for d in datasets if d is not None]


def parse_json_manifest(json_path: Path, repo_dir: Path) -> list[AttackDataset]:
    """Parse attack datasets from JSON manifest."""
    datasets = []
    
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                datasets.append(create_dataset_from_dict(item, json_path, repo_dir))
    elif isinstance(data, dict):
        if 'datasets' in data:
            for item in data['datasets']:
                datasets.append(create_dataset_from_dict(item, json_path, repo_dir))
        else:
            datasets.append(create_dataset_from_dict(data, json_path, repo_dir))
    
    return [d for d in datasets if d is not None]


def extract_mitre_id_from_path(path: Path) -> str:
    """Extract MITRE ATT&CK ID from file path (e.g., T1059.001)."""
    import re
    # Look for patterns like T1059, T1059.001, TA0001, etc.
    path_str = str(path)
    match = re.search(r'[TtSsMm][Aa]?\d{4}(?:\.\d{3})?', path_str)
    if match:
        return match.group(0).upper()
    return ""


def create_dataset_from_dict(data: dict, source_path: Path, repo_dir: Path) -> Optional[AttackDataset]:
    """Create AttackDataset from dictionary."""
    # Extract name
    name = (
        data.get('name') or 
        data.get('title') or 
        data.get('attack_data', {}).get('name') or
        source_path.stem
    )
    
    # Extract description
    description = (
        data.get('description') or 
        data.get('summary') or
        data.get('attack_data', {}).get('description') or
        ""
    )
    
    # Extract MITRE info - check many possible field names
    mitre_id = ""
    attack_technique = ""
    
    # Common field names for MITRE ID
    mitre_id_fields = [
        'mitre_attack_id', 'mitre_technique_id', 'technique_id', 'attack_id',
        'mitre_id', 'attack_technique_id', 'technique', 'id'
    ]
    
    for field in mitre_id_fields:
        if not mitre_id and data.get(field):
            val = data[field]
            if isinstance(val, str) and (val.startswith('T') or val.startswith('t')):
                mitre_id = val.upper()
                break
    
    # Check nested structures
    mitre_attack = data.get('mitre_attack', data.get('mitre', data.get('mitre_attacks', {})))
    if isinstance(mitre_attack, list) and mitre_attack:
        first = mitre_attack[0] if isinstance(mitre_attack[0], dict) else {}
        if not mitre_id:
            for field in mitre_id_fields:
                if first.get(field):
                    mitre_id = str(first[field]).upper()
                    break
        attack_technique = first.get('technique', '') or first.get('name', '') or first.get('technique_name', '')
    elif isinstance(mitre_attack, dict):
        if not mitre_id:
            for field in mitre_id_fields:
                if mitre_attack.get(field):
                    mitre_id = str(mitre_attack[field]).upper()
                    break
        attack_technique = mitre_attack.get('technique', '') or mitre_attack.get('name', '') or mitre_attack.get('technique_name', '')
    
    # Check tags for MITRE IDs
    tags_list = data.get('tags', [])
    if isinstance(tags_list, list) and not mitre_id:
        for tag in tags_list:
            if isinstance(tag, str) and (tag.startswith('T') or tag.startswith('attack.t')):
                mitre_id = tag.replace('attack.', '').upper()
                break
    
    # Extract from file path as last resort
    if not mitre_id:
        mitre_id = extract_mitre_id_from_path(source_path)
    
    # Common field names for attack technique name
    if not attack_technique:
        technique_fields = ['technique_name', 'attack_technique', 'technique', 'attack_name']
        for field in technique_fields:
            if data.get(field):
                attack_technique = data[field]
                break
    
    # Extract data source
    data_source = (
        data.get('data_source') or
        data.get('source') or
        data.get('sourcetype') or
        data.get('attack_data', {}).get('data_source') or
        "Unknown"
    )
    
    # Extract file info
    file_path = str(source_path.relative_to(repo_dir))
    file_format = data.get('format', '') or source_path.suffix[1:] if source_path.suffix else 'unknown'
    
    # Check for data file reference
    if data.get('file'):
        file_path = data['file']
    elif data.get('data_file'):
        file_path = data['data_file']
    
    # Extract tags
    tags = []
    if data.get('tags'):
        tags = data['tags'] if isinstance(data['tags'], list) else [data['tags']]
    if data.get('labels'):
        tags.extend(data['labels'] if isinstance(data['labels'], list) else [data['labels']])
    
    # Generate ID
    dataset_id = (
        data.get('id') or
        f"attack_data_{name.lower().replace(' ', '_').replace('-', '_')[:50]}"
    )
    
    return AttackDataset(
        id=dataset_id,
        name=name,
        description=description[:1000] if description else "",
        attack_technique=attack_technique,
        mitre_id=mitre_id,
        data_source=data_source,
        file_path=file_path,
        file_format=file_format,
        tags=tags[:10],
    )


def parse_from_directory_structure(repo_dir: Path) -> list[AttackDataset]:
    """
    Parse datasets from directory structure when no metadata available.
    
    Assumes structure like: datasets/<technique>/<data_file>
    """
    datasets = []
    
    for data_dir_name in ATTACK_DATA_DIRS:
        data_dir = repo_dir / data_dir_name
        if not data_dir.exists():
            continue
        
        # Find all data files
        data_extensions = {'.log', '.json', '.csv', '.txt', '.xml', '.gz', '.bz2'}
        
        for file_path in data_dir.rglob("*"):
            if file_path.is_file() and file_path.suffix.lower() in data_extensions:
                # Extract info from path
                relative_path = file_path.relative_to(repo_dir)
                parts = relative_path.parts
                
                name = file_path.stem
                technique = parts[1] if len(parts) > 1 else "Unknown"
                
                datasets.append(AttackDataset(
                    id=f"attack_data_{name[:50]}",
                    name=name,
                    description=f"Attack data file: {relative_path}",
                    attack_technique=technique.replace('_', ' ').replace('-', ' ').title(),
                    mitre_id="",
                    data_source=technique,
                    file_path=str(relative_path),
                    file_format=file_path.suffix[1:] or "unknown",
                    tags=[technique],
                ))
    
    return datasets


# =============================================================================
# SMART UPDATE
# =============================================================================

def smart_update(output_dir: Path = Path("data"), force: bool = False, cleanup: bool = True) -> bool:
    """
    Perform smart update: check version and download if needed.
    
    Args:
        output_dir: Directory for output files
        force: Force download even if up to date
        cleanup: Remove cloned repo after parsing
        
    Returns:
        True if update was performed
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    stats_path = output_dir / STATS_FILE
    data_path = output_dir / DATA_FILE
    repo_dir = output_dir / "attack_data_repo"
    
    print("=" * 70)
    print("SPLUNK ATTACK DATA - SMART UPDATE")
    print("=" * 70)
    
    # Get latest version
    latest_version, release_date, success = get_latest_version()
    
    # Check local version
    local_version = None
    local_count = 0
    
    if stats_path.exists():
        try:
            with open(stats_path, 'r') as f:
                local_stats = json.load(f)
            local_version = local_stats.get("version")
            local_count = local_stats.get("total_datasets", 0)
            print(f"Local file exists: True")
            print(f"Local version: {local_version} ({local_count} datasets)")
            print(f"Last updated: {local_stats.get('last_updated', 'Unknown')}")
        except Exception as e:
            print(f"Local file exists: True (error reading: {e})")
    else:
        print(f"Local file exists: False")
    
    print(f"Remote version: {latest_version}")
    
    # Determine if update needed
    needs_update = False
    reason = ""
    
    if force:
        needs_update = True
        reason = "Force mode"
    elif not data_path.exists():
        needs_update = True
        reason = "No local data found"
    elif local_count == 0:
        needs_update = True
        reason = "Local data is empty"
    elif local_version != latest_version and latest_version != "unknown":
        needs_update = True
        reason = f"Newer version available ({local_version} → {latest_version})"
    
    print(f"Update available: {needs_update}")
    if reason:
        print(f"Reason: {reason}")
    
    if not needs_update:
        print("\n[✓] Already up to date!")
        return False
    
    # Clone/update repository
    print(f"\n[*] Downloading version {latest_version}...")
    
    if not clone_or_update_repo(repo_dir):
        print("[!] Failed to clone repository")
        return False
    
    # Parse datasets
    datasets = parse_attack_datasets(repo_dir)
    
    if not datasets:
        print("[!] No datasets found")
        return False
    
    # Save JSON Lines file
    chunks = [ds.to_chunk() for ds in datasets]
    
    with open(data_path, 'w', encoding='utf-8') as f:
        for chunk in chunks:
            f.write(json.dumps(chunk, ensure_ascii=False) + '\n')
    print(f"\n[+] JSON Lines file: {data_path}")
    
    # Collect statistics
    mitre_ids = set(ds.mitre_id for ds in datasets if ds.mitre_id)
    data_sources = set(ds.data_source for ds in datasets)
    tags = set()
    for ds in datasets:
        tags.update(ds.tags)
    
    # Save stats
    stats = {
        "version": latest_version,
        "release_date": release_date,
        "total_datasets": len(datasets),
        "unique_mitre_techniques": len(mitre_ids),
        "unique_data_sources": len(data_sources),
        "unique_tags": len(tags),
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "source": f"https://github.com/{GITHUB_REPO}",
    }
    
    with open(stats_path, 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2)
    print(f"[+] Stats saved to {stats_path}")
    
    # Cleanup
    if cleanup and repo_dir.exists():
        cleanup_repo(repo_dir)
    
    print("=" * 70)
    print("UPDATE COMPLETE")
    print("=" * 70)
    print(f"Datasets: {len(datasets)}")
    print(f"MITRE Techniques: {len(mitre_ids)}")
    print(f"Data Sources: {len(data_sources)}")
    print("=" * 70)
    
    return True


# =============================================================================
# CLI
# =============================================================================

def print_stats(output_dir: Path = Path("data")):
    """Print local data statistics."""
    stats_path = output_dir / STATS_FILE
    
    if not stats_path.exists():
        print("No local attack data found. Run 'python -m src.fetcher_attack_data' to download.")
        return
    
    with open(stats_path, 'r') as f:
        stats = json.load(f)
    
    print("\nSplunk Attack Data - Local Data")
    print("=" * 50)
    print(f"Version: {stats.get('version', 'Unknown')}")
    print(f"Release Date: {stats.get('release_date', 'Unknown')}")
    print(f"Total Datasets: {stats.get('total_datasets', 0)}")
    print(f"MITRE Techniques: {stats.get('unique_mitre_techniques', 0)}")
    print(f"Data Sources: {stats.get('unique_data_sources', 0)}")
    print(f"Tags: {stats.get('unique_tags', 0)}")
    print(f"Last Updated: {stats.get('last_updated', 'Unknown')}")
    print(f"Source: {stats.get('source', 'Unknown')}")
    print("=" * 50)


def main():
    """CLI entry point."""
    import sys
    
    output_dir = Path("data")
    
    # Default command if no args
    if len(sys.argv) < 2 or sys.argv[1].startswith('--'):
        smart_update(output_dir=output_dir)
        return
    
    command = sys.argv[1].lower()
    
    if command == "check":
        latest_version, date, _ = get_latest_version()
        
        # Show local info
        stats_path = output_dir / STATS_FILE
        local_version = None
        local_datasets = 0
        
        if stats_path.exists():
            with open(stats_path, 'r') as f:
                stats = json.load(f)
            local_version = stats.get('version')
            local_datasets = stats.get('total_datasets', 0)
            print(f"\nLocal version: {local_version}")
            print(f"Local datasets: {local_datasets}")
            if stats.get('last_updated'):
                print(f"Last updated: {stats.get('last_updated')}")
        else:
            print("\n[!] No local data found")
        
        # Determine if update needed
        print()
        if not local_version or local_datasets == 0:
            print("[!] Update available: No local data found")
            print("    Run 'python -m src.fetcher_attack_data' to update.")
        elif local_version != latest_version:
            print(f"[!] Update available: {local_version} → {latest_version}")
            print("    Run 'python -m src.fetcher_attack_data' to update.")
        else:
            print("[✓] Already up to date.")
    
    elif command == "force":
        smart_update(output_dir=output_dir, force=True)
    
    elif command == "stats":
        print_stats(output_dir)
    
    elif command == "help" or command == "--help":
        print("""
Splunk Attack Data Fetcher (Smart Update)
==========================================

Source: https://github.com/splunk/attack_data

Commands:
    python -m src.fetcher_attack_data              Smart update (download if needed)
    python -m src.fetcher_attack_data check        Check for updates
    python -m src.fetcher_attack_data force        Force re-download
    python -m src.fetcher_attack_data stats        Show local data statistics
    python -m src.fetcher_attack_data help         Show this help

Output:
    data/splunk_attack_data.jsonl      Attack datasets for RAG
    data/splunk_attack_data.stats.json Version and statistics
""")
    
    else:
        print(f"Unknown command: {command}")
        print("Run 'python -m src.fetcher_attack_data help' for usage.")
        sys.exit(1)


if __name__ == "__main__":
    main()
