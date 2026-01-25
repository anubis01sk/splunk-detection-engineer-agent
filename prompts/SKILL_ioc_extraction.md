# SKILL: IOC Extraction and Hunting

## Indicator Types

### IP Addresses
- IPv4: `192.168.1.1`
- IPv6: `2001:0db8:85a3::8a2e:0370:7334`
- CIDR: `10.0.0.0/8`

### Domains
- Fully qualified: `malware.evil.com`
- Subdomains: `*.evil.com`

### Hashes
- MD5: 32 hex characters
- SHA1: 40 hex characters
- SHA256: 64 hex characters

### URLs
- Full paths: `http://evil.com/malware.exe`
- URI patterns: `/wp-admin/`, `/shell.php`

### Email
- Addresses: `attacker@evil.com`
- Subjects: Phishing campaign subjects

## SPL IOC Hunting Patterns

### IP Address Search
```spl
index=* earliest=-7d
| search src_ip IN ("1.2.3.4", "5.6.7.8") OR dest_ip IN ("1.2.3.4", "5.6.7.8")
| stats count by index, sourcetype, src_ip, dest_ip
```

### Domain Search
```spl
index=proxy OR index=dns earliest=-7d
| search dest_domain IN ("evil.com", "malware.org") 
  OR query IN ("evil.com", "malware.org")
| stats count by src_ip, dest_domain, query
```

### Hash Search
```spl
index=endpoint earliest=-7d
| search file_hash IN ("abc123...", "def456...")
  OR md5 IN ("abc123...", "def456...")
  OR sha256 IN ("abc123...", "def456...")
| stats count by host, file_path, file_hash
```

### URL Path Search
```spl
index=proxy earliest=-7d
| search uri_path="*shell.php*" OR uri_path="*wp-admin*"
| stats count by src_ip, dest, uri_path
```

## Bulk IOC Lookup

For large IOC lists, use lookup tables:

```spl
| inputlookup ioc_list.csv
| join type=inner src_ip 
    [search index=* earliest=-7d | fields src_ip, dest_ip, _time, user]
| stats count by src_ip, ioc_type, ioc_source
```

## Performance Considerations

1. **Limit time range**: Start with recent data (7 days)
2. **Specify indexes**: Don't search `index=*` if you know the data location
3. **Use `IN` operator**: More efficient than multiple OR conditions
4. **Batch large IOC lists**: Break into chunks of 100-500 items

## IOC Enrichment

Add context to IOC matches:

```spl
index=* src_ip="1.2.3.4" earliest=-7d
| stats 
    count as hit_count,
    dc(index) as data_sources,
    dc(dest) as unique_targets,
    values(user) as users_involved,
    min(_time) as first_seen,
    max(_time) as last_seen
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
```

## Defang/Refang IOCs

Remember to handle defanged IOCs from reports:
- `hxxp://` → `http://`
- `[.]` → `.`
- `[@]` → `@`
