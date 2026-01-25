# SKILL: Security Detection Engineering

## Detection Query Patterns

### Threshold-Based Detection
Detect when a count exceeds normal baseline.

```spl
index=auth sourcetype=*
| stats count as login_attempts by user, src_ip
| where login_attempts > 10
| eval alert_message="High login attempts from ".src_ip." for user ".user
```

### Time-Window Aggregation
Detect bursts of activity within time windows.

```spl
index=firewall action=blocked
| bin _time span=5m
| stats count by _time, src_ip
| where count > 100
| eval severity=case(count>500, "critical", count>200, "high", true(), "medium")
```

### Anomaly Detection
Find statistically unusual values.

```spl
index=proxy
| stats count by user, dest_domain
| eventstats avg(count) as avg_count, stdev(count) as stdev_count by user
| where count > (avg_count + 3*stdev_count)
```

### Sequence Detection
Find events in a specific order.

```spl
index=endpoint process_name=cmd.exe
| transaction host maxspan=5m
| search eventcount > 3
| where match(_raw, "whoami") AND match(_raw, "net user")
```

## Common Security Use Cases

### Brute Force Detection
```spl
index=auth action=failure
| stats count as failures by user, src_ip
| where failures >= 5
| eval alert_type="Brute Force Attempt"
```

### Lateral Movement
```spl
index=winevent EventCode=4624 Logon_Type=3
| stats dc(dest) as unique_hosts by user
| where unique_hosts > 5
```

### Data Exfiltration
```spl
index=proxy
| stats sum(bytes_out) as total_bytes by user
| where total_bytes > 1073741824
| eval size_gb=round(total_bytes/1073741824, 2)
```

### Privilege Escalation
```spl
index=winevent EventCode IN (4672, 4673, 4674)
| stats count by user, EventCode
| where count > 0
```

## MITRE ATT&CK Alignment

When building detections, map to MITRE techniques:

- **T1110**: Brute Force - Monitor failed auth
- **T1021**: Remote Services - Track lateral connections  
- **T1078**: Valid Accounts - Detect credential misuse
- **T1059**: Command and Scripting - Monitor process execution
- **T1003**: OS Credential Dumping - Watch for LSASS access

## Detection Output Format

Always include:
1. Relevant fields for investigation
2. Severity/risk scoring
3. Timestamps for correlation
4. Entity identifiers (user, host, IP)

```spl
| table _time, severity, user, src_ip, dest, alert_message
| sort - _time
```
