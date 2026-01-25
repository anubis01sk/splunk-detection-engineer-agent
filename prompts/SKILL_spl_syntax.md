# SKILL: SPL Syntax and Best Practices

## CRITICAL SPL SYNTAX RULES

### ❌ INVALID SYNTAX - NEVER USE

#### 1. Hash Comments Are NOT Valid SPL
```spl
# This is WRONG - SPL does NOT support hash comments
| stats count by user  # This will also fail
```

**Correct SPL comment syntax** uses triple backticks ONLY:
```spl
| stats count by user ```This is a valid SPL inline comment```
```

**Best practice**: Avoid comments in generated queries. Explain in the response text instead.

#### 2. tstats FROM Clause Syntax

**WRONG** - Cannot use index name directly in FROM:
```spl
| tstats count from winlog_security by src
| tstats count from index=main by host
```

**CORRECT** - Use WHERE clause for index filtering:
```spl
| tstats count WHERE index=main by host, sourcetype
```

**CORRECT** - Use datamodel= for data model access:
```spl
| tstats count from datamodel=Authentication.Authentication by Authentication.src
```

#### 3. tstats Field Limitations

**tstats can ONLY access these fields without a data model:**
- `_time`
- `host`
- `source`
- `sourcetype`
- `index`
- `splunk_server`

**WRONG** - Custom fields don't work:
```spl
| tstats count WHERE index=main by user, src_ip
```

**CORRECT** - Use data model or regular search:
```spl
index=main | stats count by user, src_ip
```

Or with accelerated data model:
```spl
| tstats count from datamodel=Authentication by Authentication.user, Authentication.src
```

### CIM Field Conventions

When using CIM (Common Information Model) data models, use normalized field names:

| Raw Windows Field | CIM Field | Data Model Path |
|-------------------|-----------|-----------------|
| ComputerName | dest | Authentication.dest |
| Account_Name | user | Authentication.user |
| Source_Network_Address | src | Authentication.src |
| EventCode | signature_id | Authentication.signature_id |
| Logon_Type | authentication_method | Authentication.authentication_method |

### Multi-Valued Fields

Windows Event 4625 has multi-valued `Account_Name`:
- Index 0: Subject account (who initiated)
- Index 1: Target account (who was being logged in)

```spl
| eval target_user=mvindex(Account_Name, 1)
| eval subject_user=mvindex(Account_Name, 0)
```

## Query Performance Guidelines

### Do's

1. **Filter Early**
   ```spl
   index=main sourcetype=access_combined status=500
   | stats count by uri
   ```

2. **Use tstats for indexed fields only**
   ```spl
   | tstats count WHERE index=main BY host, sourcetype, source
   ```

3. **Limit fields extracted**
   ```spl
   index=main | fields + src_ip, dest_ip, action
   ```

4. **Use stats over transaction**
   ```spl
   | stats values(action) as actions, count by session_id
   ```

5. **Specify time range explicitly**
   ```spl
   index=main earliest=-24h latest=now
   | stats count by host
   ```

### Don'ts

1. **Don't use search in middle of pipeline**
   ```spl
   index=main | stats count by user | where count > 10
   ```
   NOT: `| search count > 10`

2. **Don't use leading wildcards**
   ```spl
   index=main error
   ```
   NOT: `index=main "*error*"`

3. **Don't assume fields exist without data model**
   Always check if using `tstats` - it only sees indexed fields!

## Common Detection Patterns

### Brute Force Detection

**IMPORTANT**: For brute force detection, ALWAYS include EventCode filter!

#### Option 1: Raw Windows Event Log (DEFAULT - no data model needed)
```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625
| eval target_user=mvindex(Account_Name, 1)
| eval subject_user=mvindex(Account_Name, 0)
| bucket span=5m _time
| stats count as failed_attempts dc(target_user) as unique_users values(target_user) as attempted_users by Source_Network_Address, ComputerName, _time
| where failed_attempts > 10 OR unique_users > 5
| rename Source_Network_Address as src, ComputerName as dest
| table _time, src, dest, failed_attempts, unique_users, attempted_users
```

Key points:
- EventCode=4625 = Failed login attempts
- EventCode=4624 = Successful logins
- mvindex(Account_Name, 1) = Target user being logged into
- mvindex(Account_Name, 0) = Subject user initiating the logon

#### Option 2: CIM Authentication Data Model (if available)
```spl
| tstats summariesonly=true count as failed_attempts dc(Authentication.user) as unique_users values(Authentication.user) as attempted_users from datamodel=Authentication.Authentication where nodename=Authentication.Failed_Authentication by Authentication.src, Authentication.dest, _time span=5m
| rename Authentication.* as *
| where failed_attempts > 10 OR unique_users > 5
| table _time, src, dest, failed_attempts, unique_users, attempted_users
```

Key points:
- Use nodename=Authentication.Failed_Authentication for failures only
- CIM fields are already normalized (no mvindex needed)
- summariesonly=true uses accelerated data only

### Process Execution Detection

#### Option 1: Raw Sysmon (DEFAULT)
```spl
index=sysmon EventCode=1
| search Image IN ("*\\powershell.exe", "*\\cmd.exe", "*\\wscript.exe")
| table _time, Computer, User, Image, CommandLine, ParentImage
```

#### Option 2: CIM Endpoint.Processes
```spl
| tstats count from datamodel=Endpoint.Processes where Processes.process_name IN ("powershell.exe", "cmd.exe", "wscript.exe") by Processes.dest, Processes.user, Processes.process, Processes.parent_process, _time span=1h
| rename Processes.* as *
```

### Time-Based Analysis
```spl
index=main earliest=-24h latest=now
| bin _time span=1h
| stats count by _time
```

### Top N Analysis
```spl
index=main
| stats count by src_ip
| sort - count
| head 10
```

### Rare Value Detection
```spl
index=main
| rare user limit=10
```

### Field Extraction
```spl
index=main
| rex field=_raw "user=(?<extracted_user>\w+)"
```

## Transforming Commands

- `stats` - Aggregate statistics
- `chart` - Create charts with 2 dimensions
- `timechart` - Time-series charts
- `top` / `rare` - Frequency analysis
- `eval` - Calculate new fields
- `table` - Output specific fields
- `eventstats` - Add aggregations without reducing rows
- `streamstats` - Running calculations

## Filtering Commands

- `where` - Filter with expressions (preferred)
- `search` - Keyword/field filtering (use at START only)
- `dedup` - Remove duplicates
- `head` / `tail` - Limit results

## Statistical Outlier Detection (3-Sigma Rule)

```spl
index=main
| stats count by src
| eventstats avg(count) as avg_count, stdev(count) as stdev_count
| eval upperBound = avg_count + (stdev_count * 3)
| eval lowerBound = avg_count - (stdev_count * 3)
| eval isOutlier = if(count > upperBound OR count < lowerBound, 1, 0)
| where isOutlier=1
```
