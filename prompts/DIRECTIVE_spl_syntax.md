# SPL Syntax Requirements

<syntax_rules>

## 1. RAW SPL ONLY
Write raw SPL syntax that works on any standard Splunk installation.
Use explicit field references and commands instead of macro shortcuts.

**Why**: Macros (backtick syntax like `macro_name`) are environment-specific and may not exist on the user's Splunk instance.

## 2. PURE SPL OUTPUT
Place all explanatory text in the Explanation section, not within the query itself.
SPL supports only one comment format: triple-backtick inline comments (` `comment` `), but avoid using these.

**Why**: The `#` character is not a valid comment delimiter in SPL. Including it causes parse errors.

**Correct approach**:
- Write the SPL query without any comments
- Explain the query logic in the Explanation section of your response

## 3. TSTATS FIELD ACCESS
tstats is a high-performance command that reads from indexed metadata (tsidx files), not raw events.

**Valid indexed fields for tstats (without data model)**:
- `_time`
- `host`
- `source`
- `sourcetype`
- `index`
- `splunk_server`
- `_indextime` (in some configurations)

**Why**: Attempting to access non-indexed fields (like user, src_ip) causes silent failures or errors because tstats cannot read event-level data without an accelerated data model.

### Correct Patterns:

**For indexed fields only** (no data model):
```spl
| tstats count WHERE index=main by host, sourcetype
```

**For event-level fields** (with data model):
```spl
| tstats count from datamodel=Authentication by Authentication.user, Authentication.src
```

**For event-level fields** (no data model - use regular search):
```spl
index=main | stats count by user, src_ip
```

### Incorrect Patterns to Avoid:
```spl
| tstats count from winlog_security by user
| tstats count WHERE index=main by user, src_ip
```
These fail because `user` and `src_ip` are not indexed fields.

## 4. MULTI-VALUED FIELD HANDLING
Windows Event Log fields like `Account_Name` contain multiple values in a single event.

**Structure**:
- Index 0 = Subject account (who initiated the action)
- Index 1 = Target account (who was affected)

**Why**: Using `Account_Name` directly may return the wrong user. For login events, you typically want the target user.

**Correct extraction**:
```spl
| eval target_user=mvindex(Account_Name, 1)
| eval subject_user=mvindex(Account_Name, 0)
```

## 5. ENVIRONMENT COMPATIBILITY
Generate SPL that runs successfully on standard Splunk Enterprise or Splunk Cloud installations without requiring Enterprise Security app or custom configurations.

**Why**: Users may not have ES installed, so relying on ES-specific macros or data models will cause failures.

</syntax_rules>
