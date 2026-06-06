# Microsoft Sentinel Tables Reference

> Extracted from siem-rules SKILL.md — for SIEM detection rule development

## Common Sentinel Tables

| Table | Data Source | Key Fields |
|-------|------------|------------|
| `SigninLogs` | Azure AD interactive sign-ins | UserPrincipalName, ResultType, IPAddress, Location |
| `AADNonInteractiveUserSignInLogs` | Azure AD non-interactive sign-ins | Same as SigninLogs |
| `SecurityEvent` | Windows Security Event Log | EventID, Account, Computer, Activity |
| `Syslog` | Linux syslog | SyslogMessage, ProcessName, Facility, SeverityLevel |
| `DeviceProcessEvents` | Microsoft Defender for Endpoint | FileName, ProcessCommandLine, InitiatingProcessFileName |
| `DeviceNetworkEvents` | MDE network events | RemoteIP, RemotePort, RemoteUrl |
| `AzureActivity` | Azure control plane | OperationNameValue, Caller, ResourceGroup |
| `CommonSecurityLog` | CEF-format logs (firewalls, proxies) | DeviceAction, SourceIP, DestinationIP |
| `ThreatIntelligenceIndicator` | Threat intel feeds | NetworkIP, DomainName, Url, ExpirationDateTime |
| `OfficeActivity` | Microsoft 365 audit logs | Operation, UserId, ClientIP |

## Azure AD Sign-in ResultType Codes

| ResultType | Meaning |
|------------|---------|
| 0 | Success |
| 50126 | Invalid username or password |
| 50053 | Account locked |
| 50055 | Password expired |
| 50056 | Invalid or null password |
| 50057 | Account disabled |
| 50074 | MFA required |
| 50076 | MFA prompt not satisfied |
| 53003 | Conditional access block |

## KQL Quick Reference

| Operator | Purpose | Example |
|----------|---------|---------|
| `where` | Filter rows | `where EventID == 4625` |
| `summarize` | Aggregate | `summarize count() by UserName` |
| `extend` | Add columns | `extend Hour = hourofday(TimeGenerated)` |
| `project` | Select columns | `project TimeGenerated, User, IP` |
| `join` | Combine tables | `T1 \| join kind=inner (T2) on Key` |
| `let` | Define variables | `let threshold = 10;` |
| `ago()` | Time relative to now | `where TimeGenerated > ago(1h)` |
| `bin()` | Time bucketing | `bin(TimeGenerated, 5m)` |
| `dcount()` | Distinct count | `dcount(UserPrincipalName)` |
| `make_set()` | Collect unique values | `make_set(IPAddress, 100)` |
| `has_any` | Contains any value from list | `where User has_any (admin_list)` |
| `serialize` | Enable row-order operators | Required before `prev()`, `next()` |

## Key ATT&CK Techniques for SIEM

| Technique ID | Name | Primary SIEM Data Source |
|-------------|------|--------------------------|
| T1110 | Brute Force | Authentication logs (SigninLogs, EventCode 4625) |
| T1078 | Valid Accounts | Authentication logs, impossible travel |
| T1059 | Command and Scripting Interpreter | Process creation logs (Sysmon 1, 4688) |
| T1021 | Remote Services | Network logon events (4624 Type 3/10) |
| T1053 | Scheduled Task/Job | Event IDs 4698 (created), 4702 (updated) |
| T1136 | Create Account | Event ID 4720 (user account created) |
| T1098 | Account Manipulation | Event IDs 4728, 4732, 4756 (group membership changes) |
| T1070 | Indicator Removal | Event ID 1102 (audit log cleared) |
| T1003 | OS Credential Dumping | Sysmon EID 10 (process access to LSASS) |
| T1486 | Data Encrypted for Impact | File modification patterns, ransomware note creation |
