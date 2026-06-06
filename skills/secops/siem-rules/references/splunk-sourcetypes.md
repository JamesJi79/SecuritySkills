# Splunk Sourcetypes Reference

> Extracted from siem-rules SKILL.md — for SIEM detection rule development

## Common Splunk Sourcetypes

| Sourcetype | Data Source | Key Fields |
|------------|------------|------------|
| `WinEventLog:Security` | Windows Security Event Log | EventCode, Account_Name, ComputerName |
| `WinEventLog:System` | Windows System Event Log | EventCode, SourceName |
| `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | Sysmon | EventCode, Image, CommandLine, ParentImage |
| `linux_secure` | /var/log/secure (RHEL/CentOS) | action, user, src_ip |
| `linux_audit` | auditd logs | type, uid, exe, key |
| `pan:traffic` | Palo Alto firewall | src_ip, dest_ip, dest_port, action |
| `aws:cloudtrail` | AWS CloudTrail | eventName, sourceIPAddress, userIdentity.arn |
| `o365:management:activity` | Microsoft 365 | Operation, UserId, ClientIP |

## SPL Quick Reference

| Command | Purpose | Example |
|---------|---------|---------|
| `search` | Filter events | `index=main EventCode=4625` |
| `stats` | Aggregate | `stats count by src_ip` |
| `eval` | Compute fields | `eval hour=strftime(_time,"%H")` |
| `table` | Display columns | `table _time, user, src_ip` |
| `join` | Combine searches | `join type=inner user [search ...]` |
| `transaction` | Group related events | `transaction user maxspan=30m` |
| `bin` | Time bucketing | `bin _time span=5m` |
| `dc()` | Distinct count | `dc(user) as unique_users` |
| `values()` | Collect unique values | `values(src_ip) as source_ips` |
| `streamstats` | Running calculations | `streamstats window=1 last(field) as prev_field` |
| `iplocation` | GeoIP lookup | `iplocation ClientIP` |
| `lookup` | Enrich with lookup table | `lookup threat_intel ip as src_ip` |

## Windows Event Codes for SIEM Detection

| Event ID | Description | ATT&CK |
|----------|-------------|--------|
| 4624 | Successful logon | T1078 |
| 4625 | Failed logon | T1110 |
| 4648 | Logon with explicit credentials | T1078 |
| 4672 | Special privileges assigned to new logon | T1078.002 |
| 4688 | Process creation | T1059 |
| 4698 | Scheduled task created | T1053 |
| 4702 | Scheduled task updated | T1053 |
| 4720 | User account created | T1136 |
| 4728 | Member added to security-enabled global group | T1098 |
| 4732 | Member added to security-enabled local group | T1098 |
| 4756 | Member added to security-enabled universal group | T1098 |
| 1102 | Audit log cleared | T1070 |
| 4104 | PowerShell script block logging | T1059.001 |

## Logon Types Reference

| Logon Type | Description |
|------------|-------------|
| 2 | Interactive (local console) |
| 3 | Network (\\\\.\\pipe) |
| 4 | Batch (scheduled tasks) |
| 5 | Service (Windows services) |
| 7 | Unlock (workstation unlock) |
| 8 | NetworkCleartext (IIS basic auth) |
| 9 | NewCredentials (runas /netonly) |
| 10 | RemoteInteractive (RDP) |
| 11 | CachedInteractive (cached credentials) |
