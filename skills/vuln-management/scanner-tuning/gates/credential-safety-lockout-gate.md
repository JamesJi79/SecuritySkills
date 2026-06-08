# Credential Safety and Lockout Evidence Gate

## Purpose
Prevents false-positive "scanner credential compromise" findings when vulnerability scanners use dedicated, scoped service accounts with locked-down permissions, network access restrictions, and credential rotation, rather than shared admin credentials. The gate evaluates whether scanner credentials are secured according to least-privilege principles.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "scanner credentials at risk" or "scanning account over-privileged" as High
2. Scanner uses a dedicated service account with scoped permissions (not admin/root)
3. The service account has network restrictions (source IP, VNet, jump box)

### Gate Check: Credential Scoping

```yaml
check_credential_scoping:
  - detection_patterns:
      - "scanner.*credential|scan.*account|vulnerability.*scan.*user"
      - "service.*account.*scan|read.?only.*account|scan.*role"
      - "Nessus|Qualys|Rapid7|OpenVAS|Nmap|Burp|ZAP"
  - pass: "Scanner uses dedicated service account with scoped permissions (read-only, specific resources) → Downgrade to Low (Informational). Rationale: Scoped scanner accounts limit blast radius. Compromise of scanner credentials only exposes read-only access to scoped resources."
  - fail: "Scanner uses shared admin/root credentials → Keep severity. Shared admin credentials for scanning violate least-privilege and expose the entire environment if compromised."
```

### Gate Check: Rotation and Lockout

```yaml
check_rotation_lockout:
  - detection_patterns:
      - "credential.*rotat|key.*rotat|password.*expire|secret.*refresh"
      - "lockout.*policy|account.*lock|MFA.*scan|session.*timeout"
  - pass: "Scanner credentials are automatically rotated AND the account has lockout policies → Accept. Rotation limits the exposure window if credentials are compromised."
  - fail: "Scanner credentials never rotated OR no account lockout → Escalate to Medium. Static scanner credentials create a permanent access key that, if leaked, provides ongoing access."
```
