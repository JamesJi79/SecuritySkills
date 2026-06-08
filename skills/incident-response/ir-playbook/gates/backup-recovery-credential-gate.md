# Backup Recovery Credential and Control-Plane Gate

## Purpose
Prevents false-positive "backup recovery credential gap" findings when the IR playbook assumes access to backup recovery credentials through a privileged access management (PAM) system, break-glass account, or cloud provider's backup recovery role, rather than documenting individual credential stores. In cloud environments, backup recovery often uses provider-managed roles that don't require separate credential documentation.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "backup recovery credentials not documented" as High
2. Recovery uses cloud provider-managed roles (AWS Backup service role, Azure Backup vault, GCP backup IAM)
3. OR recovery credentials are accessible through a PAM/break-glass system

### Gate Check: Cloud-Provider Managed Recovery

```yaml
check_cloud_managed_recovery:
  - detection_patterns:
      - "backup.*recover|restore.*credential|recovery.*role|backup.*IAM"
      - "AWS.*Backup|Azure.*Backup.*vault|GCP.*backup|Veeam.*service"
      - "PAM.*recover|break.*glass|emergency.*access|privileged.*access"
  - pass: "Backup recovery uses cloud provider managed roles with documented runbook → Downgrade to Low (Informational). Rationale: Cloud provider backup services use IAM roles, not static credentials. The recovery runbook references the provider's API/console procedure."
  - fail: "Backup recovery requires static credentials (root password, service account key) that are not documented → Keep severity. Undocumented static credentials create a single point of failure for disaster recovery."
```

### Gate Check: Control-Plane Access

```yaml
check_control_plane:
  - detection_patterns:
      - "control.*plane|management.*plane|API.*access|console.*access"
      - "admin.*account|root.*access|super.*admin|break.*glass"
  - pass: "Control-plane access is available via PAM or break-glass procedure with documented approval flow → Accept. Control-plane access provides recovery capability without per-service credentials."
  - fail: "No documented control-plane access path for recovery → Escalate. Without either documented credentials or control-plane access, disaster recovery may be impossible."
```
