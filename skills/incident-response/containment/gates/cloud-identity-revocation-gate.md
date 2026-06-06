# Cloud-Managed Identity Revocation Gate

## Purpose
Prevents unnecessary system shutdown/power-off containment actions by detecting when cloud-managed identity revocation and metadata-service isolation are viable alternatives that preserve volatile evidence.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. The containment plan includes "Power Off", "System Shutdown", or "Instance Termination" as a containment action
2. The affected system is a cloud resource (AWS EC2, Azure VM, GCP Compute Engine, or OCI instance)
3. The incident involves credential theft, IAM key compromise, or instance metadata service abuse (ATT&CK T1525, T1552.005, T1078)

### Gate Check: Evidence Preservation Assessment

```yaml
check_evidence_preservation:
  - question: "Has volatile evidence (memory, running processes, network connections) been captured from the affected system?"
    pass: "Evidence is preserved OR capture is in progress → proceed with identity revocation instead of shutdown"
    fail: "Volatile evidence NOT captured → BLOCK power-off; escalate to cloud identity revocation path"
    escalation: "Recommend: revoke instance IAM role, rotate credentials, isolate metadata service before considering shutdown"
```

### Gate Check: Cloud Identity Revocation Feasibility

```yaml
check_cloud_identity_revocation:
  - provider: "AWS"
    actions:
      - "Detach instance IAM role (aws ec2 associate-iam-instance-profile --no-associate)"
      - "Revoke instance profile permissions via SCP or IAM policy boundary"
      - "Rotate any access keys associated with the instance role"
  - provider: "Azure"
    actions:
      - "Remove managed identity assignment from VM"
      - "Revoke RBAC role assignments for the managed identity"
      - "Regenerate system-assigned identity via Azure REST API"
  - provider: "GCP"
    actions:
      - "Revoke service account access to the instance (gcloud compute instances set-service-account --no-service-account)"
      - "Disable the attached service account in IAM"
      - "Remove IAM policy bindings for the compromised identity"
  - provider: "OCI"
    actions:
      - "Detach dynamic group from instance"
      - "Revoke instance principal session token"
      - "Remove IAM policy statements granting access to the instance's compartment"
```

### Gate Check: Metadata Service Isolation

```yaml
check_metadata_service_isolation:
  - description: "If the attacker is abusing the cloud metadata service (IMDSv1), isolate without shutdown"
  - actions:
      - "Disable IMDSv1 on the instance (enforce IMDSv2 only)"
      - "Block metadata service IP (169.254.169.254) via host firewall or security group"
      - "If IMDSv2 is already enforced, revoke the instance's IAM role credentials (see identity revocation above)"
  - verification: "Confirm metadata service returns 403 or connection refused before considering any shutdown"
```

## Remediation Steps

When this gate blocks a power-off containment action:

1. **Escalate to identity revocation path** -- Revoke cloud-managed identities as described above. This immediately cuts the attacker's access to cloud APIs without destroying local evidence.
2. **Isolate metadata service** -- Block access to 169.254.169.254 to prevent credential retrieval from the instance itself.
3. **Capture volatile evidence** -- Use the forensics-checklist skill to capture memory, process lists, and network connections before any destructive action.
4. **Document the deviation** -- Record in the containment plan: "Power-off deferred due to volatile evidence preservation requirements. Cloud identity revocation applied as primary containment."
5. **Re-evaluate shutdown necessity** -- After identity revocation, assess whether the instance still needs to be powered off. If the attacker's access is severed and the host is stable, schedule shutdown during maintenance window.

## False Positive Prevention

- Do NOT block shutdown when the malware is a wiper or destructive payload (see Step 4b: Wiper/Destructive Malware Containment in SKILL.md) -- in those cases, evidence preservation is secondary to preventing destruction.
- Do NOT block shutdown when the instance has no IAM role or managed identity (no cloud identity to revoke).
- Do NOT apply this gate to on-premises systems -- use credential revocation (password reset, session invalidation) instead.
