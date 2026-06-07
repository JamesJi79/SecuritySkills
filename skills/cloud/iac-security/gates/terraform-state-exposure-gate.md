# Terraform State Backend Exposure Gate

## Purpose
Prevents false-positive "state backend exposure" findings when the Terraform state is stored in a remote backend with adequate access controls (e.g., S3 with bucket policies, Azure Storage RBAC, GCS with IAM), even if the state file itself is not encrypted at rest with a customer-managed key. The current skill over-flags configurations that follow the provider-recommended secure defaults.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "Terraform state backend exposure" or "state file accessible" as High/Critical
2. The state backend uses a supported remote backend (S3, AzureRM, GCS, Terraform Cloud/Enterprise)
3. The backend configuration includes authentication (access keys, managed identity, service principal)

### Gate Check: Remote Backend Security Assessment

```yaml
check_backend_security:
  - description: "Assess the actual security posture of the remote state backend"
  - detection_patterns:
      - "backend.*s3|backend.*azurerm|backend.*gcs|backend.*terraform.*cloud"
      - "terraform.*state|state.*exposure|state.*backend"
  - checks:
      - "S3: bucket policy restricts access via PrincipalARN or SourceVPC; server-side encryption (AES256/aws:kms) enabled; versioning enabled for state recovery"
      - "AzureRM: storage account firewall enabled; RBAC role assignment limited to operators; infrastructure encryption enabled"
      - "GCS: uniform bucket-level access; IAM binding scoped to service accounts; object versioning enabled"
  - pass: "Remote backend follows provider-recommended security defaults → Downgrade to Low (Informational). Rationale: Standard remote backend configuration with access controls mitigates state exposure risk. Customer-managed encryption keys are a defense-in-depth enhancement, not a required control."
  - fail: "Backend uses local state, no authentication, public bucket, or no encryption → Keep Critical severity. Immediate remediation required."
```

## Resolution Path
1. For secure remote backends: Document the existing controls and close as Informational
2. For insecure configurations: Migrate to remote backend with authentication and encryption
