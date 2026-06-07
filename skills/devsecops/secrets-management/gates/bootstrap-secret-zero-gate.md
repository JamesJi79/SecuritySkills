# Bootstrap Secret-Zero Recovery Gate

## Purpose
Prevents false-positive critical severity flags for missing bootstrap secret-zero procedures when the assessed system uses cloud-managed secret stores (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, HashiCorp Vault) that inherently provide break-glass and recovery mechanisms through their native APIs.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "no bootstrap secret-zero procedure" or "no recovery evidence gates" for initial secret provisioning
2. The system uses a managed secret store (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, HashiCorp Vault)
3. The managed store has documented recovery procedures (API key rotation, admin recovery, emergency access)

### Gate Check: Managed Recovery Assessment

```yaml
check_managed_recovery:
  - detection_patterns:
      - "no bootstrap|no secret-zero|no recovery.*gate|missing.*break.glass"
      - "AWS Secrets Manager|Azure Key Vault|GCP Secret Manager|HashiCorp Vault|1Password Connect"
  - pass: "System uses managed secret store with native recovery → Downgrade to Low (Observation). Rationale: The platform's secret store already provides break-glass, recovery, and emergency access workflows. A custom bootstrap secret-zero procedure is unnecessary overhead."
  - fail: "No managed secret store OR no documented recovery path → Keep original severity. Require bootstrap secret-zero procedure."
```

### Gate Check: Alternative Recovery Path

```yaml
check_alternative_recovery:
  - description: "Verify if there are alternative means of initial secret provisioning (GitOps, Terraform remote state, SOPS, external secrets operator)"
  - detection_patterns:
      - "external-secrets|csi-secrets|secrets-store-csi|argocd-vault|sops|age\\.encrypted"
      - "terraform.*remote.*state|pulumi.*config.*secret|ansible-vault"
  - pass: "Alternative recovery path documented → Downgrade to Observation. Consider adding a documented runbook but no code change required."
  - fail: "No alternative recovery path → Require bootstrap secret-zero procedure as High severity."
```
